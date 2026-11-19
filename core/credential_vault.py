# core/credential_vault.py
# Antigravity Git-Vault - Windows DPAPI Encrypted Vault & Credential Manager
import subprocess
import json
import os
import re
import base64
import ctypes
import ctypes.wintypes
from typing import Dict, List, Any, Optional
from .credential_types import (
    parse_key_type,
    normalize_key_type,
    default_scope,
    platform_storable,
)

VAULT_CONFIG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config", "vault.json")

# --- Credential model: key_type / scope / rotation ---
CREDENTIAL_SCHEMA_VERSION = 2

# 轮换建议间隔（天），写入 rotation.rotate_after_days；0 = 不轮换
_DEFAULT_ROTATION_DAYS = {
    "pat_classic": 180,
    "pat_fine": 90,
    "pat_gitlab": 180,
    "ssh_user_key": 365,
    "deploy_key": 365,
    "app_private_key": 365,
    "app_installation_token": 0,
    "app_user_token": 90,
    "oauth_user_token": 90,
    "oauth_refresh_token": 180,
    "gh_cli_token": 90,
    "generic_secret": 0,
}

_SCOPE_KEYS = ("owner", "repos", "permissions", "environment")

# --- Windows DPAPI (Data Protection API) Engine ---
class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ('cbData', ctypes.wintypes.DWORD),
        ('pbData', ctypes.POINTER(ctypes.c_char))
    ]

def dpapi_encrypt(plain_text: str) -> str:
    """使用 Windows 操作系统原生 DPAPI 加密数据，密钥与当前 Windows 登录账户强绑定"""
    if not plain_text:
        return ""
    try:
        in_bytes = plain_text.encode('utf-8')
        in_blob = DATA_BLOB(len(in_bytes), ctypes.cast(ctypes.create_string_buffer(in_bytes), ctypes.POINTER(ctypes.c_char)))
        out_blob = DATA_BLOB()
        # CryptProtectData flags: 0 (UI forbidden)
        if ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(in_blob), "GitVault-Secret", None, None, None, 0, ctypes.byref(out_blob)
        ):
            encrypted_bytes = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)
            return base64.b64encode(encrypted_bytes).decode('ascii')
    except Exception as e:
        print(f"[DPAPI] Encrypt error: {e}")
    return ""

def dpapi_decrypt(cipher_b64: str) -> str:
    """使用 Windows DPAPI 解密数据，非当前用户或跨机器无法解开"""
    if not cipher_b64:
        return ""
    try:
        in_bytes = base64.b64decode(cipher_b64)
        in_blob = DATA_BLOB(len(in_bytes), ctypes.cast(ctypes.create_string_buffer(in_bytes), ctypes.POINTER(ctypes.c_char)))
        out_blob = DATA_BLOB()
        if ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)
        ):
            decrypted_bytes = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)
            return decrypted_bytes.decode('utf-8')
    except Exception as e:
        print(f"[DPAPI] Decrypt error: {e}")
    return ""

def _mask_secret(plain: str) -> str:
    """前缀段 + 长度脱敏，例如 ghp_…(36)；不保留尾部字符，避免泄露 token 熵。"""
    if not plain:
        return ""
    if len(plain) < 8:
        return f"…({len(plain)})"
    return f"{plain[:4]}…({len(plain)})"


def _default_rotation(key_type: Any, now_str: str = "") -> Dict[str, Any]:
    """rotation 三键默认值，形状冻结：{rotate_after_days, rotated_at, last_verified_at}。"""
    kt = normalize_key_type(key_type)
    return {
        "rotate_after_days": int(_DEFAULT_ROTATION_DAYS.get(kt, 0)),
        "rotated_at": now_str,
        "last_verified_at": "",
    }


def _rotation_of(entry: Dict[str, Any], key_type: Any = None) -> Dict[str, Any]:
    """读取既有 rotation，缺失键用默认值补齐；旧数据无 rotation 时整体兜底。"""
    base = _default_rotation(key_type if key_type is not None else entry.get("key_type"))
    src = entry.get("rotation")
    if isinstance(src, dict):
        for k in ("rotate_after_days", "rotated_at", "last_verified_at"):
            if k in src and src[k] is not None:
                base[k] = src[k]
    base["rotate_after_days"] = int(base["rotate_after_days"] or 0)
    return base


def _next_rotation(entry: Dict[str, Any], key_type: Any, token_changed: bool, now_str: str) -> Dict[str, Any]:
    """token 变更时刷新 rotated_at；rotate_after_days 沿用旧值，缺失时取默认表。"""
    prev = _rotation_of(entry, key_type)
    return {
        "rotate_after_days": prev["rotate_after_days"],
        "rotated_at": now_str if token_changed else prev["rotated_at"],
        "last_verified_at": prev["last_verified_at"],
    }


def _scope_of(entry: Dict[str, Any], key_type: Any = None) -> Dict[str, Any]:
    """scope 四键视图：缺省用 default_scope 深拷贝，未知键丢弃（T5 只认四键）。"""
    kt = key_type if key_type is not None else (parse_key_type(entry.get("key_type")) or "pat_classic")
    base = default_scope(kt)
    src = entry.get("scope")
    if isinstance(src, dict):
        for k in _SCOPE_KEYS:
            if k in src:
                base[k] = src[k]
    return base

# --- Vault File Management ---
def migrate_legacy_tokens(raw: Dict[str, Any]) -> bool:
    """如果存在旧的 encrypted_tokens 且 accounts 为空，执行向后平滑静默迁移"""
    accounts = raw.get("accounts", [])
    changed = False
    if not accounts and raw.get("encrypted_tokens"):
        import datetime
        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        metadata = raw.get("token_metadata", {})
        saved_accounts = raw.get("saved_accounts", {})
        for platform, cipher in raw["encrypted_tokens"].items():
            if cipher:
                username = saved_accounts.get(f"{platform}_user") or metadata.get(platform, {}).get("username", "")
                expires_at = metadata.get(platform, {}).get("expires_at", "never")
                acc_id = f"acc_{platform}_default"
                accounts.append({
                    "id": acc_id,
                    "platform": platform,
                    "username": username,
                    "alias": f"{platform.capitalize()} 默认主账号",
                    "encrypted_token": cipher,
                    "is_default": True,
                    "expires_at": expires_at,
                    "key_type": "pat_classic",
                    "scope": default_scope("pat_classic"),
                    "rotation": _default_rotation("pat_classic", now_str),
                    "created_at": now_str,
                    "updated_at": now_str
                })
                changed = True
        raw["accounts"] = accounts
    if "accounts" not in raw:
        raw["accounts"] = []
    if "repo_account_bindings" not in raw:
        raw["repo_account_bindings"] = {}
    return changed

def load_raw_vault() -> Dict[str, Any]:
    if not os.path.exists(VAULT_CONFIG_FILE):
        return {
            "accounts": [],
            "repo_account_bindings": {},
            "encrypted_tokens": {},
            "saved_accounts": {},
            "encryption": "Windows-DPAPI"
        }
    try:
        with open(VAULT_CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            # 严格清除任何可能遗留的明文 tokens 键
            if "tokens" in data:
                del data["tokens"]
            migrated = migrate_legacy_tokens(data)
            if migrated:
                save_raw_vault(data)
            return data
    except Exception:
        return {
            "accounts": [],
            "repo_account_bindings": {},
            "encrypted_tokens": {},
            "saved_accounts": {},
            "encryption": "Windows-DPAPI"
        }

def save_raw_vault(data: Dict[str, Any]) -> bool:
    try:
        # 双重保险：序列化前强制移除明文字段，只允许密文落盘
        data.pop("tokens", None)
        os.makedirs(os.path.dirname(VAULT_CONFIG_FILE), exist_ok=True)
        with open(VAULT_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False

def _calculate_expiry(expires_at: str) -> Dict[str, Any]:
    import datetime
    now = datetime.date.today()
    expiry_info = {"type": "never", "text": "永不过期", "is_expired": False, "days_left": None}
    if expires_at and expires_at != "never":
        try:
            exp_date = datetime.datetime.strptime(expires_at, "%Y-%m-%d").date()
            delta = (exp_date - now).days
            if delta < 0:
                expiry_info = {"type": "expired", "text": f"已过期 ({abs(delta)}天前)", "is_expired": True, "days_left": delta}
            elif delta <= 15:
                expiry_info = {"type": "expiring_soon", "text": f"即将过期 (剩 {delta} 天)", "is_expired": False, "days_left": delta}
            else:
                expiry_info = {"type": "valid", "text": f"有效期至 {expires_at} (剩 {delta} 天)", "is_expired": False, "days_left": delta}
        except Exception:
            expiry_info = {"type": "custom", "text": expires_at, "is_expired": False, "days_left": None}
    return expiry_info

def list_accounts_masked(platform: Optional[str] = None) -> List[Dict[str, Any]]:
    """获取多账号脱敏列表（用于 Web 控制台资产表格呈现）"""
    raw = load_raw_vault()
    accounts = raw.get("accounts", [])
    res = []
    for acc in accounts:
        if platform and acc.get("platform", "").lower() != platform.lower():
            continue
        cipher = acc.get("encrypted_token", "")
        plain = dpapi_decrypt(cipher) if cipher else ""
        if plain:
            mask_str = _mask_secret(plain)
            has_token = True
        elif cipher:
            mask_str = "(解密失败)"
            has_token = False
        else:
            mask_str = "(未设置)"
            has_token = False

        key_type = parse_key_type(acc.get("key_type")) or "pat_classic"
        expires_at = acc.get("expires_at", "never")
        expiry_info = _calculate_expiry(expires_at)

        res.append({
            "id": acc.get("id"),
            "platform": acc.get("platform"),
            "username": acc.get("username", ""),
            "alias": acc.get("alias", ""),
            "is_default": acc.get("is_default", False),
            "has_token": has_token,
            "masked": mask_str,
            "key_type": key_type,
            "scope": _scope_of(acc, key_type),
            "expires_at": expires_at,
            "expiry_info": expiry_info,
            "rotation": _rotation_of(acc, key_type),
            "created_at": acc.get("created_at", ""),
            "updated_at": acc.get("updated_at", "")
        })
    return res

def add_or_update_account(
    platform: str,
    token: Optional[str] = None,
    username: str = "",
    alias: str = "",
    expires_at: str = "never",
    is_default: bool = False,
    account_id: Optional[str] = None,
    key_type: str = "pat_classic",
    scope: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """添加或更新平台账号（条目含 key_type / scope / rotation 三组字段）"""
    platform = platform.lower().strip()
    if not platform:
        return {"success": False, "error": "平台名称不能为空"}

    kt = parse_key_type(key_type)
    if kt is None:
        return {"success": False, "error": f"非法的密钥类型: {key_type}"}
    if not platform_storable(kt):
        return {"success": False, "error": f"平台域密钥不入本地凭据库: {kt}"}

    raw = load_raw_vault()
    accounts = raw.get("accounts", [])
    import datetime
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    scope_val = _scope_of({"scope": scope}, kt)

    # 查找已有账号
    target_idx = -1
    if account_id:
        for idx, acc in enumerate(accounts):
            if acc.get("id") == account_id:
                target_idx = idx
                break

    # 如果是该平台的第一个账号，强制为默认
    existing_for_platform = [a for a in accounts if a.get("platform") == platform]
    if not existing_for_platform:
        is_default = True

    if target_idx >= 0:
        # 更新已有账号
        acc = accounts[target_idx]
        token_changed = bool(token and token.strip())
        if token_changed:
            acc["encrypted_token"] = dpapi_encrypt(token.strip())
        if username:
            acc["username"] = username.strip()
        if alias is not None:
            acc["alias"] = alias.strip()
        if expires_at:
            acc["expires_at"] = expires_at.strip()
        acc["key_type"] = kt
        acc["scope"] = scope_val
        acc["rotation"] = _next_rotation(acc, kt, token_changed, now_str)
        acc["updated_at"] = now_str
        target_acc = acc
    else:
        # 新增账号
        if not token or not token.strip():
            return {"success": False, "error": "新增账号必须提供 Access Token"}
        import time
        new_id = account_id or f"acc_{platform}_{int(time.time()*1000)}"
        target_acc = {
            "id": new_id,
            "platform": platform,
            "username": username.strip(),
            "alias": alias.strip() or f"{platform.capitalize()} 账号",
            "encrypted_token": dpapi_encrypt(token.strip()),
            "is_default": is_default,
            "expires_at": expires_at.strip() or "never",
            "key_type": kt,
            "scope": scope_val,
            "rotation": _next_rotation({}, kt, True, now_str),
            "created_at": now_str,
            "updated_at": now_str
        }
        accounts.append(target_acc)

    # 如果当前账号被设为默认，将同平台其它账号的 is_default 置为 False
    if is_default:
        for a in accounts:
            if a.get("platform") == platform:
                a["is_default"] = (a.get("id") == target_acc.get("id"))

    # 同步旧兼容字段
    if target_acc.get("is_default"):
        raw.setdefault("encrypted_tokens", {})[platform] = target_acc.get("encrypted_token", "")
        raw.setdefault("saved_accounts", {})[f"{platform}_user"] = target_acc.get("username", "")
        raw.setdefault("token_metadata", {})[platform] = {
            "username": target_acc.get("username", ""),
            "expires_at": target_acc.get("expires_at", "never")
        }

    raw["accounts"] = accounts
    success = save_raw_vault(raw)
    return {"success": success, "account_id": target_acc.get("id"), "is_default": target_acc.get("is_default"), "key_type": kt}

def set_default_account(account_id: str) -> Dict[str, Any]:
    """将指定账号设为该平台的默认活动账号"""
    raw = load_raw_vault()
    accounts = raw.get("accounts", [])
    target = None
    for acc in accounts:
        if acc.get("id") == account_id:
            target = acc
            break
    if not target:
        return {"success": False, "error": f"未找到账号 ID: {account_id}"}

    platform = target.get("platform")
    for acc in accounts:
        if acc.get("platform") == platform:
            acc["is_default"] = (acc.get("id") == account_id)

    # 同步旧兼容字段
    raw.setdefault("encrypted_tokens", {})[platform] = target.get("encrypted_token", "")
    raw.setdefault("saved_accounts", {})[f"{platform}_user"] = target.get("username", "")
    raw.setdefault("token_metadata", {})[platform] = {
        "username": target.get("username", ""),
        "expires_at": target.get("expires_at", "never")
    }

    success = save_raw_vault(raw)
    return {"success": success, "account_id": account_id, "platform": platform}

def delete_account(account_id: str) -> Dict[str, Any]:
    """删除指定账号"""
    raw = load_raw_vault()
    accounts = raw.get("accounts", [])
    target_idx = -1
    for idx, acc in enumerate(accounts):
        if acc.get("id") == account_id:
            target_idx = idx
            break
    if target_idx < 0:
        return {"success": False, "error": f"未找到账号 ID: {account_id}"}

    deleted_acc = accounts.pop(target_idx)
    platform = deleted_acc.get("platform")

    # 如果删除的是默认账号，且同平台还有其它账号，将第一个置为默认
    if deleted_acc.get("is_default"):
        remaining = [a for a in accounts if a.get("platform") == platform]
        if remaining:
            remaining[0]["is_default"] = True
            raw.setdefault("encrypted_tokens", {})[platform] = remaining[0].get("encrypted_token", "")
            raw.setdefault("saved_accounts", {})[f"{platform}_user"] = remaining[0].get("username", "")
        else:
            if "encrypted_tokens" in raw and platform in raw["encrypted_tokens"]:
                del raw["encrypted_tokens"][platform]
            if "saved_accounts" in raw and f"{platform}_user" in raw["saved_accounts"]:
                del raw["saved_accounts"][f"{platform}_user"]

    # 清理仓库绑定中的无效引用
    bindings = raw.get("repo_account_bindings", {})
    for r_path, r_bind in list(bindings.items()):
        if r_bind.get(platform) == account_id:
            del r_bind[platform]

    raw["accounts"] = accounts
    success = save_raw_vault(raw)
    return {"success": success, "deleted_id": account_id}

def bind_repo_account(repo_path: str, platform: str, account_id: str) -> Dict[str, Any]:
    """将特定仓库绑定到指定平台账号（若 account_id 为空则解绑）"""
    raw = load_raw_vault()
    norm_path = os.path.normpath(repo_path)
    bindings = raw.setdefault("repo_account_bindings", {})
    if norm_path not in bindings:
        bindings[norm_path] = {}

    if account_id and account_id.strip():
        bindings[norm_path][platform] = account_id.strip()
    else:
        bindings[norm_path].pop(platform, None)

    success = save_raw_vault(raw)
    return {"success": success, "repo_path": norm_path, "platform": platform, "account_id": account_id}

def get_repo_account_bindings(repo_path: Optional[str] = None) -> Dict[str, Any]:
    raw = load_raw_vault()
    bindings = raw.get("repo_account_bindings", {})
    if repo_path:
        norm_path = os.path.normpath(repo_path)
        return bindings.get(norm_path, {})
    return bindings

def get_plain_token(platform: str, repo_path: Optional[str] = None, key_type: Optional[str] = None) -> str:
    """获取指定平台的明文 Token（优先仓库绑定 -> 默认账号 -> 首个账号 -> 旧兼容字段）。

    key_type 省略时行为与旧版完全一致；传入时优先同平台同类型凭据，
    未命中则回退旧链路，避免 push 因类型不匹配而中断。
    """
    platform = platform.lower().strip()
    raw = load_raw_vault()
    accounts = raw.get("accounts", [])

    kt = parse_key_type(key_type) if key_type is not None else None
    if kt:
        ordered = []
        if repo_path:
            norm_path_kt = os.path.normpath(repo_path)
            bound_acc_id_kt = raw.get("repo_account_bindings", {}).get(norm_path_kt, {}).get(platform)
            if bound_acc_id_kt:
                ordered.extend(a for a in accounts if a.get("id") == bound_acc_id_kt)
        ordered.extend(a for a in accounts if a.get("platform") == platform and a.get("is_default"))
        ordered.extend(a for a in accounts if a.get("platform") == platform)
        for acc in ordered:
            if parse_key_type(acc.get("key_type")) != kt or not acc.get("encrypted_token"):
                continue
            plain = dpapi_decrypt(acc["encrypted_token"])
            if plain:
                return plain

    # 1. 检查仓库级独立绑定
    if repo_path:
        norm_path = os.path.normpath(repo_path)
        bound_acc_id = raw.get("repo_account_bindings", {}).get(norm_path, {}).get(platform)
        if bound_acc_id:
            for acc in accounts:
                if acc.get("id") == bound_acc_id and acc.get("encrypted_token"):
                    plain = dpapi_decrypt(acc["encrypted_token"])
                    if plain:
                        return plain

    # 2. 查找该平台的默认活动账号 (is_default == True)
    for acc in accounts:
        if acc.get("platform") == platform and acc.get("is_default") and acc.get("encrypted_token"):
            plain = dpapi_decrypt(acc["encrypted_token"])
            if plain:
                return plain

    # 3. 查找该平台的任意有效账号
    for acc in accounts:
        if acc.get("platform") == platform and acc.get("encrypted_token"):
            plain = dpapi_decrypt(acc["encrypted_token"])
            if plain:
                return plain

    # 4. 回退旧 encrypted_tokens 字段
    cipher = raw.get("encrypted_tokens", {}).get(platform, "")
    if cipher:
        return dpapi_decrypt(cipher)

    return ""

def get_tokens_masked() -> Dict[str, Any]:
    raw = load_raw_vault()
    enc_tokens = raw.get("encrypted_tokens", {})
    metadata = raw.get("token_metadata", {})
    masked = {}

    # accounts[] 为准：每平台取代表账号（is_default 优先），旧 encrypted_tokens 键只读补位
    per_platform = {}
    for acc in raw.get("accounts", []):
        p = (acc.get("platform") or "").lower()
        if not p:
            continue
        cur = per_platform.get(p)
        if cur is None or (acc.get("is_default") and not cur.get("is_default")):
            per_platform[p] = acc

    platforms = list(dict.fromkeys(list(per_platform) + list(enc_tokens)))
    for platform in platforms:
        acc = per_platform.get(platform) or {}
        cipher = acc.get("encrypted_token") or enc_tokens.get(platform, "")
        meta = metadata.get(platform, {})
        key_type = parse_key_type(acc.get("key_type")) or "pat_classic"
        expires_at = acc.get("expires_at") or meta.get("expires_at", "never")
        entry = {
            "has_token": False,
            "masked": "",
            "key_type": key_type,
            "expires_at": expires_at,
            "expiry_info": _calculate_expiry(expires_at),
            "rotation": _rotation_of(acc, key_type)
        }
        if cipher:
            plain = dpapi_decrypt(cipher)
            if plain:
                entry["has_token"] = True
                entry["masked"] = _mask_secret(plain)
            else:
                entry["masked"] = "(解密失败)"
        masked[platform] = entry

    return {
        "tokens": masked,
        "accounts": list_accounts_masked(),
        "repo_account_bindings": raw.get("repo_account_bindings", {}),
        "saved_accounts": raw.get("saved_accounts", {}),
        "non_git_secrets": get_non_git_secrets_masked(),
        "encryption": "Windows DPAPI (硬件与用户凭据级加密保护)"
    }

def update_token(platform: str, token: str, username: str = "", expires_at: str = "never", clear_token: bool = False, key_type: Optional[str] = None, scope: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    raw = load_raw_vault()
    if clear_token or (token and token.strip() == "__CLEAR__"):
        accounts = raw.get("accounts", [])
        for a in list(accounts):
            if a.get("platform") == platform and a.get("is_default"):
                delete_account(a.get("id"))
                break
        return {"success": True, "platform": platform, "encrypted": True, "encryption_method": "Windows DPAPI"}

    accounts = raw.get("accounts", [])
    default_acc = None
    for a in accounts:
        if a.get("platform") == platform and a.get("is_default"):
            default_acc = a
            break

    acc_id = default_acc.get("id") if default_acc else None
    alias = default_acc.get("alias", f"{platform.capitalize()} 默认主账号") if default_acc else f"{platform.capitalize()} 默认主账号"
    # key_type / scope 未传时回退该默认账号既有值，其次 pat_classic
    effective_key_type = key_type or (default_acc or {}).get("key_type") or "pat_classic"
    effective_scope = scope if scope is not None else (default_acc or {}).get("scope")

    res = add_or_update_account(
        platform=platform,
        token=token,
        username=username,
        alias=alias,
        expires_at=expires_at,
        is_default=True,
        account_id=acc_id,
        key_type=effective_key_type,
        scope=effective_scope
    )
    res["platform"] = platform
    res["encrypted"] = True
    res["encryption_method"] = "Windows DPAPI"
    return res

# --- Non-Git Secrets Management (Cloudflare, LLMs, Custom APIs) ---
def get_non_git_secret_plain(service: str) -> str:
    """内部解密 Non-Git 密钥（仅供 secret_proxy 在内存中微秒级注入，严禁外发或打日志）"""
    raw = load_raw_vault()
    secrets = raw.get("non_git_secrets", {})
    entry = secrets.get(service.lower().strip(), {})
    cipher = entry.get("encrypted", "")
    if not cipher:
        return ""
    return dpapi_decrypt(cipher)
def list_all_secrets_plain() -> Dict[str, Any]:
    """内部明文导出接口：仅供 export / SOPS 桥接使用，严禁接入任何 HTTP 或 MCP 响应。

    返回 {"accounts": [{id, platform, key_type, plain_token}], "non_git": {service: {key_type, plain}}}。
    调用方必须保证明文只在本机内存流转，不回传网络、不写日志。
    """
    raw = load_raw_vault()
    accounts = []
    for acc in raw.get("accounts", []):
        cipher = acc.get("encrypted_token", "")
        plain = dpapi_decrypt(cipher) if cipher else ""
        if not plain:
            continue
        accounts.append({
            "id": acc.get("id"),
            "platform": acc.get("platform"),
            "key_type": parse_key_type(acc.get("key_type")) or "pat_classic",
            "plain_token": plain,
        })
    non_git = {}
    for service, item in (raw.get("non_git_secrets", {}) or {}).items():
        item = item or {}
        cipher = item.get("encrypted", "")
        plain = dpapi_decrypt(cipher) if cipher else ""
        if not plain:
            continue
        non_git[service] = {
            "key_type": parse_key_type(item.get("key_type")) or normalize_key_type(item.get("category")),
            "plain": plain,
        }
    return {"accounts": accounts, "non_git": non_git}

def get_non_git_secrets_masked() -> Dict[str, Any]:
    """获取所有 Non-Git 密钥的脱敏掩码视图（用于 Web UI 与安全展示）"""
    raw = load_raw_vault()
    secrets = raw.get("non_git_secrets", {})
    masked = {}
    for service, item in secrets.items():
        item = item or {}
        cipher = item.get("encrypted", "")
        plain = dpapi_decrypt(cipher) if cipher else ""
        key_type = parse_key_type(item.get("key_type")) or normalize_key_type(item.get("category"))
        expires_at = item.get("expires_at", "never") or "never"
        masked[service] = {
            "service": service,
            "has_secret": bool(plain),
            "masked": _mask_secret(plain) if plain else "(未配置或解密失败)",
            "key_type": key_type,
            "category": item.get("category", "custom"),
            "env_var": item.get("env_var", f"{service.upper()}_API_KEY"),
            "alias": item.get("alias", service.capitalize()),
            "description": item.get("description", ""),
            "expires_at": expires_at,
            "expiry_info": _calculate_expiry(expires_at),
            "rotation": _rotation_of(item, key_type),
            "updated_at": item.get("updated_at", ""),
            "metadata": item.get("metadata", {})
        }
    return masked

def list_all_secrets_masked(category: Optional[str] = None) -> List[Dict[str, Any]]:
    """获取所有通用业务密钥的脱敏列表（支持按分类过滤）"""
    masked_dict = get_non_git_secrets_masked()
    res = []
    for service, item in masked_dict.items():
        cat = item.get("category", "custom")
        if category and category.lower() != "all" and cat.lower() != category.lower():
            continue
        res.append(item)
    return res

def update_non_git_secret(
    service: str,
    secret: str,
    category: str = "custom",
    description: str = "",
    metadata: Dict[str, Any] = None,
    env_var: str = "",
    alias: str = "",
    key_type: str = "",
    expires_at: str = ""
) -> Dict[str, Any]:
    """使用 Windows DPAPI 加密保存 Non-Git 密钥（含 key_type / expires_at / rotation）"""
    service = service.lower().strip()
    if not service:
        return {"success": False, "error": "服务名称不能为空"}

    raw = load_raw_vault()
    if "non_git_secrets" not in raw:
        raw["non_git_secrets"] = {}

    import datetime
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    existing = raw["non_git_secrets"].get(service, {})
    kt = parse_key_type(key_type) or parse_key_type(existing.get("key_type")) or normalize_key_type(category)

    if secret and secret.strip():
        cipher = dpapi_encrypt(secret.strip())
        raw["non_git_secrets"][service] = {
            "encrypted": cipher,
            "category": category.strip() or existing.get("category") or "custom",
            "env_var": env_var.strip() or existing.get("env_var") or f"{service.upper()}_API_KEY",
            "alias": alias.strip() or existing.get("alias") or service.capitalize(),
            "description": description.strip() if description is not None else existing.get("description", ""),
            "key_type": kt,
            "expires_at": (expires_at or "").strip() or existing.get("expires_at") or "never",
            "rotation": _next_rotation(existing, kt, True, now_str),
            "updated_at": now_str,
            "metadata": metadata or existing.get("metadata", {})
        }
    else:
        # Clear secret if empty string provided
        if service in raw["non_git_secrets"]:
            if env_var or alias or category:
                raw["non_git_secrets"][service].update({
                    "env_var": env_var.strip() or existing.get("env_var", ""),
                    "alias": alias.strip() or existing.get("alias", ""),
                    "category": category.strip() or existing.get("category", "custom"),
                    "description": description.strip() if description is not None else existing.get("description", ""),
                    "key_type": kt,
                    "expires_at": (expires_at or "").strip() or existing.get("expires_at") or "never",
                    "updated_at": now_str
                })
            else:
                del raw["non_git_secrets"][service]

    success = save_raw_vault(raw)
    return {
        "success": success,
        "service": service,
        "encrypted": True,
        "encryption_method": "Windows DPAPI"
    }

def save_generic_secret(
    service: str,
    secret: str,
    env_var: str = "",
    category: str = "custom",
    alias: str = "",
    description: str = "",
    metadata: Dict[str, Any] = None
) -> Dict[str, Any]:
    """统一保存通用业务密钥快捷别名"""
    return update_non_git_secret(
        service=service,
        secret=secret,
        category=category,
        description=description,
        metadata=metadata,
        env_var=env_var,
        alias=alias
    )

def delete_non_git_secret(service: str) -> Dict[str, Any]:
    """删除指定的 Non-Git 密钥"""
    service = service.lower().strip()
    raw = load_raw_vault()
    if "non_git_secrets" in raw and service in raw["non_git_secrets"]:
        del raw["non_git_secrets"][service]
        success = save_raw_vault(raw)
        return {"success": success, "service": service}
    return {"success": True, "service": service, "message": "密钥不存在"}

# --- Token Auto-Inspector via Platform REST APIs ---
def inspect_token_online(platform: str, token: str) -> Dict[str, Any]:
    """通过官方 API 自动探测令牌的真实用户名、过期时间及有效性"""
    import urllib.request
    import urllib.error
    token = token.strip()
    if not token:
        return {"valid": False, "error": "令牌不能为空"}

    headers = {"User-Agent": "GitVault/1.0"}

    # 配置网络代理 opener（如配置了本地 Clash/V2Ray 代理）
    opener = urllib.request.build_opener()
    try:
        from . import network_router
        routes = network_router.load_network_routes()
        p_cfg = routes.get("platforms", {}).get(platform, {})
        proxy_url = ""
        if p_cfg.get("mode") == "proxy":
            proxy_url = p_cfg.get("proxy_url") or routes.get("global_proxy", "")
        elif routes.get("global_proxy"):
            proxy_url = routes.get("global_proxy")
        if proxy_url:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({'http': proxy_url, 'https': proxy_url}))
    except Exception:
        pass
    
    if platform == "github":
        url = "https://api.github.com/user"
        req = urllib.request.Request(url, headers={"User-Agent": "GitVault/1.0", "Authorization": f"token {token}"})
        try:
            with opener.open(req, timeout=8) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                exp_header = resp.headers.get("github-authentication-token-expiration")
                scopes = resp.headers.get("x-oauth-scopes", "")
                expires_at = "never"
                if exp_header:
                    expires_at = exp_header.split()[0] # e.g. '2027-11-07'
                return {
                    "valid": True,
                    "platform": "github",
                    "username": data.get("login", ""),
                    "display_name": data.get("name", ""),
                    "expires_at": expires_at,
                    "scopes": scopes
                }
        except urllib.error.HTTPError as e:
            return {"valid": False, "error": f"GitHub 验证失败 (HTTP {e.code}): 令牌无效或无 repo 权限"}
        except Exception as e:
            return {"valid": False, "error": f"网络异常: {str(e)}"}

    elif platform == "gitee":
        url = f"https://gitee.com/api/v5/user?access_token={token}"
        req = urllib.request.Request(url, headers=headers)
        try:
            with opener.open(req, timeout=8) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return {
                    "valid": True,
                    "platform": "gitee",
                    "username": data.get("login", ""),
                    "display_name": data.get("name", ""),
                    "expires_at": "never",
                    "scopes": "projects"
                }
        except urllib.error.HTTPError as e:
            return {"valid": False, "error": f"Gitee 验证失败 (HTTP {e.code}): 令牌无效或已过期"}
        except Exception as e:
            return {"valid": False, "error": f"网络异常: {str(e)}"}

    elif platform == "gitlab":
        # Check token self metadata
        expires_at = "never"
        scopes = ""
        try:
            req_self = urllib.request.Request(
                "https://gitlab.com/api/v4/personal_access_tokens/self",
                headers={"User-Agent": "GitVault/1.0", "PRIVATE-TOKEN": token}
            )
            with opener.open(req_self, timeout=8) as resp:
                t_data = json.loads(resp.read().decode("utf-8"))
                expires_at = t_data.get("expires_at", "never")
                scopes = ",".join(t_data.get("scopes", []))
        except Exception:
            pass

        # Check user info
        try:
            req_u = urllib.request.Request(
                "https://gitlab.com/api/v4/user",
                headers={"User-Agent": "GitVault/1.0", "PRIVATE-TOKEN": token}
            )
            with opener.open(req_u, timeout=8) as resp:
                u_data = json.loads(resp.read().decode("utf-8"))
                return {
                    "valid": True,
                    "platform": "gitlab",
                    "username": u_data.get("username", ""),
                    "display_name": u_data.get("name", ""),
                    "expires_at": expires_at,
                    "scopes": scopes
                }
        except urllib.error.HTTPError as e:
            if e.code == 403:
                # 403 表示令牌已通过鉴权，但属于精细化限制（仅包含 Code:Push 仓库权限，未授予 read_user 个人信息读取权限）
                return {
                    "valid": True,
                    "platform": "gitlab",
                    "username": "<owner>",
                    "display_name": "GitLab 开发者",
                    "expires_at": expires_at,
                    "scopes": "Code:Push",
                    "note": "精细化代码令牌 (仓库读写权限有效)"
                }
            return {"valid": False, "error": f"GitLab 验证失败 (HTTP {e.code}): 令牌无效"}
        except Exception as e:
            return {"valid": False, "error": f"网络异常: {str(e)}"}

    return {"valid": False, "error": f"未知平台: {platform}"}

# --- Windows Credential Manager Interop ---
def list_windows_git_credentials() -> List[Dict[str, str]]:
    credentials = []
    try:
        proc = subprocess.run(
            ["cmdkey", "/list"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5
        )
        output = proc.stdout
        blocks = re.split(r"\r?\n\s*\r?\n", output)
        for block in blocks:
            if any(k in block.lower() for k in ["git:", "github", "gitee", "gitlab"]):
                target_match = re.search(r"(?:Target|目标):\s*(.+)", block, re.IGNORECASE)
                user_match = re.search(r"(?:User|用户名):\s*(.+)", block, re.IGNORECASE)
                type_match = re.search(r"(?:Type|类型):\s*(.+)", block, re.IGNORECASE)
                if target_match:
                    credentials.append({
                        "target": target_match.group(1).strip(),
                        "user": user_match.group(1).strip() if user_match else "N/A",
                        "type": type_match.group(1).strip() if type_match else "Generic"
                    })
    except Exception as e:
        credentials.append({"target": "Error reading cmdkey", "user": str(e), "type": "Error"})
    return credentials

def delete_windows_credential(target: str) -> Dict[str, Any]:
    try:
        proc = subprocess.run(
            ["cmdkey", f"/delete:{target}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5
        )
        return {
            "success": proc.returncode == 0,
            "target": target,
            "output": (proc.stdout + proc.stderr).strip()
        }
    except Exception as e:
        return {"success": False, "target": target, "error": str(e)}
