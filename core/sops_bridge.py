# core/sops_bridge.py
# Antigravity Git-Vault - SOPS + age 跨机密文层
"""SOPS + age 跨机凭据密文层（T4）。路由接入归 T5，tests 归 T6。

对外接口（canonical + 别名，别名与 canonical 同一实现，T5 用别名）：
    export_secrets / export_to_file   明文导出 -> 临时明文 -> sops 加密 -> 目标文件
    import_secrets / import_from_file sops 解密 -> 灌回 DPAPI 库 -> 只回变更摘要
    diff_secrets  / diff_with_vault   库 vs 密文差异 -> 只回名字与动作
    sops_available()                  能力探测 + 版本，供 T5 GET /api/vault/sops/status
    INSTALL_HINT                      sops 缺失时的安装指引文案（T5 直接取用）

硬约束：
- 明文只存在于内存与 sops 的输入临时文件，临时文件 finally 删除。
- age 私钥绝不进 argv：只经 SOPS_AGE_KEY_FILE 指向的 0600 临时文件；argv 只带路径。
- sops stderr 一律过 redaction.redact_text() 才返回；返回值不含任何明文值。
- sops.exe 缺失时立即返回 error="SOPS_NOT_INSTALLED" + install_hint，不降级写明文。
- sops 内置 age 支持，加解密不需要额外的 age.exe；age-keygen 仅用于一次性生成密钥。

age 私钥来源（方案 A，已冻结）：DPAPI 库 non_git_secrets["_sops_age_key"]，
写入方式：update_non_git_secret("_sops_age_key", "<私钥整段>")。
库中没有时回退环境变量 SOPS_AGE_KEY（本机/CI 应急用，同样只落临时文件、不进 argv）。
gen key（用户侧一次性，需联网）：
    age-keygen -o %USERPROFILE%\\.config\\sops\\age.key
    公钥 age1... 填进 .sops.yaml 的 creation_rules.age
    私钥整段（含 AGE-SECRET-KEY-1... 行）存进 _sops_age_key

可搬移方案（仅说明，未实现）：age -p 口令包裹私钥为 age.key.age，换机时 age -d 解出口令
再存入 DPAPI。sops 不接受口令加密的 age 文件，必须先解一次。

密文文件结构（.sops.yaml 的 encrypted_regex 只加密 secret 叶子，key 名与元数据全明文，保证 diff 可读）：
    schema_version: 1
    exported_at: "..."
    accounts:
      "<account_id>": {platform, key_type, secret}
    non_git:
      "<service>": {key_type, secret}

真实 export->import round-trip 在本机（无 sops.exe）未验证，见交付说明。
"""
import json
import os
import shutil
import subprocess
import tempfile
import datetime
from typing import Any, Dict, List, Optional, Tuple

try:
    from core import redaction as _redaction
except Exception:  # 直接以脚本方式运行时无 core 包
    _redaction = None

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# 默认目标路径冻结为 config/vault.enc.yaml（与 .sops.yaml 的 path_regex 一致）
DEFAULT_CROSS_FILE = os.path.join(ROOT_DIR, "config", "vault.enc.yaml")
SOPS_CONFIG_FILE = os.path.join(ROOT_DIR, ".sops.yaml")
SOPS_BIN_ENV = "GIT_VAULT_SOPS_BIN"   # 覆盖 sops 路径，供 T6 假脚本注入
AGE_KEY_SERVICE = "_sops_age_key"
AGE_KEY_ENV = "SOPS_AGE_KEY"
SCHEMA_VERSION = 1
SECRET_LEAF = "secret"
DEFAULT_TIMEOUT = 60

INSTALL_HINT = (
    "本机未检测到 sops.exe。跨机密文层依赖 sops（sops 内置 age 支持，加解密无需单独装 age.exe）。"
    "安装任选其一："
    "1) winget：先运行「winget search sops」确认包 id 再 install（未联网无法预填 id）；"
    "2) choco install sops；"
    "3) scoop install sops；"
    "4) 手动下载 sops.exe（github.com/getsops/sops/releases），放入已在 PATH 的目录；"
    "验证：sops --version 有输出。"
    "生成 age 密钥（一次性）：age-keygen -o %USERPROFILE%\\.config\\sops\\age.key，"
    "公钥 age1... 填进仓库根 .sops.yaml 的 creation_rules.age，"
    "私钥整段存入 DPAPI 库：update_non_git_secret('_sops_age_key', 私钥内容)。"
)


def _redact(text: Any) -> str:
    if text is None:
        return ""
    s = str(text)
    return _redaction.redact_text(s) if _redaction else s


def _now() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _fail(code: str, message: str = "", **extra: Any) -> Dict[str, Any]:
    res: Dict[str, Any] = {
        "success": False,
        "error": code,
        "message": _redact(message),
        "install_hint": INSTALL_HINT if code in ("SOPS_NOT_INSTALLED", "SOPS_BROKEN") else "",
    }
    res.update(extra)
    return res


def _sops_bin() -> str:
    override = (os.environ.get(SOPS_BIN_ENV) or "").strip()
    if override:
        return override
    return shutil.which("sops") or ""


def _cmdline(bin_path: str, args: List[str]) -> List[str]:
    """argv 组装：仅放可执行文件与参数（/路径），私钥永不入 argv。"""
    low = bin_path.lower()
    if os.name == "nt" and low.endswith((".bat", ".cmd")):
        return [os.environ.get("COMSPEC", "cmd.exe"), "/d", "/c", bin_path] + list(args)
    if os.name == "nt" and low.endswith(".ps1"):
        shell = shutil.which("pwsh") or "powershell.exe"
        return [shell, "-NoProfile", "-NonInteractive", "-File", bin_path] + list(args)
    return [bin_path] + list(args)


def sops_available() -> Dict[str, Any]:
    """探测 sops 能力。available 仅取决于 sops 本身；age 字段仅供展示（非必需）。"""
    bin_path = _sops_bin()
    info: Dict[str, Any] = {
        "available": False,
        "sops": bin_path,
        "age": shutil.which("age") or "",
        "sops_version": "",
        "error": "",
        "install_hint": INSTALL_HINT,
    }
    if not bin_path:
        info["error"] = "SOPS_NOT_INSTALLED"
        return info
    try:
        proc = subprocess.run(
            _cmdline(bin_path, ["--version"]),
            text=True, encoding="utf-8", errors="replace",
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15,
        )
        out = ((proc.stdout or "") + (proc.stderr or "")).strip()
        info["sops_version"] = out.splitlines()[0] if out else ""
        info["available"] = proc.returncode == 0
        if not info["available"]:
            info["error"] = "SOPS_BROKEN"
            info["message"] = _redact(out)
    except Exception as exc:
        info["error"] = "SOPS_BROKEN"
        info["message"] = _redact(exc)
    return info


def _load_age_key() -> str:
    try:
        from core import credential_vault
        key = (credential_vault.get_non_git_secret_plain(AGE_KEY_SERVICE) or "").strip()
        if key:
            return key
    except Exception:
        pass
    return (os.environ.get(AGE_KEY_ENV) or "").strip()


def _run_sops(args: List[str], age_key: str = "", timeout: int = DEFAULT_TIMEOUT) -> Tuple[int, str, str]:
    """执行 sops：私钥经 0600 临时文件 + SOPS_AGE_KEY_FILE 注入，finally 删除。"""
    key_path = ""
    env = os.environ.copy()
    env.pop(AGE_KEY_ENV, None)
    if age_key:
        fd, key_path = tempfile.mkstemp(prefix=".gv-age-", suffix=".key")
        try:
            os.chmod(key_path, 0o600)
        except Exception:
            pass
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(age_key if age_key.endswith("\n") else age_key + "\n")
        env["SOPS_AGE_KEY_FILE"] = key_path
    try:
        proc = subprocess.run(
            _cmdline(_sops_bin(), args),
            env=env, cwd=ROOT_DIR, text=True, encoding="utf-8", errors="replace",
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
        )
        return proc.returncode, proc.stdout or "", _redact(proc.stderr or "")
    finally:
        if key_path and os.path.exists(key_path):
            try:
                os.unlink(key_path)
            except Exception:
                pass


def _preflight(target: str) -> Optional[Dict[str, Any]]:
    """公共前置：sops 可用 + age 私钥可用。返回 None 表示通过。"""
    info = sops_available()
    if not info["available"]:
        return _fail(
            info.get("error") or "SOPS_NOT_INSTALLED",
            info.get("message") or "跨机密文层需要 sops.exe，本机不可用。",
            path=target,
        )
    if not _load_age_key():
        return _fail(
            "AGE_KEY_MISSING",
            "未找到 age 私钥：请用 update_non_git_secret('_sops_age_key', 私钥内容) 存入 DPAPI 库，"
            "或临时设置环境变量 SOPS_AGE_KEY。",
            path=target,
        )
    return None


def _build_document(payload: Dict[str, Any]) -> Dict[str, Any]:
    accounts: Dict[str, Any] = {}
    for acc in payload.get("accounts") or []:
        acc_id = str(acc.get("id") or "").strip()
        plain = acc.get("plain_token") or ""
        if not acc_id or not plain:
            continue
        accounts[acc_id] = {
            "platform": acc.get("platform") or "",
            "key_type": acc.get("key_type") or "pat_classic",
            SECRET_LEAF: plain,
        }
    non_git: Dict[str, Any] = {}
    for service, item in (payload.get("non_git") or {}).items():
        item = item or {}
        plain = item.get("plain") or ""
        if not plain:
            continue
        non_git[str(service)] = {
            "key_type": item.get("key_type") or "",
            SECRET_LEAF: plain,
        }
    return {
        "schema_version": SCHEMA_VERSION,
        "exported_at": _now(),
        "accounts": accounts,
        "non_git": non_git,
    }


def _entry_names(doc: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    return (doc.get("accounts") or {}, doc.get("non_git") or {})


def export_secrets(path: Optional[str] = None,
                   recipients: Optional[List[str]] = None,
                   dry_run: bool = False) -> Dict[str, Any]:
    """明文导出并 sops 加密到目标文件。返回值只含名字与计数，不含任何密钥值。"""
    target = os.path.abspath(path or DEFAULT_CROSS_FILE)
    blocked = _preflight(target)
    if blocked:
        return blocked
    age_key = _load_age_key()
    try:
        from core import credential_vault
        payload = credential_vault.list_all_secrets_plain()
    except Exception as exc:
        return _fail("VAULT_READ_FAILED", exc, path=target)

    doc = _build_document(payload)
    names = sorted([f"accounts:{k}" for k in doc["accounts"]] + [f"non_git:{k}" for k in doc["non_git"]])
    base = {
        "path": target,
        "count": len(names),
        "names": names,
        "sops_version": sops_available().get("sops_version", ""),
        "install_hint": "",
    }
    if dry_run:
        base.update({"success": True, "dry_run": True})
        return base
    if not names:
        base.update({"success": True, "dry_run": False, "note": "库内无可用明文密钥，未生成文件"})
        return base

    os.makedirs(os.path.dirname(target), exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".gv-export-", suffix=".yaml", dir=os.path.dirname(target))
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            # JSON 是合法 YAML；sops 按 yaml 输出重排成块状，避免手写 YAML emitter
            json.dump(doc, fh, indent=2, ensure_ascii=False, sort_keys=True)
            fh.write("\n")
        args = ["--encrypt", "--input-type", "yaml", "--output-type", "yaml", "--output", target]
        if os.path.exists(SOPS_CONFIG_FILE):
            args += ["--config", SOPS_CONFIG_FILE]
        if recipients:
            args += ["--age", ",".join(recipients)]
        args.append(tmp)
        rc, _out, err = _run_sops(args, age_key)
    except subprocess.TimeoutExpired:
        return _fail("SOPS_TIMEOUT", "sops 加密超时", path=target)
    except Exception as exc:
        return _fail("SOPS_FAILED", exc, path=target)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except Exception:
                pass
    if rc != 0:
        return _fail("SOPS_FAILED", err or "sops 加密失败", path=target, returncode=rc)

    # 明文泄漏兜底：产物里出现任何一个明文值即删除产物并报错
    try:
        with open(target, "r", encoding="utf-8") as fh:
            content = fh.read()
    except Exception as exc:
        return _fail("SOPS_READBACK_FAILED", exc, path=target)
    pairs = [(f"accounts:{k}", v) for k, v in doc["accounts"].items()] + \
            [(f"non_git:{k}", v) for k, v in doc["non_git"].items()]
    leaked = [name for name, entry in pairs
              if entry.get(SECRET_LEAF) and entry[SECRET_LEAF] in content]
    if leaked:
        try:
            os.unlink(target)
        except Exception:
            pass
        return _fail("SOPS_PLAINTEXT_LEAK", "加密产物仍含明文，已删除产物", path=target, leaked=len(leaked))

    base.update({"success": True, "dry_run": False, "bytes": os.path.getsize(target)})
    return base


def _decrypt_document(path: str, age_key: str) -> Tuple[Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """sops 解密并转 JSON 读取，零第三方 YAML 依赖。"""
    if not os.path.exists(path):
        return None, _fail("CROSS_FILE_MISSING", "密文文件不存在", path=path)
    try:
        rc, out, err = _run_sops(
            ["--decrypt", "--input-type", "yaml", "--output-type", "json", path], age_key)
    except subprocess.TimeoutExpired:
        return None, _fail("SOPS_TIMEOUT", "sops 解密超时", path=path)
    except Exception as exc:
        return None, _fail("SOPS_FAILED", exc, path=path)
    if rc != 0:
        return None, _fail("SOPS_FAILED", err or "sops 解密失败", path=path, returncode=rc)
    try:
        doc = json.loads(out)
    except Exception:
        return None, _fail("CROSS_FILE_INVALID", "解密结果结构非法", path=path)
    if not isinstance(doc, dict):
        return None, _fail("CROSS_FILE_INVALID", "解密结果结构非法", path=path)
    return doc, None


def import_secrets(path: Optional[str] = None,
                   dry_run: bool = False,
                   prune_missing: bool = False) -> Dict[str, Any]:
    """解密目标文件并灌回 DPAPI 库；只返回服务名与动作，绝不含明文。"""
    target = os.path.abspath(path or DEFAULT_CROSS_FILE)
    blocked = _preflight(target)
    if blocked:
        return blocked
    doc, err = _decrypt_document(target, _load_age_key())
    if err:
        return err
    try:
        from core import credential_vault
        from core.credential_types import parse_key_type
        current = credential_vault.list_all_secrets_plain()
    except Exception as exc:
        return _fail("VAULT_READ_FAILED", exc, path=target)

    file_accounts, file_non_git = _entry_names(doc)
    cur_accounts = {str(a.get("id")): a for a in (current.get("accounts") or []) if a.get("id")}
    cur_non_git = current.get("non_git") or {}

    added: List[str] = []
    updated: List[str] = []
    unchanged = 0
    for acc_id, entry in file_accounts.items():
        entry = entry or {}
        plain = str(entry.get(SECRET_LEAF) or "").strip()
        if not plain:
            continue
        name = f"accounts:{acc_id}"
        if acc_id not in cur_accounts:
            added.append(name)
        elif cur_accounts[acc_id].get("plain_token") != plain:
            updated.append(name)
        else:
            unchanged += 1
    for service, entry in file_non_git.items():
        entry = entry or {}
        plain = str(entry.get(SECRET_LEAF) or "").strip()
        if not plain:
            continue
        name = f"non_git:{service}"
        if service not in cur_non_git:
            added.append(name)
        elif cur_non_git[service].get("plain") != plain:
            updated.append(name)
        else:
            unchanged += 1

    removed: List[str] = []
    if prune_missing:
        removed = [f"accounts:{k}" for k in cur_accounts if k not in file_accounts] + \
                  [f"non_git:{k}" for k in cur_non_git if k not in file_non_git]

    summary: Dict[str, Any] = {
        "success": True,
        "path": target,
        "added": sorted(added),
        "updated": sorted(updated),
        "removed": sorted(removed),
        "unchanged": unchanged,
        "count": len(added) + len(updated) + unchanged,
        "dry_run": bool(dry_run),
        "install_hint": "",
    }
    if dry_run:
        return summary

    failed: List[str] = []
    for acc_id, entry in file_accounts.items():
        entry = entry or {}
        plain = str(entry.get(SECRET_LEAF) or "").strip()
        if not plain:
            continue
        res = credential_vault.add_or_update_account(
            platform=entry.get("platform") or "github",
            token=plain,
            account_id=str(acc_id),
            key_type=entry.get("key_type") or "pat_classic",
        )
        if not res.get("success"):
            failed.append(f"accounts:{acc_id}")
    for service, entry in file_non_git.items():
        entry = entry or {}
        plain = str(entry.get(SECRET_LEAF) or "").strip()
        if not plain:
            continue
        kt = entry.get("key_type") or ""
        res = credential_vault.update_non_git_secret(
            service=str(service),
            secret=plain,
            key_type=kt if parse_key_type(kt) else "",
        )
        if not res.get("success"):
            failed.append(f"non_git:{service}")
    if prune_missing:
        for name in removed:
            kind, _, key = name.partition(":")
            if kind == "accounts":
                credential_vault.delete_account(key)
            else:
                credential_vault.delete_non_git_secret(key)

    summary["success"] = not failed
    summary["failed"] = sorted(failed)
    if failed:
        summary["error"] = "IMPORT_PARTIAL"
    return summary


def diff_secrets(path: Optional[str] = None) -> Dict[str, Any]:
    """比对库与密文文件；只返回名字与动作，不返回任何值。"""
    target = os.path.abspath(path or DEFAULT_CROSS_FILE)
    blocked = _preflight(target)
    if blocked:
        return blocked
    doc, err = _decrypt_document(target, _load_age_key())
    if err:
        return err
    try:
        from core import credential_vault
        current = credential_vault.list_all_secrets_plain()
    except Exception as exc:
        return _fail("VAULT_READ_FAILED", exc, path=target)

    file_accounts, file_non_git = _entry_names(doc)
    cur_accounts = {str(a.get("id")): a for a in (current.get("accounts") or []) if a.get("id")}
    cur_non_git = current.get("non_git") or {}

    vault_keys = {f"accounts:{k}" for k in cur_accounts} | {f"non_git:{k}" for k in cur_non_git}
    file_keys = {f"accounts:{k}" for k in file_accounts} | {f"non_git:{k}" for k in file_non_git}
    changed: List[str] = []
    same = 0
    for name in sorted(vault_keys & file_keys):
        kind, _, key = name.partition(":")
        if kind == "accounts":
            a = cur_accounts.get(key) or {}
            b = file_accounts.get(key) or {}
            if a.get("plain_token") == b.get(SECRET_LEAF):
                same += 1
            else:
                changed.append(name)
        else:
            a = cur_non_git.get(key) or {}
            b = file_non_git.get(key) or {}
            if a.get("plain") == b.get(SECRET_LEAF):
                same += 1
            else:
                changed.append(name)

    return {
        "success": True,
        "path": target,
        "vault_only": sorted(vault_keys - file_keys),
        "file_only": sorted(file_keys - vault_keys),
        "changed": changed,
        "same": same,
        "has_changes": bool(changed or (vault_keys - file_keys) or (file_keys - vault_keys)),
        "install_hint": "",
    }


# --- 任务术语别名（T5 按这三个名字写死，勿改名） ---
export_to_file = export_secrets
import_from_file = import_secrets
diff_with_vault = diff_secrets

__all__ = [
    "INSTALL_HINT", "DEFAULT_CROSS_FILE", "SOPS_CONFIG_FILE", "SOPS_BIN_ENV", "AGE_KEY_SERVICE",
    "sops_available", "export_secrets", "import_secrets", "diff_secrets",
    "export_to_file", "import_from_file", "diff_with_vault",
]
