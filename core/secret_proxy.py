# core/secret_proxy.py
# Antigravity Git-Vault - Zero-Plaintext Secret Proxy & Cloudflare Gateway
import json
import urllib.request
import urllib.error
import urllib.parse
import ipaddress
import socket
import base64
import re
from typing import Dict, List, Any, Optional
from core import credential_vault
from core.redaction import redact, redact_text

CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4"

# service -> (固定主机, 路径前缀)。代理只能访问这些目标，禁止调用方指定任意 URL。
SERVICE_ALLOW = {
    "cloudflare": ("api.cloudflare.com", "/client/v4"),
    "openai": ("api.openai.com", "/v1"),
    "anthropic": ("api.anthropic.com", "/v1"),
    "github": ("api.github.com", "/"),
    "gitee": ("gitee.com", "/api/v5"),
    "gemini": ("generativelanguage.googleapis.com", "/"),
}


def resolve_proxy_target(service: str, endpoint: str):
    """把相对 endpoint 解析为该 service 的固定目标；绝对 URL 仅允许同 service 主机。"""
    service = (service or "").lower().strip()
    allow = SERVICE_ALLOW.get(service)
    if not allow:
        return None, (400, f"[PROXY][400] 不允许的 service: {service}")
    host, prefix = allow
    endpoint = (endpoint or "").strip()
    if endpoint.startswith(("http://", "https://")):
        parsed = urllib.parse.urlsplit(endpoint)
        if parsed.scheme != "https" or (parsed.hostname or "").lower() != host \
                or parsed.username or parsed.password or parsed.port not in (None, 443):
            return None, (400, "[PROXY][400] 绝对 URL 只允许同一 service 的固定 https 主机")
        path = parsed.path or "/"
        if prefix != "/" and not (path == prefix or path.startswith(prefix + "/")):
            return None, (400, "[PROXY][400] 路径超出该 service 的白名单前缀")
        target_url = endpoint
    else:
        ep = endpoint.lstrip("/")
        p = prefix.strip("/")
        if p and (ep == p or ep.startswith(p + "/")):
            ep = ep[len(p):].lstrip("/")
        if prefix == "/":
            target_url = f"https://{host}/{ep}"
        else:
            target_url = f"https://{host}{prefix}/{ep}"
    # SSRF: 解析主机，拒绝非公网地址
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except Exception:
        return None, (400, "[PROXY][400] 目标主机解析失败")
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            return None, (400, "[PROXY][400] 目标主机解析到非公网地址，已拒绝")
    return target_url, None

def sanitize_response(data: Any, sensitive_token: str = "") -> Any:
    """Recursively scrub plaintext token, credential shapes, and base64 echo of them."""
    if sensitive_token:
        data = _strip_exact(data, sensitive_token)
    data = redact(data)
    return _decode_base64_secrets(data)


def _strip_exact(data: Any, token: str) -> Any:
    if isinstance(data, str):
        return data.replace(token, "[REDACTED_SECRET]")
    if isinstance(data, dict):
        return {k: _strip_exact(v, token) for k, v in data.items()}
    if isinstance(data, list):
        return [_strip_exact(v, token) for v in data]
    return data


def _decode_base64_secrets(data: Any) -> Any:
    """检测 Base64 回显：解码后若命中凭据形状，则整串替换。"""
    if isinstance(data, str):
        s = data.strip()
        if len(s) >= 16 and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s):
            try:
                raw = base64.b64decode(s, validate=True).decode("utf-8", "ignore")
            except Exception:
                raw = ""
            if re.search(r"(gh[pousr]_[A-Za-z0-9]{20,}|glpat-[A-Za-z0-9_\-]{20,}|cfut_[A-Za-z0-9]{20,}"
                         r"|sk-[A-Za-z0-9]{16,}|oauth2:|access_token=|[a-fA-F0-9]{32})", raw):
                return "<REDACTED>"
        return data
    if isinstance(data, dict):
        return {k: _decode_base64_secrets(v) for k, v in data.items()}
    if isinstance(data, list):
        return [_decode_base64_secrets(v) for v in data]
    return data

def execute_proxy_request(
    service: str,
    endpoint: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    query_params: Optional[Dict[str, Any]] = None,
    payload: Optional[Any] = None,
    timeout: int = 15
) -> Dict[str, Any]:
    """
    Execute zero-plaintext HTTP request.
    Token is decrypted in private process memory, injected into headers,
    and never exposed to caller or logs.
    """
    service = service.lower().strip()
    plain_token = credential_vault.get_non_git_secret_plain(service)
    
    # Fallback: check git platform token if service is github/gitee/gitlab
    if not plain_token and service in ["github", "gitee", "gitlab"]:
        raw_vault = credential_vault.load_raw_vault()
        cipher = raw_vault.get("encrypted_tokens", {}).get(service, "")
        if cipher:
            plain_token = credential_vault.dpapi_decrypt(cipher)

    if not plain_token:
        return {
            "success": False,
            "status_code": 401,
            "error": f"[PROXY][401] 服务 '{service}' 尚未在保险箱中配置密钥或解密失败。",
            "data": None
        }

    # Resolve target URL through strict allowlist (no arbitrary URL, no SSRF, no userinfo)
    target_url, err = resolve_proxy_target(service, endpoint)
    if err:
        code, msg = err
        return {"success": False, "status_code": code, "error": msg, "data": None}

    if query_params:
        query_string = urllib.parse.urlencode(query_params)
        sep = "&" if "?" in target_url else "?"
        target_url = f"{target_url}{sep}{query_string}"

    req_headers = {
        "User-Agent": "GitVault-SecretProxy/1.0",
        "Accept": "application/json"
    }
    if headers:
        for k, v in headers.items():
            if k.lower() not in ["authorization", "x-auth-key", "x-auth-email"]:
                req_headers[k] = v

    # Inject Authorization Header in memory
    if service == "cloudflare":
        req_headers["Authorization"] = f"Bearer {plain_token}"
    elif service in ["openai", "gemini"]:
        req_headers["Authorization"] = f"Bearer {plain_token}"
    elif service == "anthropic":
        req_headers["x-api-key"] = plain_token
        req_headers["anthropic-version"] = "2023-06-01"
    elif service == "github":
        req_headers["Authorization"] = f"token {plain_token}"
    elif service == "gitee":
        req_headers["Authorization"] = f"Bearer {plain_token}"
    else:
        req_headers["Authorization"] = f"Bearer {plain_token}"

    data_bytes = None
    if payload is not None and method.upper() in ["POST", "PUT", "PATCH", "DELETE"]:
        req_headers["Content-Type"] = "application/json; charset=utf-8"
        if isinstance(payload, str):
            data_bytes = payload.encode("utf-8")
        else:
            data_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    req = urllib.request.Request(
        url=target_url,
        data=data_bytes,
        headers=req_headers,
        method=method.upper()
    )

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None

    opener = urllib.request.build_opener(_NoRedirect())

    try:
        with opener.open(req, timeout=timeout) as resp:
            resp_code = resp.getcode()
            raw_body = resp.read().decode("utf-8", errors="replace")
            try:
                parsed_json = json.loads(raw_body)
                cleaned_data = sanitize_response(parsed_json, plain_token)
            except Exception:
                cleaned_data = sanitize_response(raw_body, plain_token)

            return {
                "success": True,
                "status_code": resp_code,
                "service": service,
                "endpoint": endpoint,
                "data": cleaned_data
            }
    except urllib.error.HTTPError as e:
        if 300 <= e.code < 400:
            return {"success": False, "status_code": e.code, "error": "[PROXY] 目标返回重定向，已阻止（防止凭据二次外发）", "details": None}
        err_body = e.read().decode("utf-8", errors="replace")
        try:
            parsed_err = json.loads(err_body)
            cleaned_err = sanitize_response(parsed_err, plain_token)
        except Exception:
            cleaned_err = sanitize_response(err_body, plain_token)

        return {
            "success": False,
            "status_code": e.code,
            "service": service,
            "endpoint": endpoint,
            "error": f"[PROXY][HTTP_{e.code}] 目标 API 响应错误",
            "details": cleaned_err
        }
    except Exception as e:
        return {
            "success": False,
            "status_code": 500,
            "service": service,
            "endpoint": endpoint,
            "error": f"[PROXY][ERR] 代理网络请求失败: {str(e)}",
            "details": None
        }

# --- Cloudflare Dedicated Shortcuts ---
def cloudflare_verify_token() -> Dict[str, Any]:
    """Verify stored Cloudflare API Token status and validity."""
    res = execute_proxy_request(
        service="cloudflare",
        endpoint="user/tokens/verify",
        method="GET"
    )
    if res["success"]:
        data = res.get("data", {})
        result = data.get("result", {})
        status = result.get("status", "unknown")
        return {
            "valid": status == "active",
            "status": status,
            "id": result.get("id", ""),
            "message": "[OK] Cloudflare 令牌处于有效激活状态。" if status == "active" else f"[WARN] 令牌状态: {status}",
            "raw": data
        }
    return {
        "valid": False,
        "status": "invalid",
        "error": res.get("error", "验证失败"),
        "details": res.get("details")
    }

def cloudflare_list_zones() -> Dict[str, Any]:
    """List Cloudflare Zones with status, domain, name, and plan."""
    res = execute_proxy_request(
        service="cloudflare",
        endpoint="zones",
        method="GET"
    )
    if res["success"]:
        data = res.get("data", {})
        zones_raw = data.get("result", [])
        zones = []
        for z in zones_raw:
            zones.append({
                "id": z.get("id"),
                "name": z.get("name"),
                "status": z.get("status"),
                "paused": z.get("paused"),
                "type": z.get("type"),
                "name_servers": z.get("name_servers", []),
                "plan": z.get("plan", {}).get("name", "Free")
            })
        return {
            "success": True,
            "count": len(zones),
            "zones": zones
        }
    return {
        "success": False,
        "error": res.get("error", "获取 Zone 列表失败"),
        "details": res.get("details")
    }

def cloudflare_purge_cache(zone_id: str, purge_everything: bool = True, files: Optional[List[str]] = None) -> Dict[str, Any]:
    """Purge cache for a given zone."""
    if not zone_id:
        return {"success": False, "error": "[PROXY] zone_id 不能为空"}

    body: Dict[str, Any] = {}
    if purge_everything:
        body["purge_everything"] = True
    elif files:
        body["files"] = files
    else:
        body["purge_everything"] = True

    res = execute_proxy_request(
        service="cloudflare",
        endpoint=f"zones/{zone_id}/purge_cache",
        method="POST",
        payload=body
    )
    if res["success"]:
        return {
            "success": True,
            "zone_id": zone_id,
            "message": f"[OK] 已成功为 Zone {zone_id} 触发全站缓存清理 (Purge Cache)！",
            "data": res.get("data")
        }
    return {
        "success": False,
        "zone_id": zone_id,
        "error": res.get("error", "清理缓存失败"),
        "details": res.get("details")
    }
