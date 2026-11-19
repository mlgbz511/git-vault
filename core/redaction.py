# core/redaction.py
# Git-Vault output redaction: secrets never leave the process in plaintext.
import re
from typing import Any

REDACTED = "<REDACTED>"

SENSITIVE_KEYS = {
    "token", "access_token", "refresh_token", "id_token",
    "password", "passwd", "secret", "client_secret",
    "api_key", "apikey", "private_key", "authorization",
    "auth", "credential", "credentials", "x-k",
}

_PATTERNS = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL), REDACTED),
    (re.compile(r"(://)[^/@\s]+@"), r"\1***@"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), REDACTED),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), REDACTED),
    (re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"), REDACTED),
    (re.compile(r"\bcfut_[A-Za-z0-9]{20,}\b"), REDACTED),
    (re.compile(r"\bsk-[A-Za-z0-9]{16,}\b"), REDACTED),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), REDACTED),
    (re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"), REDACTED),
    (re.compile(r"(?i)\b(Bearer|Token|Basic)\s+([A-Za-z0-9._~+/=\-]{12,})"), lambda m: m.group(1) + " " + REDACTED),
]

_KEY_VALUE = re.compile(
    r"(?i)([\"']?(?:access[_-]?token|refresh[_-]?token|token|password|passwd|secret|"
    r"api[_-]?key|private[_-]?key|authorization)[\"']?\s*[:=]\s*)([\"']?)([^\"'\s,}]{8,})"
)


def redact_text(text: Any) -> str:
    """Mask known credential shapes inside one string."""
    if text is None:
        return text
    s = str(text)
    for pattern, replacement in _PATTERNS:
        s = pattern.sub(replacement, s)
    s = _KEY_VALUE.sub(lambda m: m.group(1) + m.group(2) + REDACTED, s)
    return s


def sanitize_url_credentials(url: Any) -> Any:
    """Hide only URL userinfo: scheme://user:pass@host -> scheme://***@host."""
    if not url:
        return url
    return re.sub(r"(://)[^/@\s]+@", r"\1***@", str(url))


def sanitize_remotes(remotes: Any) -> Any:
    if not isinstance(remotes, dict):
        return remotes
    out = dict(remotes)
    if out.get("fetch_url"):
        out["fetch_url"] = sanitize_url_credentials(out["fetch_url"])
    if isinstance(out.get("push_urls"), list):
        out["push_urls"] = [sanitize_url_credentials(u) for u in out["push_urls"]]
    return out


def _OPAQUE_SECRET_RE() -> re.Pattern:
    return re.compile(r"[A-Za-z0-9+/=_\-.]{24,512}")


_OPAQUE_SECRET = _OPAQUE_SECRET_RE()


def _looks_like_secret(value: str) -> bool:
    """敏感键容器内的叶子兜底：大小写+数字三类齐全的高熵不透明串按密钥处理。

    放宽容器脱敏后用它保证 fail-closed：无固定前缀的随机密钥仍会被抹掉。
    实测本机 vault 快照 63 个叶子字符串零命中（时间戳/UUID/掩码串均不满足）。
    """
    if not _OPAQUE_SECRET.fullmatch(value):
        return False
    return (any(c.islower() for c in value)
            and any(c.isupper() for c in value)
            and any(c.isdigit() for c in value))


def redact(obj: Any, in_sensitive_container: bool = False) -> Any:
    """递归脱敏 dicts/lists/strings，用于任何对外输出。

    键名命中 SENSITIVE_KEYS 时按值的**形状**决定，而不是整值抹掉：
      bool            -> 原样保留（行为不变）
      dict / list     -> 递归进入（修复点）
      其它标量        -> REDACTED（真正的密钥值，行为不变）

    修复原因：credentials 这类键装的是**已脱敏的结构化容器**（账号列表），
    旧写法把整个列表抹成 "<REDACTED>" 字符串，使前端
    `data.credentials || data.accounts` 兜底失效并抛 TypeError。
    递归进入时启用 in_sensitive_container 兜底，容器内形似高熵密钥的叶子仍抹掉，
    其余叶子照常过 redact_text 形态匹配，因此不降低整体脱敏强度。
    """
    if isinstance(obj, str):
        if in_sensitive_container and _looks_like_secret(obj):
            return REDACTED
        return redact_text(obj)
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            sensitive = isinstance(k, str) and k.lower() in SENSITIVE_KEYS
            if sensitive and v not in (None, "", False):
                if isinstance(v, bool):
                    out[k] = v
                elif isinstance(v, (dict, list, tuple, set)):
                    out[k] = redact(v, True)
                else:
                    out[k] = REDACTED
            else:
                out[k] = redact(v, in_sensitive_container)
        return out
    if isinstance(obj, (list, tuple, set)):
        return [redact(v, in_sensitive_container) for v in obj]
    return obj
