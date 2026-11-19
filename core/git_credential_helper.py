#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Git credential helper backed by Git-Vault DPAPI store.

Token flows git <-> helper via stdin/stdout only: never in argv or env.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core import credential_vault


def _platform(host: str) -> str:
    host = (host or "").lower()
    if "github.com" in host:
        return "github"
    if "gitee.com" in host:
        return "gitee"
    if "gitlab.com" in host:
        return "gitlab"
    return ""


# 通道优先级：HTTPS 优先最小授权的细粒度 PAT，其次经典 PAT 与 App 令牌。
_HTTPS_KEY_TYPES = ("pat_fine", "pat_classic", "gh_cli_token", "oauth_user_token",
                    "app_installation_token")


def _channel(req: dict) -> str:
    """依据 credential 请求判定通道；缺省 https 保持旧行为。"""
    proto = (req.get("protocol") or "").lower()
    url = (req.get("url") or "").lower()
    if proto == "ssh" or url.startswith(("ssh://", "git@")):
        return "ssh"
    return "https"


def _token_for(platform: str) -> str:
    """按 key_type 优先级取 HTTPS 通道令牌；全类型未命中则回退默认链路。"""
    for key_type in _HTTPS_KEY_TYPES:
        token = credential_vault.get_plain_token(platform, key_type=key_type)
        if token:
            return token
    return credential_vault.get_plain_token(platform)


def main() -> int:
    action = sys.argv[1] if len(sys.argv) > 1 else "get"
    if action not in ("get", "store", "erase"):
        return 0
    req = {}
    for line in sys.stdin:
        line = line.strip()
        if not line:
            break
        if "=" in line:
            k, v = line.split("=", 1)
            req[k] = v
    if action != "get":
        return 0
    platform = _platform(req.get("host", ""))
    if not platform:
        return 0
    if _channel(req) == "ssh":
        # 私钥无法经 credential 协议传递，SSH 交回 ssh-agent/IdentityFile；此处只拒绝误发 PAT。
        return 0
    token = _token_for(platform)
    if not token:
        return 0
    username = "x-access-token" if platform == "github" else "oauth2"
    sys.stdout.write(f"username={username}\npassword={token}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
