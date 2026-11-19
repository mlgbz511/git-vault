# core/network_router.py
# Antigravity Git-Vault - Platform Network Router & Accelerator
import os
import json
import time
import socket
from typing import Dict, List, Any, Optional

VAULT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROUTER_CONFIG_FILE = os.path.join(VAULT_ROOT, "config", "network_routes.json")

DEFAULT_ROUTES = {
    "routes": {
        "github": {
            "mode": "direct",
            "proxy_url": "http://127.0.0.1:7890",
            "hosts_ip": "20.205.243.166"
        },
        "gitee": {
            "mode": "direct",
            "locked": True,
            "description": "境内直连通道 (强制锁定，防止境外代理降速或风控)"
        },
        "gitlab": {
            "mode": "direct",
            "proxy_url": "http://127.0.0.1:7890"
        }
    }
}

def load_network_routes() -> Dict[str, Any]:
    """Load platform network routing policies."""
    if not os.path.exists(ROUTER_CONFIG_FILE):
        save_network_routes(DEFAULT_ROUTES)
        return DEFAULT_ROUTES
    try:
        with open(ROUTER_CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            # Guarantee Gitee is locked direct
            if "routes" in data and "gitee" in data["routes"]:
                data["routes"]["gitee"]["mode"] = "direct"
                data["routes"]["gitee"]["locked"] = True
            return data
    except Exception:
        return DEFAULT_ROUTES

def save_network_routes(data: Dict[str, Any]) -> bool:
    """Save platform network routing policies."""
    try:
        # Enforce Gitee direct rule
        if "routes" in data and "gitee" in data["routes"]:
            data["routes"]["gitee"]["mode"] = "direct"
            data["routes"]["gitee"]["locked"] = True

        os.makedirs(os.path.dirname(ROUTER_CONFIG_FILE), exist_ok=True)
        with open(ROUTER_CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False

def update_platform_route(platform: str, mode: str, proxy_url: str = "", hosts_ip: str = "") -> Dict[str, Any]:
    """Update route policy for a given platform."""
    platform = platform.lower().strip()
    mode = mode.lower().strip()

    if platform == "gitee":
        if mode != "direct":
            return {
                "success": False,
                "error": "[ROUTER][LOCKED] Gitee 强制锁定境内直连通道，禁止配置代理或 Hosts 绕行！"
            }

    data = load_network_routes()
    routes = data.setdefault("routes", {})
    if platform not in routes:
        routes[platform] = {}

    routes[platform]["mode"] = mode
    if proxy_url:
        routes[platform]["proxy_url"] = proxy_url.strip()
    if hosts_ip:
        routes[platform]["hosts_ip"] = hosts_ip.strip()

    if platform == "gitee":
        routes[platform]["locked"] = True
        routes[platform]["mode"] = "direct"

    success = save_network_routes(data)
    return {
        "success": success,
        "platform": platform,
        "mode": routes[platform]["mode"],
        "route": routes[platform]
    }

def get_git_extra_args(target_url: str) -> List[str]:
    """
    Get git config CLI flags to inject into git commands based on target platform routing.
    Injects command-scoped http.proxy flags so child git processes route correctly
    without URL userinfo prefix mismatch issues in libcurl.
    """
    routes = load_network_routes().get("routes", {})
    args = []

    if "github.com" in target_url:
        gh_route = routes.get("github", {})
        mode = gh_route.get("mode", "direct")
        if mode == "proxy":
            proxy_url = gh_route.get("proxy_url", "http://127.0.0.1:11455")
            args.extend(["-c", f"http.proxy={proxy_url}"])
        elif mode == "hosts":
            hosts_ip = gh_route.get("hosts_ip", "20.205.243.166").strip()
            if hosts_ip:
                args.extend(["-c", f"http.curloptResolve=github.com:443:{hosts_ip}", "-c", "http.proxy="])
                if target_url.startswith("git@") or target_url.startswith("ssh://"):
                    args.extend(["-c", f"core.sshCommand=ssh -o HostName={hosts_ip}"])
        elif mode == "direct":
            args.extend(["-c", "http.proxy="])
    elif "gitee.com" in target_url:
        # Enforce direct by clearing proxy for gitee
        args.extend(["-c", "http.proxy="])
    elif "gitlab.com" in target_url:
        gl_route = routes.get("gitlab", {})
        mode = gl_route.get("mode", "direct")
        if mode == "proxy":
            proxy_url = gl_route.get("proxy_url", "http://127.0.0.1:11455")
            args.extend(["-c", f"http.proxy={proxy_url}"])
        elif mode == "direct":
            args.extend(["-c", "http.proxy="])

    return args

def probe_platform_latency(platform: str, timeout: float = 3.0) -> Dict[str, Any]:
    """Test TCP latency to a platform's HTTPS endpoint."""
    target_hosts = {
        "github": ("github.com", 443),
        "gitee": ("gitee.com", 443),
        "gitlab": ("gitlab.com", 443),
        "cloudflare": ("1.1.1.1", 443)
    }

    host, port = target_hosts.get(platform.lower().strip(), (f"{platform}.com", 443))

    start = time.perf_counter()
    try:
        # Resolve IP
        ip = socket.gethostbyname(host)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.close()
        elapsed_ms = round((time.perf_counter() - start) * 1000, 1)
        return {
            "platform": platform,
            "host": host,
            "ip": ip,
            "status": "ok",
            "latency_ms": elapsed_ms,
            "message": f"[OK] 连接成功 ({elapsed_ms}ms)"
        }
    except socket.timeout:
        return {
            "platform": platform,
            "host": host,
            "ip": None,
            "status": "timeout",
            "latency_ms": None,
            "message": f"[FAIL] 连接超时 ({timeout}s)"
        }
    except Exception as e:
        return {
            "platform": platform,
            "host": host,
            "ip": None,
            "status": "error",
            "latency_ms": None,
            "message": f"[ERROR] {str(e)}"
        }

def probe_all_routes() -> Dict[str, Any]:
    """Probe network latency for all managed platforms."""
    return {
        "github": probe_platform_latency("github"),
        "gitee": probe_platform_latency("gitee"),
        "gitlab": probe_platform_latency("gitlab")
    }
