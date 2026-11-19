# server.py

# Antigravity Git-Vault - Local HTTP Backend Server & MCP Gateway

import os

import sys

import json

import uuid

import queue

import time

import mimetypes

import ipaddress

from urllib.parse import urlparse, parse_qs

from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler



# Add root directory to sys.path

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

sys.path.insert(0, BASE_DIR)



# Guard against None std streams in Windows detached / GUI / WindowStyle Hidden mode

if sys.stdout is None:

    try:

        sys.stdout = open(os.devnull, 'w', encoding='utf-8')

    except Exception:

        pass

if sys.stderr is None:

    try:

        sys.stderr = open(os.devnull, 'w', encoding='utf-8')

    except Exception:

        pass



from core import (
    redaction,
    git_engine,
    credential_vault,
    credential_types,
    compliance_guard,
    secret_proxy,
    network_router,
    mcp_server,
    gitignore_manager,
    star_vault_engine,
    agent_installer
)



PORT = 8765

WEB_DIR = os.path.join(BASE_DIR, "web")



# Active SSE Sessions for MCP

sse_sessions = {}



def is_trusted_host(host_header: str) -> bool:
    """Validate that the Host header is a valid local loopback address (DNS rebinding defense)."""
    if not host_header:
        return False
    # Reject whitespace, tabs, and control characters (RFC 7230 §5.4 smuggling defense)
    if any(c.isspace() for c in host_header) or any(ord(c) < 32 or ord(c) == 127 for c in host_header):
        return False
    host_header = host_header.strip()
    if not host_header:
        return False

    # Check IPv6 bracketed notation: [::1] or [::1]:8765
    if host_header.startswith("["):
        end_idx = host_header.find("]")
        if end_idx == -1:
            return False
        hostname = host_header[1:end_idx].strip()
        port_part = host_header[end_idx + 1:]
        if port_part:
            if not port_part.startswith(":"):
                return False
            port_str = port_part[1:].strip()
            if not port_str.isdigit():
                return False
            port = int(port_str)
            if not (1 <= port <= 65535):
                return False
    else:
        parts = host_header.split(":")
        if len(parts) > 2:
            # Handle unbracketed IPv6 loopback addresses like ::1
            try:
                ip = ipaddress.ip_address(host_header)
                return ip.is_loopback
            except ValueError:
                return False
        elif len(parts) == 2:
            hostname = parts[0].strip()
            port_str = parts[1].strip()
            if not port_str.isdigit():
                return False
            port = int(port_str)
            if not (1 <= port <= 65535):
                return False
        else:
            hostname = parts[0].strip()

    hostname = hostname.lower().rstrip(".")
    if hostname in ("localhost", "127.0.0.1", "::1"):
        return True
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_loopback:
            return True
    except ValueError:
        pass
    return False


def is_trusted_origin(origin: str) -> bool:
    """Validate that the Origin header is a trusted local loopback origin."""
    if not origin:
        return False
    # Reject internal whitespace, tabs, control characters, commas
    if any(c.isspace() for c in origin) or any(ord(c) < 32 or ord(c) == 127 for c in origin) or "," in origin:
        return False
    origin = origin.strip()
    if origin == "null":
        return False
    try:
        parsed = urlparse(origin)
        scheme = (parsed.scheme or "").lower()
        if scheme not in ("http", "https"):
            return False

        # Origin MUST NOT have user credentials (RFC 6454 §4)
        if parsed.username is not None or parsed.password is not None:
            return False

        # Origin MUST NOT have a path (other than empty or root), query, or fragment (RFC 6454 §6.2)
        if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
            return False

        # Validate port if specified
        try:
            port = parsed.port
            if port is not None and not (1 <= port <= 65535):
                return False
        except ValueError:
            return False

        hostname = (parsed.hostname or "").lower().rstrip(".")
        if not hostname:
            return False
        if hostname in ("localhost", "127.0.0.1", "::1"):
            return True
        try:
            ip = ipaddress.ip_address(hostname)
            if ip.is_loopback:
                return True
        except ValueError:
            pass
        return False
    except Exception:
        return False


class GitVaultHandler(BaseHTTPRequestHandler):

    def handle_one_request(self):
        try:
            super().handle_one_request()
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            self.close_connection = True

    def parse_request(self):
        """Pre-dispatch validation for Host (DNS rebinding) and Origin (CSRF)."""
        if not super().parse_request():
            return False

        def _drain_body():
            try:
                cl_header = self.headers.get("Content-Length")
                if cl_header:
                    cl = int(cl_header)
                    if 0 < cl <= 1048576:
                        self.rfile.read(cl)
            except Exception:
                pass

        # 1. Host header validation (DNS Rebinding defense)
        host_headers = self.headers.get_all("Host") or []
        if len(host_headers) > 1:
            _drain_body()
            self.send_response(400)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b'{"success": false, "error": "Bad Request: Multiple Host headers"}')
            self.wfile.flush()
            self.close_connection = True
            return False

        host = host_headers[0] if host_headers else None
        if not host:
            if self.request_version == "HTTP/1.1":
                _drain_body()
                self.send_response(400)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b'{"success": false, "error": "Bad Request: Missing Host header in HTTP/1.1"}')
                self.wfile.flush()
                self.close_connection = True
                return False
        else:
            if not is_trusted_host(host):
                _drain_body()
                self.send_response(403)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b'{"success": false, "error": "Forbidden: untrusted Host header"}')
                self.wfile.flush()
                self.close_connection = True
                return False

        # 2. Origin validation for state-modifying requests (CSRF defense)
        origin_headers = self.headers.get_all("Origin") or []
        if len(origin_headers) > 1:
            if self.command in ("POST", "DELETE", "PUT", "PATCH", "OPTIONS"):
                _drain_body()
                self.send_response(403)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b'{"success": false, "error": "Forbidden: multiple Origin headers"}')
                self.wfile.flush()
                self.close_connection = True
                return False

        origin = origin_headers[0] if origin_headers else None
        if origin and not is_trusted_origin(origin):
            if self.command in ("POST", "DELETE", "PUT", "PATCH", "OPTIONS"):
                _drain_body()
                self.send_response(403)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(b'{"success": false, "error": "Forbidden: untrusted Origin"}')
                self.wfile.flush()
                self.close_connection = True
                return False

        return True

    def log_message(self, format, *args):

        try:

            if sys.stderr:

                sys.stderr.write(redaction.redact_text(f"[GitVault] {self.address_string()} - {format % args}") + "\n")

        except Exception:

            pass

    def _apply_cors_headers(self):
        """Conditionally attach CORS headers only for trusted loopback origins."""
        origin_headers = self.headers.get_all("Origin") or []
        if len(origin_headers) == 1:
            origin = origin_headers[0]
            if is_trusted_origin(origin):
                self.send_header("Access-Control-Allow-Origin", origin)
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS, DELETE, HEAD")
                self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
                self.send_header("Vary", "Origin")

    def send_json(self, data, status=200):

        body = json.dumps(redaction.redact(data), ensure_ascii=False).encode("utf-8")

        self.send_response(status)

        self.send_header("Content-Type", "application/json; charset=utf-8")

        self.send_header("Content-Length", str(len(body)))

        self._apply_cors_headers()

        self.end_headers()

        self.wfile.write(body)

    def do_OPTIONS(self):
        origin_headers = self.headers.get_all("Origin") or []
        if len(origin_headers) > 1:
            self.send_response(403)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b'{"success": false, "error": "Forbidden: multiple Origin headers"}')
            self.close_connection = True
            return

        origin = origin_headers[0] if origin_headers else None
        if origin and not is_trusted_origin(origin):
            self.send_response(403)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b'{"success": false, "error": "Forbidden: untrusted Origin"}')
            self.close_connection = True
            return

        self.send_response(204)
        self._apply_cors_headers()
        self.end_headers()



    def do_HEAD(self):

        self.do_GET()



    def read_json_body(self):

        try:

            content_length = int(self.headers.get("Content-Length", 0))

            if content_length > 0:

                raw = self.rfile.read(content_length).decode("utf-8")

                return json.loads(raw)

        except Exception:

            pass

        return {}



    def handle_sse(self):

        """Handle Server-Sent Events (SSE) connection for MCP client."""

        session_id = str(uuid.uuid4())

        msg_queue = queue.Queue()

        sse_sessions[session_id] = msg_queue



        self.send_response(200)

        self.send_header("Content-Type", "text/event-stream; charset=utf-8")

        self.send_header("Cache-Control", "no-cache")

        self.send_header("Connection", "keep-alive")

        self._apply_cors_headers()

        self.end_headers()



        # Send initial endpoint event pointing to the message receipt endpoint

        endpoint_data = f"/mcp/message?session_id={session_id}"

        init_evt = f"event: endpoint\ndata: {endpoint_data}\n\n"

        self.wfile.write(init_evt.encode("utf-8"))

        self.wfile.flush()



        try:

            while True:

                try:

                    # Wait for message with 15s keepalive ping

                    msg = msg_queue.get(timeout=15)

                    payload = f"event: message\ndata: {json.dumps(redaction.redact(msg), ensure_ascii=False)}\n\n"

                    self.wfile.write(payload.encode("utf-8"))

                    self.wfile.flush()

                except queue.Empty:

                    # Keep-alive heartbeat comment

                    ping_payload = ": ping\n\n"

                    self.wfile.write(ping_payload.encode("utf-8"))

                    self.wfile.flush()

        except (BrokenPipeError, ConnectionResetError):

            pass

        finally:

            sse_sessions.pop(session_id, None)



    def do_GET(self):

        parsed = urlparse(self.path)

        path = parsed.path

        qs = parse_qs(parsed.query)



        # MCP SSE Stream

        if path == "/mcp/sse":

            self.handle_sse()

            return



        # MCP Audit Log

        elif path == "/api/mcp/audit":

            limit = int(qs.get("limit", [50])[0])

            logs = mcp_server.get_audit_logs(limit=limit)

            self.send_json({"logs": logs})

            return



        # Agent Integration Status

        elif path == "/api/agent/status":

            status = agent_installer.check_antigravity_status()

            self.send_json(status)

            return



        # DSH Plugin Manifest & Command

        elif path == "/api/agent/dsh-config":

            manifest = agent_installer.get_dsh_manifest()

            dsh_dir = os.path.join(BASE_DIR, "extensions", "dsh")

            self.send_json({

                "manifest": manifest,

                "install_command": f'dsh plugin add "{dsh_dir}"',

                "plugin_path": dsh_dir

            })

            return



        # Panic Button (Read-Only Lock)

        elif path == "/api/panic-button":

            locked = compliance_guard.is_panic_button_active()

            self.send_json({

                "locked": locked,

                "status_text": "[READ-ONLY 只读锁定]" if locked else "[READ-WRITE 正常写入]"

            })

            return



        # Status & Identity

        elif path == "/api/git-profiles":
            data = git_engine.load_git_profiles()
            curr = git_engine.get_identity()
            c_name = (curr.get("name") or "").strip()
            c_email = (curr.get("email") or "").strip()
            matched_id = None
            for p in data.get("profiles", []):
                if p.get("name", "").strip() == c_name and p.get("email", "").strip() == c_email:
                    matched_id = p.get("id")
                    break
            self.send_json({
                "profiles": data.get("profiles", []),
                "active_id": matched_id or data.get("active_id", "github"),
                "default_id": data.get("default_id", "github"),
                "current": curr
            })
            return

        elif path == "/api/status":

            identity = git_engine.get_identity()

            self.send_json({

                "identity": identity,

                "panic_button_locked": compliance_guard.is_panic_button_active()

            })

            return



        # Platforms Health Check (Supports ?force=true to bypass 60s TTL cache)

        elif path == "/api/health-check":

            force = qs.get("force", ["false"])[0].lower() == "true"

            platforms = git_engine.check_platforms_health(force=force)

            self.send_json({"platforms": platforms, "cached": platforms.get("_cached", False)})

            return



        # Repositories List (High-Performance Fast Path with In-Memory TTL Cache & ThreadPool)

        elif path == "/api/repos":

            workspace_root = qs.get("workspace_root", ["<vault-root>"])[0]

            only_mine = qs.get("only_mine", ["true"])[0].lower() == "true"

            depth = int(qs.get("depth", [3])[0])

            force_refresh = qs.get("refresh", ["false"])[0].lower() == "true"

            force_scan = qs.get("force_scan", ["false"])[0].lower() == "true"

            detailed = git_engine.get_managed_repositories_fast(

                workspace_root=workspace_root,

                depth=depth,

                only_mine=only_mine,

                force_refresh=force_refresh,

                force_scan=force_scan

            )

            self.send_json(detailed)

            return



        # Live Scan SSE Stream (Real-Time Process Visualization)

        elif path == "/api/repos/scan-stream":

            scan_path = qs.get("scan_path", ["<vault-root>"])[0]

            depth = int(qs.get("depth", [3])[0])

            only_mine = qs.get("only_mine", ["true"])[0].lower() == "true"



            self.send_response(200)

            self.send_header("Content-Type", "text/event-stream; charset=utf-8")

            self.send_header("Cache-Control", "no-cache")

            self.send_header("Connection", "keep-alive")

            self._apply_cors_headers()

            self.end_headers()



            def stream_callback(event):

                evt_line = f"data: {json.dumps(redaction.redact(event), ensure_ascii=False)}\n\n"

                try:

                    self.wfile.write(evt_line.encode("utf-8"))

                    self.wfile.flush()

                except Exception:

                    pass



            result = git_engine.scan_repositories_detailed(

                workspace_root=scan_path,

                depth=depth,

                only_mine=only_mine,

                callback=stream_callback

            )

            # Omit redundant massive trace list from complete event because events were already streamed in real time

            lean_result = {

                "repos": result.get("repos", []),

                "stats": result.get("stats", {}),

                "filter_only_mine": result.get("filter_only_mine", only_mine),

                "workspace_root": result.get("workspace_root", scan_path)

            }

            complete_evt = f"data: {json.dumps(redaction.redact({'type': 'complete', 'result': lean_result}), ensure_ascii=False)}\n\n"

            try:

                self.wfile.write(complete_evt.encode("utf-8"))

                self.wfile.flush()

            except Exception:

                pass

            self.close_connection = True

            return



        # Live Sync SSE Stream (Real-Time Push Trace & Single-Line Progress)

        elif path == "/api/sync-stream":

            repo_path = qs.get("repo_path", [""])[0]

            branch = qs.get("branch", [""])[0] or None

            target_platform = qs.get("target_platform", [""])[0] or None

            force = qs.get("force", ["0"])[0].lower() in ("1", "true", "yes")



            if not repo_path or not os.path.exists(repo_path):

                self.send_json({"success": False, "error": f"Invalid repo path: {repo_path}"}, 400)

                return



            self.send_response(200)

            self.send_header("Content-Type", "text/event-stream; charset=utf-8")

            self.send_header("Cache-Control", "no-cache")

            self.send_header("Connection", "keep-alive")

            self._apply_cors_headers()

            self.end_headers()



            try:

                for event in git_engine.sync_repository_stream(repo_path, branch=branch, target_platform=target_platform, force=force):

                    evt_line = f"data: {json.dumps(redaction.redact(event), ensure_ascii=False)}\n\n"

                    try:

                        self.wfile.write(evt_line.encode("utf-8"))

                        self.wfile.flush()

                    except (BrokenPipeError, ConnectionResetError):

                        break

            except Exception as e:

                err_evt = f"data: {json.dumps({'type': 'error', 'percent': 100, 'message': str(e)}, ensure_ascii=False)}\n\n"

                try:

                    self.wfile.write(err_evt.encode("utf-8"))

                    self.wfile.flush()

                except Exception:

                    pass

            self.close_connection = True

            return



        # Repository Full Detail (Level-2 Workspace)

        elif path == "/api/repo/detail":

            repo_path = qs.get("path", [""])[0] or qs.get("repo_path", [""])[0]

            if not repo_path or not os.path.exists(repo_path):

                self.send_json({"success": False, "error": f"无效的仓库路径: {repo_path}"}, 400)

                return

            detail = git_engine.get_repository_full_detail(repo_path)

            self.send_json(detail)

            return



        # Repository Diff Inspector

        elif path == "/api/repo/diff":

            repo_path = qs.get("path", [""])[0]

            staged_only = qs.get("staged_only", ["false"])[0].lower() == "true"

            if not repo_path:

                self.send_json({"success": False, "error": "Repo path is required"}, 400)

                return

            diff_data = git_engine.get_repo_diff(repo_path, staged_only=staged_only)

            self.send_json(diff_data)

            return



        # Sync Audit Logs

        elif path == "/api/sync/audit-logs":

            limit = int(qs.get("limit", [50])[0])

            logs = git_engine.load_sync_audit_logs(limit=limit)

            self.send_json({"success": True, "logs": logs})

            return



        # Real-time Agent Model Self-Identification
        elif path == "/api/agent/detect":
            try:
                from core import agent_detector
                det = agent_detector.detect_active_agent_model()
            except Exception as e:
                det = {"success": False, "error": str(e), "signature": "GV_AGY_Gemini-3.8-Flash", "raw_name": "Gemini 3.8 Flash"}
            det["bot_email"] = "<bot-email>"
            self.send_json(det)
            return

        # Repository Commits

        elif path == "/api/repo/commits":

            repo_path = qs.get("path", [""])[0]

            count = int(qs.get("count", [30])[0])

            if not repo_path:

                self.send_json({"success": False, "error": "Repo path is required"}, 400)

                return

            commits_data = git_engine.get_repo_commits(repo_path, count=count)

            self.send_json(commits_data)

            return



        # Vault Git Tokens & Windows Credentials

        elif path == "/api/vault":

            tokens_data = credential_vault.get_tokens_masked()

            win_creds = credential_vault.list_windows_git_credentials()

            self.send_json({

                "tokens": tokens_data.get("tokens", {}),

                "accounts": tokens_data.get("accounts", []),

                "repo_account_bindings": tokens_data.get("repo_account_bindings", {}),

                "saved_accounts": tokens_data.get("saved_accounts", {}),

                "credentials": tokens_data.get("credentials", tokens_data.get("accounts", [])),

                "non_git_secrets": tokens_data.get("non_git_secrets", {}),

                "windows_credentials": win_creds

            })

            return



        # Multi-Account List & Bindings

        elif path == "/api/vault/accounts":

            platform = qs.get("platform", [None])[0]

            accounts = credential_vault.list_accounts_masked(platform=platform)

            bindings = credential_vault.get_repo_account_bindings()

            self.send_json({

                "accounts": accounts,

                "repo_account_bindings": bindings

            })

            return



        # Universal Secret Vault List (Filtered by Category)

        elif path == "/api/vault/secrets":

            category = qs.get("category", [None])[0]

            secrets_list = credential_vault.list_all_secrets_masked(category=category)

            self.send_json({"secrets": secrets_list})

            return



        # Non-Git Secrets Only (Legacy Dict Map)

        elif path == "/api/vault/non-git":

            masked = credential_vault.get_non_git_secrets_masked()

            self.send_json({"secrets": masked})

            return



        # Key Type Catalog (T5: 类型单一事实源，供面板类型列与筛选)
        elif path == "/api/vault/key-types":

            self.send_json({
                "key_types": [
                    {
                        "id": tid,
                        "label_zh": meta.get("label_zh", tid),
                        "storage_domain": meta.get("storage_domain", "client"),
                        "can_push": bool(meta.get("can_push", False))
                    }
                    for tid, meta in credential_types.KEY_TYPES.items()
                ]
            })

            return

        # SOPS Availability (T5: 前端按钮置灰 / install_hint)
        elif path == "/api/vault/sops/status":

            self.send_json(_sops_status())

            return

        # Network Routes

        elif path == "/api/network/routes":

            routes = network_router.load_network_routes()

            self.send_json(routes)

            return



        # Cloudflare Proxies (GET support)

        elif path == "/api/proxy/cloudflare/verify":

            res = secret_proxy.cloudflare_verify_token()

            self.send_json(res)

            return



        elif path == "/api/proxy/cloudflare/zones":

            res = secret_proxy.cloudflare_list_zones()

            self.send_json(res)

            return



        # Global .gitignore Presets & Status

        elif path == "/api/gitignore/status":

            status_data = gitignore_manager.get_global_gitignore_status()

            self.send_json(status_data)

            return

        # Star Vault API - Query Vault & Repositories
        elif path == "/api/stars/vault":
            list_name = qs.get("list_name", ["all"])[0]
            if list_name == "all" and "list" in qs:
                list_name = qs.get("list", ["all"])[0]
            search = qs.get("search", [""])[0]
            language = qs.get("language", ["all"])[0]
            if language == "all" and "lang" in qs:
                language = qs.get("lang", ["all"])[0]

            vault_data = star_vault_engine.load_starred_vault()
            filtered_repos = star_vault_engine.filter_vault_repos(
                vault_data,
                list_name=list_name,
                search=search,
                language=language
            )
            stats = star_vault_engine.get_vault_stats(vault_data)

            self.send_json({
                "success": True,
                "account": vault_data.get("account", "<owner>"),
                "banned_source_account": vault_data.get("banned_source_account", "<owner>"),
                "last_sync": vault_data.get("last_sync", ""),
                "lists": vault_data.get("lists", []),
                "repositories": filtered_repos,
                "total_matched": len(filtered_repos),
                "stats": stats
            })
            return

        # Star Vault API - Safe Paced Restore SSE Stream
        elif path == "/api/stars/restore-stream":
            dry_run_str = qs.get("dry_run", ["false"])[0].lower()
            dry_run = dry_run_str in ("true", "1", "yes")

            token = qs.get("token", [""])[0]
            if not token:
                token = credential_vault.get_plain_token("github")

            if not token and not dry_run:
                self.send_json({"success": False, "error": "未提供或未配置 GitHub Token (PAT)"}, 400)
                return

            recreate_lists_str = qs.get("recreate_lists", ["true"])[0].lower()
            recreate_lists = recreate_lists_str not in ("false", "0", "no")

            pacing_delay_str = qs.get("pacing_delay", [""])[0] or qs.get("pacing", ["1.2"])[0]
            try:
                pacing_delay = float(pacing_delay_str)
            except ValueError:
                pacing_delay = 1.2

            repos_param = qs.get("repos", [""])[0]
            target_repos = [r.strip() for r in repos_param.split(",") if r.strip()] if repos_param else None

            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self._apply_cors_headers()
            self.end_headers()

            try:
                for event in star_vault_engine.restore_to_account_stream(
                    token=token,
                    target_repo_names=target_repos,
                    recreate_lists=recreate_lists,
                    pacing_delay=pacing_delay,
                    dry_run=dry_run
                ):
                    line = f"data: {json.dumps(redaction.redact(event), ensure_ascii=False)}\n\n"
                    try:
                        self.wfile.write(line.encode("utf-8"))
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError):
                        break
            except Exception as e:
                err_evt = f"data: {json.dumps({'type': 'error', 'percent': 100, 'message': str(e)}, ensure_ascii=False)}\n\n"
                try:
                    self.wfile.write(err_evt.encode("utf-8"))
                    self.wfile.flush()
                except Exception:
                    pass
            self.close_connection = True
            return

        # Star Vault API - Download STARS_INDEX.md
        elif path == "/api/stars/export-markdown":
            md_content = redaction.redact_text(star_vault_engine.render_stars_markdown())
            content_bytes = md_content.encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", "text/markdown; charset=utf-8")
            self.send_header("Content-Disposition", 'attachment; filename="STARS_INDEX.md"')
            self.send_header("Content-Length", str(len(content_bytes)))
            self._apply_cors_headers()
            self.end_headers()

            self.wfile.write(content_bytes)
            return




        # Serve Static Web Files

        file_path = path.lstrip("/")

        if not file_path or file_path == "":

            file_path = "index.html"



        target_file = os.path.normpath(os.path.join(WEB_DIR, file_path))

        if os.path.commonpath([target_file, WEB_DIR]) == WEB_DIR and os.path.isfile(target_file):

            mime_type, _ = mimetypes.guess_type(target_file)

            mime_type = mime_type or "application/octet-stream"

            try:

                with open(target_file, "rb") as f:

                    content = f.read()

                self.send_response(200)

                self.send_header("Content-Type", f"{mime_type}; charset=utf-8")

                self.send_header("Content-Length", str(len(content)))

                self.end_headers()

                self.wfile.write(content)

                return

            except Exception as e:

                self.send_error(500, f"Read error: {str(e)}")

                return

        

        self.send_error(404, "Not Found")



    def do_POST(self):

        parsed = urlparse(self.path)

        path = parsed.path

        qs = parse_qs(parsed.query)

        body = self.read_json_body()



        # MCP JSON-RPC Message Handling

        if path == "/mcp/message":

            session_id = qs.get("session_id", [""])[0]

            resp = mcp_server.handle_json_rpc(

                body,

                agent_id=f"agent-sse-{session_id[:8]}" if session_id else "agent-http",

                client_ip=self.address_string()

            )

            # If session is active, also push to SSE stream

            if session_id and session_id in sse_sessions:

                sse_sessions[session_id].put(resp)

            self.send_json(resp)

            return



        # Panic Button Toggle

        elif path == "/api/panic-button":

            locked = body.get("locked", True)

            success = compliance_guard.set_panic_button(locked)

            self.send_json({

                "success": success,

                "locked": compliance_guard.is_panic_button_active()

            })

            return



        # Identity Config

        elif path == "/api/git-profiles/apply":
            profile_id = body.get("id", "github")
            scope = body.get("scope", "global")
            repo_path = body.get("repo_path", None)
            res = git_engine.set_active_git_profile(profile_id, scope=scope, cwd=repo_path)
            self.send_json(res)
            return

        elif path == "/api/git-profiles/save":
            label = body.get("label", "")
            name = body.get("name", "")
            email = body.get("email", "")
            profile_id = body.get("id", None)
            if not name or not email:
                self.send_json({"error": "name and email are required"}, 400)
                return
            res = git_engine.add_or_update_git_profile(label, name, email, profile_id=profile_id)
            self.send_json(res)
            return

        elif path == "/api/git-profiles/delete":
            profile_id = body.get("id", "")
            res = git_engine.delete_git_profile(profile_id)
            self.send_json(res)
            return

        elif path == "/api/git-profiles/set-default":
            profile_id = body.get("id", "github")
            res = git_engine.set_default_git_profile(profile_id)
            self.send_json(res)
            return

        elif path == "/api/identity":

            name = body.get("name", "")

            email = body.get("email", "")

            scope = body.get("scope", "global")

            repo_path = body.get("repo_path", None)

            res = git_engine.set_identity(name, email, scope=scope, cwd=repo_path)

            self.send_json(res)

            return



        # Repo Commit Builder

        elif path == "/api/repo/commit":

            repo_path = body.get("repo_path", "")

            message = body.get("message", "")

            stage_all = body.get("stage_all", True)

            agent_name = body.get("agent_name")
            agent_email = body.get("agent_email", "<bot-email>")
            author_mode = body.get("author_mode", "co_author")

            res = git_engine.create_commit(
                repo_path=repo_path,
                message=message,
                stage_all=stage_all,
                agent_name=agent_name,
                agent_email=agent_email,
                author_mode=author_mode
            )

            self.send_json(res)

            return



        # System Launchers: Explorer, VS Code, Terminal

        elif path == "/api/system/open-explorer":

            p = body.get("path", "")

            res = git_engine.open_in_explorer(p)

            self.send_json(res)

            return



        elif path == "/api/system/open-vscode":

            p = body.get("path", "")

            res = git_engine.open_in_vscode(p)

            self.send_json(res)

            return



        elif path == "/api/system/open-terminal":

            p = body.get("path", "")

            res = git_engine.open_in_terminal(p)

            self.send_json(res)

            return



        elif path == "/api/system/locate-folder":

            folder_name = body.get("folder_name", "")

            hints = body.get("hints", [])

            matches = git_engine.locate_folder_path(folder_name, hint_paths=hints)

            if matches:

                self.send_json({"success": True, "path": matches[0], "candidates": matches})

            else:

                self.send_json({"success": False, "error": f"未能在已知工作区中自动定位到名为 [{folder_name}] 且包含 .git 的仓库路径，请手动补全。"})

            return



        # Migrate Repo from <owner> to <owner>

        elif path == "/api/repo/migrate-owner":

            repo_path = body.get("repo_path") or body.get("path") or ""

            new_user = body.get("new_user", "<owner>")

            if not repo_path or not os.path.exists(repo_path):

                self.send_json({"success": False, "error": "Invalid repo path"}, 400)

                return

            res = git_engine.migrate_repo_to_511(repo_path, new_user=new_user)

            self.send_json(res)

            return



        # Batch Migrate All Repos from <owner> to <owner>

        elif path == "/api/repos/migrate-all-to-511":

            new_user = body.get("new_user", "<owner>")

            res = git_engine.migrate_all_repos_to_511(new_user=new_user)

            self.send_json(res)

            return



        # Create GitHub Remote Repo and Push Initial Branch

        elif path == "/api/repo/create-remote-github":

            repo_path = body.get("repo_path") or body.get("path") or ""

            repo_name = body.get("repo_name", "")

            is_private = body.get("private", True)

            token = body.get("token")

            save_token = body.get("save_token", False)

            if token and save_token:

                try:

                    credential_vault.add_or_update_account(

                        platform="github",

                        username="<owner>",

                        token=token,

                        alias="GitHub <owner> 个人 Token",

                        is_default=True

                    )

                except Exception:

                    pass

            res = git_engine.create_github_remote_repo(repo_path, repo_name=repo_name, is_private=is_private, token=token, push_initial=bool(body.get("push_initial", True)))

            self.send_json(res)

            return



        # Batch Create GitHub Remote Repos (Disabled for anti-abuse protection)

        elif path == "/api/repos/batch-create-remote-github":

            self.send_json({
                "success": False,
                "error": "批量建库已被安全策略禁用，防止触发 GitHub 自动化反作弊风控与二次速率限制。请在仓库列表中使用单库【GitHub 建库】功能。"
            }, 403)

            return



        # Triple Remotes Config

        elif path == "/api/configure-triple":

            repo_path = body.get("repo_path", "")

            gh_url = body.get("github_url", "")

            ge_url = body.get("gitee_url", "")

            gl_url = body.get("gitlab_url", "")

            if not repo_path or not os.path.exists(repo_path):

                self.send_json({"success": False, "error": "Invalid repo path"}, 400)

                return

            res = git_engine.configure_triple_remotes(repo_path, gh_url, ge_url, gl_url)

            self.send_json(res)

            return



        # Synchronize Repo (Push)

        elif path == "/api/sync":

            repo_path = body.get("repo_path", "")

            branch = body.get("branch", "")

            target_platform = body.get("target_platform", None)

            force = bool(body.get("force", False))

            if not repo_path or not os.path.exists(repo_path):

                self.send_json({"success": False, "error": "Invalid repo path"}, 400)

                return

            res = git_engine.sync_repository(repo_path, branch=branch, target_platform=target_platform, force=force)

            self.send_json(res)

            return



        # Disaster Backup

        elif path == "/api/backup":

            repo_paths = body.get("repo_paths", [])

            if not repo_paths:

                all_repos = git_engine.scan_repositories("<vault-root>")

                repo_paths = [r["path"] for r in all_repos]

            res = git_engine.trigger_backup(repo_paths)

            self.send_json(res)

            return



        # Vault Git Token (Legacy Single-Token Compatible)

        elif path == "/api/vault/token":

            platform = body.get("platform", "")

            token = body.get("token", "")

            username = body.get("username", "")

            expires_at = body.get("expires_at", "never")

            clear_token = body.get("clear_token", False)

            key_type, scope, input_err = _credential_input(body)

            if input_err:

                _audit_vault(self, "vault.token.update", {"platform": platform},
                             {"success": False, "error": input_err})

                self.send_json({"success": False, "error": input_err}, 400)

                return

            res = credential_vault.update_token(
                platform, token, username, expires_at,
                clear_token=clear_token, key_type=key_type, scope=scope
            )

            _audit_vault(self, "vault.token.update", {"platform": platform, "key_type": key_type}, res)

            self.send_json(res)

            return



        # Multi-Account Management Endpoints

        elif path == "/api/vault/account/save":

            platform = body.get("platform", "")

            token = body.get("token")

            username = body.get("username", "")

            alias = body.get("alias", "")

            expires_at = body.get("expires_at", "never")

            is_default = body.get("is_default", False)

            account_id = body.get("account_id")

            existing_acc = None

            if account_id:

                try:

                    existing_acc = next(
                        (a for a in credential_vault.load_raw_vault().get("accounts", [])
                         if a.get("id") == account_id), None
                    )

                except Exception:

                    existing_acc = None

            key_type, scope, input_err = _credential_input(body)

            if input_err:

                _audit_vault(self, "vault.account.save", {"platform": platform},
                             {"success": False, "error": input_err})

                self.send_json({"success": False, "error": input_err}, 400)

                return

            if key_type is None:

                key_type = credential_types.parse_key_type((existing_acc or {}).get("key_type")) or "pat_classic"

            if scope is None and existing_acc:

                scope = existing_acc.get("scope")

            res = credential_vault.add_or_update_account(

                platform=platform,

                token=token,

                username=username,

                alias=alias,

                expires_at=expires_at,

                is_default=is_default,

                account_id=account_id,

                key_type=key_type,

                scope=scope

            )

            _audit_vault(self, "vault.account.save", {"platform": platform, "key_type": key_type}, res)

            self.send_json(res)

            return



        elif path == "/api/vault/account/set-default":

            account_id = body.get("account_id", "")

            if not account_id:

                self.send_json({"success": False, "error": "Account ID is required"}, 400)

                return

            res = credential_vault.set_default_account(account_id)

            _audit_vault(self, "vault.account.set_default", {"account_id": account_id}, res)

            self.send_json(res)

            return



        elif path == "/api/vault/account/delete":

            account_id = body.get("account_id", "")

            if not account_id:

                self.send_json({"success": False, "error": "Account ID is required"}, 400)

                return

            res = credential_vault.delete_account(account_id)

            _audit_vault(self, "vault.account.delete", {"account_id": account_id}, res)

            self.send_json(res)

            return



        elif path == "/api/vault/account/inspect":

            account_id = body.get("account_id", "")

            if not account_id:

                self.send_json({"valid": False, "error": "Account ID is required"}, 400)

                return

            raw = credential_vault.load_raw_vault()

            acc = next((a for a in raw.get("accounts", []) if a.get("id") == account_id), None)

            if not acc:

                self.send_json({"valid": False, "error": f"未找到账号凭据: {account_id}"}, 404)

                return

            cipher = acc.get("encrypted_token", "") or acc.get("token", "")

            plain_token = credential_vault.dpapi_decrypt(cipher) if cipher else ""

            if not plain_token:

                self.send_json({"valid": False, "error": "该账号未配置有效的 Token 密文"})

                return

            res = credential_vault.inspect_token_online(acc.get("platform", ""), plain_token)

            self.send_json(res)

            return



        elif path == "/api/vault/repo-binding":

            repo_path = body.get("repo_path", "")

            platform = body.get("platform", "")

            account_id = body.get("account_id", "")

            if not repo_path or not platform:

                self.send_json({"success": False, "error": "repo_path and platform are required"}, 400)

                return

            res = credential_vault.bind_repo_account(repo_path, platform, account_id)

            _audit_vault(self, "vault.repo.binding",
                         {"repo_path": repo_path, "platform": platform, "account_id": account_id}, res)

            self.send_json(res)

            return



        # Universal Secret Vault Save & Delete

        elif path == "/api/vault/secret/save":

            service = body.get("service", "")

            secret = body.get("secret", "")

            env_var = body.get("env_var", "")

            category = body.get("category", "custom")

            alias = body.get("alias", "")

            description = body.get("description", "")

            metadata = body.get("metadata", {})

            res = credential_vault.save_generic_secret(

                service=service,

                secret=secret,

                env_var=env_var,

                category=category,

                alias=alias,

                description=description,

                metadata=metadata

            )

            _audit_vault(self, "vault.secret.save", {"service": service, "category": category}, res)

            self.send_json(res)

            return



        elif path == "/api/vault/secret/delete":

            service = body.get("service", "")

            if not service:

                self.send_json({"success": False, "error": "Service is required"}, 400)

                return

            res = credential_vault.delete_non_git_secret(service)

            _audit_vault(self, "vault.secret.delete", {"service": service}, res)

            self.send_json(res)

            return



        # Cross-Machine SOPS Encrypted Layer (T5: 路由仅接入，逻辑在 core/sops_bridge.py)
        elif path in ("/api/vault/sops/export", "/api/vault/sops/import", "/api/vault/sops/diff"):

            action = path.rsplit("/", 1)[-1]

            bridge, bridge_err = _sops_bridge()

            if bridge is None:

                self.send_json({"success": False, "error": bridge_err}, 503)

                return

            target_path, path_err = _sops_path(body.get("path"))

            if path_err:

                self.send_json({"success": False, "error": path_err}, 400)

                return

            sops_state = _sops_status()

            if not sops_state.get("available"):

                self.send_json({"success": False, "error": sops_state.get("install_hint", "sops/age 不可用")}, 503)

                return

            if action in ("export", "import") and compliance_guard.is_panic_button_active():

                self.send_json({"success": False, "error": "Panic Button 只读锁已启用"}, 423)

                return

            func_name = {"export": "export_to_file", "import": "import_from_file", "diff": "diff_with_vault"}[action]

            try:

                fn = getattr(bridge, func_name)

                res = fn(target_path) if target_path else fn()

            except TypeError:

                res = {"success": False, "error": "sops_bridge." + func_name + " 签名不匹配"}

            _audit_vault(self, "vault.sops." + action, {"path": target_path or ""}, res)

            self.send_json(res)

            return



        # Repositories Scan, Manual-Add, Ignore, Unignore

        elif path == "/api/repos/scan":

            scan_path = body.get("scan_path", "<vault-root>")

            depth = int(body.get("depth", 3))

            only_mine = bool(body.get("only_mine", True))

            detailed = git_engine.scan_repositories_detailed(scan_path, depth=depth, only_mine=only_mine)

            self.send_json(detailed)

            return



        elif path == "/api/repos/manual-add":

            repo_path = body.get("path", "")

            alias = body.get("alias", "")

            if not repo_path:

                self.send_json({"success": False, "error": "Repo path is required"}, 400)

                return

            res = git_engine.manual_add_repo(repo_path, alias)

            self.send_json(res)

            return



        elif path == "/api/repos/ignore":

            repo_path = body.get("path", "")

            if not repo_path:

                self.send_json({"success": False, "error": "Repo path is required"}, 400)

                return

            res = git_engine.ignore_repo(repo_path)

            self.send_json(res)

            return



        elif path == "/api/repos/unignore":

            repo_path = body.get("path", "")

            if not repo_path:

                self.send_json({"success": False, "error": "Repo path is required"}, 400)

                return

            res = git_engine.unignore_repo(repo_path)

            self.send_json(res)

            return



        elif path == "/api/repos/archive":

            repo_path = body.get("path", "")

            reason = body.get("reason", "")

            if not repo_path:

                self.send_json({"success": False, "error": "Repo path is required"}, 400)

                return

            res = git_engine.archive_repo(repo_path, reason=reason)

            self.send_json(res)

            return



        elif path == "/api/repos/unarchive":

            repo_path = body.get("path", "")

            if not repo_path:

                self.send_json({"success": False, "error": "Repo path is required"}, 400)

                return

            res = git_engine.unarchive_repo(repo_path)

            self.send_json(res)

            return



        # Vault Non-Git Secret (Legacy endpoint)

        elif path == "/api/vault/non-git":

            service = body.get("service", "")

            secret = body.get("secret", "")

            category = body.get("category", "custom")

            description = body.get("description", "")

            env_var = body.get("env_var", "")

            alias = body.get("alias", "")

            metadata = body.get("metadata", {})

            res = credential_vault.update_non_git_secret(

                service=service,

                secret=secret,

                category=category,

                description=description,

                metadata=metadata,

                env_var=env_var,

                alias=alias

            )

            self.send_json(res)

            return



        elif path == "/api/vault/delete-non-git":

            service = body.get("service", "")

            res = credential_vault.delete_non_git_secret(service)

            _audit_vault(self, "vault.delete_non_git", {"service": service}, res)

            self.send_json(res)

            return



        # Inspect Git Token Online

        elif path == "/api/vault/inspect-token":

            platform = body.get("platform", "")

            token = body.get("token", "")

            res = credential_vault.inspect_token_online(platform, token)

            self.send_json(res)

            return



        # Windows Credential Delete

        elif path == "/api/vault/delete-credential":

            target = body.get("target", "")

            if not target:

                self.send_json({"success": False, "error": "Target required"}, 400)

                return

            res = credential_vault.delete_windows_credential(target)

            _audit_vault(self, "vault.delete_credential", {"target": target}, res)

            self.send_json(res)

            return



        # Zero-Plaintext Secret Proxy Generic Request

        elif path == "/api/proxy/request":

            service = body.get("service", "")

            endpoint = body.get("endpoint", "")

            method = body.get("method", "GET")

            headers = body.get("headers")

            query_params = body.get("query_params")

            payload = body.get("payload")

            res = secret_proxy.execute_proxy_request(

                service=service,

                endpoint=endpoint,

                method=method,

                headers=headers,

                query_params=query_params,

                payload=payload

            )

            self.send_json(res)

            return



        # Cloudflare Dedicated Proxies

        elif path == "/api/proxy/cloudflare/verify":

            res = secret_proxy.cloudflare_verify_token()

            self.send_json(res)

            return



        elif path == "/api/proxy/cloudflare/zones":

            res = secret_proxy.cloudflare_list_zones()

            self.send_json(res)

            return



        elif path == "/api/proxy/cloudflare/purge-cache":

            zone_id = body.get("zone_id", "")

            purge_everything = body.get("purge_everything", True)

            files = body.get("files")

            res = secret_proxy.cloudflare_purge_cache(

                zone_id=zone_id,

                purge_everything=purge_everything,

                files=files

            )

            self.send_json(res)

            return



        # Network Routes Update

        elif path == "/api/network/routes":

            platform = body.get("platform", "")

            mode = body.get("mode", "direct")

            proxy_url = body.get("proxy_url", "")

            hosts_ip = body.get("hosts_ip", "")

            res = network_router.update_platform_route(

                platform=platform,

                mode=mode,

                proxy_url=proxy_url,

                hosts_ip=hosts_ip

            )

            self.send_json(res)

            return



        # Network Probe

        elif path == "/api/network/probe":

            res = network_router.probe_all_routes()

            self.send_json(res)

            return



        # Compliance Scan Endpoint

        elif path == "/api/compliance/scan":

            repo_path = body.get("repo_path", "")

            text = body.get("text", "")

            violations = []

            if text:

                violations.extend(compliance_guard.scan_text_for_secrets(text, "Text Input"))

            if repo_path and os.path.exists(repo_path):

                violations.extend(compliance_guard.check_file_sizes(repo_path))

                violations.extend(compliance_guard.scan_contraband_tools(repo_path))

            self.send_json({

                "passed": not any(v.get("severity") == "BLOCK" for v in violations),

                "count": len(violations),

                "violations": violations

            })

            return



        # Pre-Adoption Repository Security Audit & Report

        elif path == "/api/compliance/repo-audit":

            repo_path = body.get("repo_path") or body.get("path") or ""

            if not repo_path or not os.path.exists(repo_path):

                self.send_json({"success": False, "error": f"仓库路径无效或不存在: {repo_path}"}, 400)

                return

            res = compliance_guard.audit_repository_readiness(repo_path)

            self.send_json(res)

            return



        # Pre-Adoption Security Remediation (Append to .gitignore)

        elif path == "/api/compliance/remediate-gitignore":

            repo_path = body.get("repo_path") or body.get("path") or ""

            patterns = body.get("patterns", [])

            if not repo_path or not os.path.exists(repo_path):

                self.send_json({"success": False, "error": f"仓库路径无效或不存在: {repo_path}"}, 400)

                return

            res = compliance_guard.remediate_gitignore_rules(repo_path, patterns)

            self.send_json(res)

            return



        # Global .gitignore Presets Apply & Clear

        elif path == "/api/gitignore/apply":

            preset = body.get("preset", "strict")

            custom_content = body.get("custom_content")

            target_path = body.get("target_path")

            res = gitignore_manager.apply_global_gitignore(

                preset_id=preset,

                custom_content=custom_content,

                target_path=target_path

            )

            self.send_json(res)

            return



        elif path == "/api/gitignore/clear":

            res = gitignore_manager.clear_global_gitignore()

            self.send_json(res)

            return



        # Custom Gitignore Templates CRUD

        elif path == "/api/gitignore/custom/save":

            template_id = body.get("id", "")

            name = body.get("name", "")

            content = body.get("content", "")

            description = body.get("description", "")

            res = gitignore_manager.save_custom_template(

                template_id=template_id,

                name=name,

                content=content,

                description=description

            )

            self.send_json(res)

            return



        elif path == "/api/gitignore/custom/delete":

            template_id = body.get("id", "")

            if not template_id:

                self.send_json({"success": False, "error": "Template id is required"}, 400)

                return

            res = gitignore_manager.delete_custom_template(template_id)

            self.send_json(res)

            return

        # Star Vault API - Fetch Cloud Lists & Stars via GitHub GraphQL + REST
        elif path == "/api/stars/fetch-cloud":
            token = body.get("token", "").strip()
            if not token:
                token = credential_vault.get_plain_token("github")

            if not token:
                self.send_json({
                    "success": False,
                    "error": "未检测到 GitHub Access Token。请在请求中提供 token，或在 [凭据管理] 中配置并设为默认。"
                }, 400)
                return

            # 1. GraphQL 查询 Lists 与所属仓库
            gql_res = star_vault_engine.query_github_star_lists(token)
            if not gql_res.get("success"):
                self.send_json({
                    "success": False,
                    "error": f"GraphQL 拉取失败: {gql_res.get('error', '未知错误')}"
                }, 502)
                return

            cloud_lists = gql_res.get("lists", [])
            cloud_repos = gql_res.get("repositories", [])

            # 2. REST API 抓取 flat stars (补充时间戳和未归类到 List 的 Star)
            max_pages = int(body.get("max_pages", 5))
            try:
                flat_stars = star_vault_engine.fetch_flat_stars(token, max_pages=max_pages)
            except Exception:
                flat_stars = []

            # 3. 合并到本地库
            current_vault = star_vault_engine.load_starred_vault()
            merged_stage1 = star_vault_engine.merge_stars_data(current_vault, [], flat_stars)
            final_merged = star_vault_engine.merge_stars_data(merged_stage1, cloud_lists, cloud_repos)

            star_vault_engine.save_starred_vault(final_merged)
            star_vault_engine.save_stars_markdown()

            self.send_json({
                "success": True,
                "synced_stars": len(final_merged.get("repositories", [])),
                "synced_lists": len(final_merged.get("lists", [])),
                "vault": final_merged
            })
            return

        # Star Vault API - Manual Import & Enrichment
        elif path == "/api/stars/manual-import":
            target_list = body.get("list_name", "").strip() or "未分类"
            repos_input = body.get("repos") or body.get("raw_text") or []
            token = body.get("token", "").strip()
            if not token:
                token = credential_vault.get_plain_token("github")

            res = star_vault_engine.manual_import_repos(
                repos_input=repos_input,
                target_list=target_list,
                token=token
            )
            status_code = 200 if res.get("success") else 400
            self.send_json(res, status_code)
            return

        # Star Vault API - Multi-Cloud Push Bus
        elif path == "/api/stars/push-cloud":
            branch = body.get("branch", "main")
            res = star_vault_engine.sync_stars_vault_repo(branch=branch)
            self.send_json(res)
            return

        # Star Vault API - Delete Repo (Single or Batch)
        elif path == "/api/stars/delete-repo":
            full_names = body.get("full_names")
            if isinstance(full_names, list) and full_names:
                count = 0
                for fn in full_names:
                    if star_vault_engine.delete_repo_from_vault(str(fn).strip()):
                        count += 1
                self.send_json({"success": True, "count": count, "full_names": full_names})
                return

            full_name = body.get("full_name", "").strip()
            if not full_name:
                self.send_json({"success": False, "error": "full_name or full_names is required"}, 400)
                return

            deleted = star_vault_engine.delete_repo_from_vault(full_name)
            self.send_json({"success": deleted, "full_name": full_name})
            return

        # Star Vault API - Clear All Repositories
        elif path == "/api/stars/clear-all":
            res = star_vault_engine.clear_vault_repositories()
            self.send_json(res)
            return

        # Star Vault API - Reset To Seed Baseline
        elif path == "/api/stars/reset-seed":
            res = star_vault_engine.reset_vault_to_seed()
            self.send_json(res)
            return

        # Star Vault API - Create List
        elif path == "/api/stars/create-list":
            name = body.get("name", "").strip()
            desc = body.get("description", "").strip()
            res = star_vault_engine.create_list_in_vault(name=name, description=desc)
            status_code = 200 if res.get("success") else 400
            self.send_json(res, status_code)
            return

        # Star Vault API - Star Repo Directly
        elif path == "/api/stars/star-repo":
            full_name = body.get("full_name", "").strip()
            owner = body.get("owner", "").strip()
            repo = body.get("repo", "").strip()
            if not owner or not repo:
                if "/" in full_name:
                    owner, repo = full_name.split("/", 1)
                else:
                    self.send_json({"success": False, "error": "owner and repo are required"}, 400)
                    return

            token = body.get("token", "").strip()
            if not token:
                token = credential_vault.get_plain_token("github")

            if not token:
                self.send_json({"success": False, "error": "未提供或未配置 GitHub Token"}, 400)
                return

            res = star_vault_engine.star_repository(token, owner, repo)
            self.send_json(res)
            return

        # Agent Integration - 1-Click Install Antigravity Plugin & Schemas
        elif path == "/api/agent/install-antigravity":
            res = agent_installer.install_antigravity_plugin()
            status_code = 200 if res.get("success") else 500
            self.send_json(res, status_code)
            return




        self.send_error(404, "Not Found")

    def do_DELETE(self):
        self.send_json({"success": False, "error": "Method Not Allowed"}, 405)



# --- T5: 凭据路由辅助（校验 / 审计 / SOPS 路径白名单） ---


def _audit_vault(handler, tool_name, args, res, ok_msg="操作成功"):
    """统一审计凭据 CRUD。args 只放标识，绝不放 token/secret 明文。"""
    try:
        ok = bool((res or {}).get("success", True))
        mcp_server.log_audit_entry(
            tool_name=tool_name,
            args=args or {},
            status="SUCCESS" if ok else "ERROR",
            message=ok_msg if ok else str((res or {}).get("error", "")),
            client_ip=handler.address_string(),
        )
    except Exception:
        pass


def _credential_input(body):
    """校验 key_type / scope，返回 (key_type, scope, error)。"""
    raw_kt = body.get("key_type")
    kt = credential_types.parse_key_type(raw_kt) if raw_kt else None
    if raw_kt and not kt:
        return None, None, "非法的 key_type: " + str(raw_kt)
    if credential_types.KEY_TYPES.get(kt, {}).get("storage_domain") == "platform":
        return None, None, "平台域密钥不得入库: " + kt
    scope = body.get("scope")
    if scope is None:
        return kt, None, None
    if kt is None:
        return None, None, "指定 scope 时必须同时提供 key_type"
    if not isinstance(scope, dict):
        return None, None, "scope 必须是对象"
    allowed = set(credential_types.default_scope(kt).keys())
    unknown = sorted(set(scope.keys()) - allowed)
    if unknown:
        return None, None, "scope 含未知键: " + ", ".join(unknown)
    for key, val in scope.items():
        if val is None:
            continue
        ok = isinstance(val, str)
        ok = ok or (isinstance(val, list) and all(isinstance(x, str) for x in val))
        ok = ok or (key == "permissions" and isinstance(val, dict)
                    and all(isinstance(x, (str, bool)) for x in val.values()))
        if not ok:
            return None, None, "scope." + key + " 类型非法"
    try:
        if len(json.dumps(scope, ensure_ascii=False)) > 4096:
            return None, None, "scope 过大"
    except (TypeError, ValueError):
        return None, None, "scope 不可序列化"
    return kt, scope, None


def _sops_bridge():
    """惰性导入 T4 模块；未落地时返回 (None, error)，不阻断 server 启动。"""
    try:
        from core import sops_bridge
        return sops_bridge, None
    except Exception as exc:
        return None, "SOPS 模块不可用: " + str(exc)


def _sops_status():
    """探测 SOPS 可用性与安装提示，供 GET /api/vault/sops/status 与路由复用。"""
    bridge, err = _sops_bridge()
    if bridge is None:
        return {"available": False, "install_hint": err}
    try:
        # sops_available() 返回 dict（含 available/error），不是 bool；bool(dict) 恒真会谎报可用
        info = bridge.sops_available() or {}
        available = bool(info.get("available")) if isinstance(info, dict) else bool(info)
    except Exception:
        available = False
    hint = ""
    for name in ("INSTALL_HINT", "install_hint"):
        try:
            hint = getattr(bridge, name) or hint
        except Exception:
            pass
    if not hint:
        hint = "未检测到 sops/age，请安装后重试"
    return {"available": available, "install_hint": hint}


def _sops_path(raw):
    """SOPS 路径白名单：realpath 必须落在 BASE_DIR 内，后缀受限；空值表示用 T4 默认。"""
    if not raw:
        return None, None
    if not isinstance(raw, str):
        return None, "path 必须是字符串"
    resolved = os.path.realpath(os.path.abspath(raw))
    root = os.path.realpath(BASE_DIR) + os.sep
    if not resolved.startswith(root):
        return None, "path 越界：仅允许仓库目录内"
    if not resolved.lower().endswith((".yaml", ".yml", ".enc.yaml")):
        return None, "path 后缀必须是 .yaml/.yml/.enc.yaml"
    return resolved, None


def run_server(port=PORT):

    ThreadingHTTPServer.allow_reuse_address = True

    server = ThreadingHTTPServer(("127.0.0.1", port), GitVaultHandler)

    print(f">>> Git-Vault Server & MCP Gateway running at: http://127.0.0.1:{port}")

    try:

        server.serve_forever()

    except KeyboardInterrupt:

        print("\nShutting down Git-Vault...")

        server.server_close()



if __name__ == "__main__":

    run_server()

