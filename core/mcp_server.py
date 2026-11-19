# core/mcp_server.py
# Antigravity Git-Vault - Model Context Protocol (MCP) Server 2.0
import sys
import os
import json
import time
import datetime
from typing import Dict, List, Any, Optional, Tuple

# Root imports
VAULT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if VAULT_ROOT not in sys.path:
    sys.path.insert(0, VAULT_ROOT)

from core import (
    redaction,
    git_engine,
    compliance_guard,
    secret_proxy,
    credential_vault,
    star_vault_engine,
    gitignore_manager,
    gov_git
)

LOGS_DIR = os.path.join(VAULT_ROOT, "logs")
AUDIT_LOG_FILE = os.path.join(LOGS_DIR, "mcp_audit.log")
STARS_INDEX_FILE = os.path.join(VAULT_ROOT, "STARS_INDEX.md")

def log_audit_entry(
    tool_name: str,
    args: Dict[str, Any],
    status: str,
    message: str = "",
    agent_id: str = "agent-local",
    client_ip: str = "127.0.0.1"
) -> Dict[str, Any]:
    """Append a structured audit log entry."""
    os.makedirs(LOGS_DIR, exist_ok=True)
    args = args or {}
    
    # Redact sensitive fields in args
    clean_args = {}
    for k, v in args.items():
        if any(sec in k.lower() for sec in ["token", "secret", "password", "key", "auth"]):
            clean_args[k] = "[REDACTED]"
        else:
            clean_args[k] = v

    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = {
        "timestamp": now_str,
        "agent_id": agent_id,
        "client_ip": client_ip,
        "tool": tool_name,
        "args": clean_args,
        "status": status,  # "SUCCESS", "BLOCKED", "ERROR"
        "message": message
    }

    entry = redaction.redact(entry)

    try:
        with open(AUDIT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        sys.stderr.write(f"[AUDIT_ERROR] Failed to write audit log: {e}\n")

    return entry

def get_audit_logs(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve the most recent audit log entries."""
    if not os.path.exists(AUDIT_LOG_FILE):
        return []
    entries = []
    try:
        with open(AUDIT_LOG_FILE, "r", encoding="utf-8") as f:
            lines = f.readlines()
            for line in reversed(lines):
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                        if len(entries) >= limit:
                            break
                    except Exception:
                        pass
    except Exception:
        pass
    return entries

# =============================================================================
# Tool Implementations (MCP 2.0 Core Catalog)
# =============================================================================

def tool_vault_list_repos(args: Dict[str, Any]) -> Dict[str, Any]:
    workspace_root = args.get("workspace_root", "<vault-root>")
    repos = git_engine.scan_repositories(workspace_root)
    for _r in repos:
        if isinstance(_r, dict) and isinstance(_r.get("remotes"), dict):
            _r["remotes"] = git_engine.sanitize_remotes(_r["remotes"])
    return {
        "success": True,
        "count": len(repos),
        "workspace_root": workspace_root,
        "repos": repos
    }

def tool_vault_get_diff(args: Dict[str, Any]) -> Dict[str, Any]:
    repo_path = args.get("repo_path", "")
    staged_only = args.get("staged_only", False)
    if not repo_path:
        return {"success": False, "error": "[MCP] repo_path 参数为必填项"}
    return git_engine.get_repo_diff(repo_path, staged_only=staged_only)

def tool_vault_commit_push(args: Dict[str, Any]) -> Dict[str, Any]:
    repo_path = args.get("repo_path", "")
    message = args.get("message", "")
    should_push = args.get("push", True)
    agent_name = args.get("agent_name", "GV_AGY_Gemini-3.8-Flash")
    agent_email = args.get("agent_email", "<bot-email>")

    if not repo_path or not message:
        return {"success": False, "error": "[MCP] repo_path 与 message 均为必填项"}

    # 1. Optional partial staging (rule 14): only requested paths
    stage_paths = list(args.get("paths") or [])
    if stage_paths:
        add_res = git_engine.run_git(["add", "-A", "--"] + stage_paths, cwd=repo_path)
        if not add_res.get("success"):
            return {"success": False, "error": "stage failed: " + (add_res.get("stderr") or add_res.get("stdout") or "")}

    # 2. Commit (panic check + compliance guard + repo governance gate)
    commit_res = git_engine.create_commit(
        repo_path=repo_path,
        message=message,
        stage_all=not stage_paths,
        agent_name=agent_name,
        agent_email=agent_email
    )

    if not commit_res.get("success", False):
        err = str(commit_res.get("error", ""))
        if "nothing to commit" in err and should_push:
            push_res = git_engine.sync_repository(repo_path)
            return {
                "success": True,
                "commit": {"success": True, "notice": "working tree clean, skipped commit"},
                "push": push_res
            }
        return commit_res

    # 2. Push if requested
    push_res = None
    if should_push:
        push_res = git_engine.sync_repository(repo_path)

    return {
        "success": True,
        "commit": commit_res,
        "push": push_res,
        "staged_files": stage_paths if stage_paths else ["<all>"],
    }

def tool_vault_create_repo(args: Dict[str, Any]) -> Dict[str, Any]:
    repo_name = args.get("repo_name", "").strip()
    parent_dir = args.get("parent_dir", "<vault-root>").strip()
    initial_branch = args.get("initial_branch", "main").strip() or "main"

    if not repo_name:
        return {"success": False, "error": "[MCP] repo_name 不能为空"}

    can_write, panic_msg = compliance_guard.check_write_permission()
    if not can_write:
        return {"success": False, "blocked": True, "error": panic_msg}

    repo_dir = os.path.join(parent_dir, repo_name)
    if os.path.exists(repo_dir) and os.path.exists(os.path.join(repo_dir, ".git")):
        return {"success": False, "error": f"[MCP] 仓库已存在: {repo_dir}"}

    os.makedirs(repo_dir, exist_ok=True)
    init_res = git_engine.run_git(["init", "-b", initial_branch], cwd=repo_dir)
    if not init_res["success"]:
        return {"success": False, "error": init_res["stderr"]}

    # Ensure author identity binding to verified human account
    raw_vault = credential_vault.load_raw_vault()
    saved_accounts = raw_vault.get("saved_accounts", {})
    default_user = saved_accounts.get("gitee_user") or saved_accounts.get("github_user") or "<owner>"
    git_engine.set_identity(name=default_user, email=f"{default_user}@users.noreply.git", scope="local", cwd=repo_dir)

    return {
        "success": True,
        "repo_name": repo_name,
        "path": repo_dir,
        "branch": initial_branch,
        "bound_user": default_user
    }

def tool_vault_audit_compliance(args: Dict[str, Any]) -> Dict[str, Any]:
    """Proactively audit repository compliance before making commits."""
    repo_path = args.get("repo_path") or "<vault-root>"
    if not os.path.exists(repo_path):
        return {"success": False, "error": f"[MCP] 仓库路径不存在: {repo_path}"}

    report = compliance_guard.audit_repository_readiness(repo_path)
    findings = report.get("findings", [])
    is_compliant = report.get("compliant", len(findings) == 0)
    return {
        "success": True,
        "repo_path": repo_path,
        "compliant": is_compliant,
        "violations_count": len(findings),
        "violations": findings,
        "remediation_suggested": not is_compliant,
        "message": "Repository is compliant." if is_compliant else "Violations detected. Run vault_remediate_gitignore to auto-heal untracked leaks."
    }

def tool_vault_remediate_gitignore(args: Dict[str, Any]) -> Dict[str, Any]:
    """Auto-remediate repository by writing rules to .gitignore and clearing cache."""
    repo_path = args.get("repo_path", "")
    patterns = args.get("patterns", [])
    if not repo_path or not os.path.exists(repo_path):
        return {"success": False, "error": f"[MCP] 仓库路径无效: {repo_path}"}

    can_write, panic_msg = compliance_guard.check_write_permission()
    if not can_write:
        return {"success": False, "blocked": True, "error": panic_msg}

    res = compliance_guard.remediate_gitignore_rules(repo_path, patterns)
    return res

def tool_vault_check_panic(args: Dict[str, Any]) -> Dict[str, Any]:
    """Check if the global Panic Button read-only lock is currently active."""
    locked = compliance_guard.is_panic_button_active()
    return {
        "success": True,
        "locked": locked,
        "mode": "READ_ONLY" if locked else "READ_WRITE",
        "message": "Panic button is ACTIVE. All write/commit/push operations are physically blocked." if locked else "System is healthy. Write operations permitted."
    }

def tool_vault_search_stars(args: Dict[str, Any]) -> Dict[str, Any]:
    """Search personal curated Star Vault assets by keyword, list name, or primary language."""
    query = args.get("query", "").strip()
    list_name = args.get("list_name", "").strip()
    language = args.get("language", "").strip()
    limit = int(args.get("limit", 20))

    res = star_vault_engine.query_vault(
        search=query,
        list_name=list_name if list_name else None,
        language=language if language else None
    )
    repos = res.get("repositories", [])[:limit]
    return {
        "success": True,
        "query": query,
        "list_name": list_name or "all",
        "count": len(repos),
        "total_matched": res.get("total_matched", len(repos)),
        "results": repos
    }

def tool_vault_query_lists(args: Dict[str, Any]) -> Dict[str, Any]:
    """Retrieve all curated Lists and repository count distribution."""
    vault = star_vault_engine.load_starred_vault()
    lists = vault.get("lists", [])
    stats = vault.get("stats", {})
    return {
        "success": True,
        "total_lists": len(lists),
        "total_stars": stats.get("total_stars", len(vault.get("repositories", []))),
        "lists": lists
    }

def tool_vault_star_repo(args: Dict[str, Any]) -> Dict[str, Any]:
    """Star a repository on GitHub and associate it with a personal List."""
    full_name = args.get("full_name", "").strip()
    list_name = args.get("list_name", "").strip()
    if not full_name or "/" not in full_name:
        return {"success": False, "error": "[MCP] full_name 必须是有效格式 (如 'owner/repo')"}

    can_write, panic_msg = compliance_guard.check_write_permission()
    if not can_write:
        return {"success": False, "blocked": True, "error": panic_msg}

    owner, repo = full_name.split("/", 1)
    star_res = star_vault_engine.star_repo_rest(None, owner, repo)

    # Optionally associate with user list in vault
    if list_name:
        star_vault_engine.add_or_create_list(list_name)

    return {
        "success": star_res.get("success", False),
        "full_name": full_name,
        "list_name": list_name or None,
        "details": star_res
    }

def tool_vault_proxy_api(args: Dict[str, Any]) -> Dict[str, Any]:
    service = args.get("service", "")
    endpoint = args.get("endpoint", "")
    method = args.get("method", "GET")
    headers = args.get("headers")
    query_params = args.get("query_params")
    payload = args.get("payload")

    if not service or not endpoint:
        return {"success": False, "error": "[MCP] service 与 endpoint 均为必填项"}

    return secret_proxy.execute_proxy_request(
        service=service,
        endpoint=endpoint,
        method=method,
        headers=headers,
        query_params=query_params,
        payload=payload
    )

def tool_vault_get_audit_log(args: Dict[str, Any]) -> Dict[str, Any]:
    limit = args.get("limit", 50)
    logs = get_audit_logs(limit=int(limit))
    return {
        "success": True,
        "count": len(logs),
        "logs": logs
    }

# =============================================================================
# Tool Registry (MCP 2.0 Full 10+ Standard Tools)
# =============================================================================

def tool_vault_git_status(args: Dict[str, Any]) -> Dict[str, Any]:
    repo_path = args.get("repo_path", "")
    if not repo_path:
        return {"success": False, "error": "[MCP] repo_path 为必填项"}
    return gov_git.get_repo_status(repo_path)

def tool_vault_git_branch(args: Dict[str, Any]) -> Dict[str, Any]:
    repo_path = args.get("repo_path", "")
    if not repo_path:
        return {"success": False, "error": "[MCP] repo_path 为必填项"}
    return gov_git.git_branch_manage(
        repo_path=repo_path,
        action=args.get("action", "list"),
        name=args.get("name", "") or "",
        base=args.get("base", "") or "",
        confirm=bool(args.get("confirm", False)),
    )

def tool_vault_git_merge(args: Dict[str, Any]) -> Dict[str, Any]:
    repo_path = args.get("repo_path", "")
    source = args.get("source", "")
    if not repo_path or not source:
        return {"success": False, "error": "[MCP] repo_path 与 source 均为必填项"}
    return gov_git.git_merge(
        repo_path=repo_path,
        source=source,
        into=args.get("into", "main") or "",
        strategy=args.get("strategy", "ff") or "ff",
        dry_run=bool(args.get("dry_run", True)),
    )

MCP_TOOLS = [
    {
        "name": "vault_list_repos",
        "description": "列出本地工作区中所有纳管的 Git 仓库状态、分支、未推送情况与多云同步健康度",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspace_root": {"type": "string", "description": "工作区根路径，默认 <vault-root>"}
            }
        },
        "handler": tool_vault_list_repos
    },
    {
        "name": "vault_get_diff",
        "description": "安全读取指定仓库的工作区代码差异与状态（内置敏感信息防泄漏实时扫描）",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_path": {"type": "string", "description": "本地 Git 仓库绝对路径"},
                "staged_only": {"type": "boolean", "description": "是否仅查看已暂存变更"}
            },
            "required": ["repo_path"]
        },
        "handler": tool_vault_get_diff
    },
    {
        "name": "vault_commit_push",
        "description": "受控执行代码暂存、合规校验、自动附加 Co-authored-by 署名并提交与分发推送。严格受全局只读锁 (Panic Button) 保护。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_path": {"type": "string", "description": "本地仓库绝对路径"},
                "message": {"type": "string", "description": "提交说明 (Commit Message)"},
                "push": {"type": "boolean", "description": "提交后是否自动执行三端多路分发推送，默认 true"},
                "agent_name": {"type": "string", "description": "Agent 协作者名称，默认 GV_AGY_Gemini-2.5-Pro"},
                "agent_email": {"type": "string", "description": "Agent 协作者邮箱"},
                "paths": {"type": "array", "items": {"type": "string"}, "description": "可选：仅暂存并提交这些路径（部分提交）"}
            },
            "required": ["repo_path", "message"]
        },
        "handler": tool_vault_commit_push
    },
    {
        "name": "vault_create_repo",
        "description": "统一在本地工作区初始化新 Git 仓库，并绑定自然人开发者主身份 (默认 <owner>)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_name": {"type": "string", "description": "仓库名称"},
                "parent_dir": {"type": "string", "description": "父目录，默认 <vault-root>"},
                "initial_branch": {"type": "string", "description": "初始分支名称，默认 main"}
            },
            "required": ["repo_name"]
        },
        "handler": tool_vault_create_repo
    },
    {
        "name": "vault_audit_compliance",
        "description": "主动扫描仓库的合规状态，检查是否包含未脱敏敏感密钥 (API Key, 私钥) 或超出平台限额的大文件 (Gitee 50MB/GitHub 100MB)",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_path": {"type": "string", "description": "待检查的本地 Git 仓库绝对路径"}
            },
            "required": ["repo_path"]
        },
        "handler": tool_vault_audit_compliance
    },
    {
        "name": "vault_remediate_gitignore",
        "description": "对发现的违规文件或泄漏项自动注入 .gitignore 规则并执行缓存解除跟踪 (git rm --cached)，实现一键合规自愈",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_path": {"type": "string", "description": "本地 Git 仓库绝对路径"},
                "patterns": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "可选需写入 .gitignore 的规则列表；为空时将自动提取违规项写入"
                }
            },
            "required": ["repo_path"]
        },
        "handler": tool_vault_remediate_gitignore
    },
    {
        "name": "vault_check_panic",
        "description": "查询当前系统是否处于 Panic Button 全局只读急停锁保护状态，明确是否允许写操作",
        "inputSchema": {
            "type": "object",
            "properties": {}
        },
        "handler": tool_vault_check_panic
    },
    {
        "name": "vault_search_stars",
        "description": "在个人本地 Star 容灾库中精准检索已收藏的开源项目（支持按关键词、Lists 分类名或主要语言筛选）",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "搜索关键词（匹配仓库名或描述）"},
                "list_name": {"type": "string", "description": "指定的自定义分类 List（如 agent tool, SKILL, Cloudflare 等）"},
                "language": {"type": "string", "description": "指定编程语言（如 Python, TypeScript, Rust 等）"},
                "limit": {"type": "integer", "description": "返回最多条数，默认 20"}
            }
        },
        "handler": tool_vault_search_stars
    },
    {
        "name": "vault_query_lists",
        "description": "获取当前 Star 容灾中枢中收录的所有自定义 Lists 分类及各分类下的资产数量",
        "inputSchema": {
            "type": "object",
            "properties": {}
        },
        "handler": tool_vault_query_lists
    },
    {
        "name": "vault_star_repo",
        "description": "由 Agent 为指定的开源仓库在 GitHub 点星并归入指定 List",
        "inputSchema": {
            "type": "object",
            "properties": {
                "full_name": {"type": "string", "description": "目标仓库全名，如 'owner/repo'"},
                "list_name": {"type": "string", "description": "可选归属分类 List 名称"}
            },
            "required": ["full_name"]
        },
        "handler": tool_vault_star_repo
    },
    {
        "name": "vault_proxy_api",
        "description": "零明文代理调用外部三方 API (如 Cloudflare, OpenAI 等)。由 Git-Vault 内部解密注入 Token，Agent 全程不接触明文密钥。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "service": {"type": "string", "description": "服务标识，如 cloudflare, openai, anthropic"},
                "endpoint": {"type": "string", "description": "API 端点相对路径或完整 URL"},
                "method": {"type": "string", "description": "HTTP 请求方法，默认 GET"},
                "headers": {"type": "object", "description": "可选请求头"},
                "query_params": {"type": "object", "description": "可选 URL 查询参数"},
                "payload": {"type": "object", "description": "可选请求体 (JSON)"}
            },
            "required": ["service", "endpoint"]
        },
        "handler": tool_vault_proxy_api
    },
    {
        "name": "vault_get_audit_log",
        "description": "查询 Agent 历史调用审计记录与合规阻断日志",
        "inputSchema": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "description": "返回最近日志条数，默认 50"}
            }
        },
        "handler": tool_vault_get_audit_log
    }
]

MCP_TOOLS.extend([
    {
        "name": "vault_git_status",
        "description": "结构化读取仓库状态（分支、ahead/behind、staged/unstaged/untracked）。只读；写操作仍须经 vault 工具。",
        "inputSchema": {
            "type": "object",
            "properties": {"repo_path": {"type": "string", "description": "本地 Git 仓库绝对路径"}},
            "required": ["repo_path"]
        },
        "handler": tool_vault_git_status
    },
    {
        "name": "vault_git_branch",
        "description": "受控分支操作（list/create/switch/delete）。删除需 confirm=true，当前分支禁删，受 Panic 锁保护。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_path": {"type": "string", "description": "本地 Git 仓库绝对路径"},
                "action": {"type": "string", "description": "list | create | switch | delete"},
                "name": {"type": "string", "description": "分支名（list 可省略）"},
                "base": {"type": "string", "description": "创建分支基点，默认 HEAD"},
                "confirm": {"type": "boolean", "description": "删除分支必须为 true"}
            },
            "required": ["repo_path", "action"]
        },
        "handler": tool_vault_git_branch
    },
    {
        "name": "vault_git_merge",
        "description": "受控合并（ff/no-ff/squash）。dry_run 默认 true：--no-commit 探测冲突后 abort，不改工作树。",
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo_path": {"type": "string", "description": "本地 Git 仓库绝对路径"},
                "source": {"type": "string", "description": "待合并分支/提交"},
                "into": {"type": "string", "description": "目标分支，默认 main，必须等于当前分支"},
                "strategy": {"type": "string", "description": "ff | no-ff | squash，默认 ff"},
                "dry_run": {"type": "boolean", "description": "默认 true，仅探测冲突"}
            },
            "required": ["repo_path", "source"]
        },
        "handler": tool_vault_git_merge
    },
])
TOOLS_MAP = {t["name"]: t for t in MCP_TOOLS}

# =============================================================================
# Resources Registry (MCP 2.0 Read-Only URIs)
# =============================================================================

MCP_RESOURCES = [
    {
        "uri": "vault://stars/index.md",
        "name": "Star Vault Offline Markdown Index",
        "description": "Latest structured catalog of curated GitHub Stars and Lists in Markdown format",
        "mimeType": "text/markdown"
    },
    {
        "uri": "vault://stars/catalog.json",
        "name": "Star Vault JSON Catalog",
        "description": "Raw structured repository vault database (17+ repos across 8 Lists)",
        "mimeType": "application/json"
    },
    {
        "uri": "vault://system/health",
        "name": "Git-Vault Multi-Cloud Health & Panic Status",
        "description": "Multi-cloud connectivity (GitHub, Gitee, GitLab) and Panic Button status",
        "mimeType": "application/json"
    }
]

def read_mcp_resource(uri: str) -> Optional[Dict[str, Any]]:
    """Read content for a given vault:// URI."""
    if uri == "vault://stars/index.md":
        if os.path.exists(STARS_INDEX_FILE):
            with open(STARS_INDEX_FILE, "r", encoding="utf-8") as f:
                content = f.read()
        else:
            vault = star_vault_engine.load_starred_vault()
            content = star_vault_engine.render_stars_markdown(vault)
        return {
            "uri": uri,
            "mimeType": "text/markdown",
            "text": content
        }
    elif uri == "vault://stars/catalog.json":
        vault = star_vault_engine.load_starred_vault()
        return {
            "uri": uri,
            "mimeType": "application/json",
            "text": json.dumps(vault, ensure_ascii=False, indent=2)
        }
    elif uri == "vault://system/health":
        locked = compliance_guard.is_panic_button_active()
        raw_vault = credential_vault.load_raw_vault()
        saved = raw_vault.get("saved_accounts", {})
        health_data = {
            "panic_button_locked": locked,
            "mode": "READ_ONLY" if locked else "READ_WRITE",
            "accounts": {
                "github": {"user": saved.get("github_user", "<owner>"), "auth": "SSH/Token"},
                "gitee": {"user": saved.get("gitee_user", "<owner>"), "auth": "Token"},
                "gitlab": {"user": saved.get("gitlab_user", "<owner>"), "auth": "SSH"}
            },
            "timestamp": datetime.datetime.now().isoformat()
        }
        return {
            "uri": uri,
            "mimeType": "application/json",
            "text": json.dumps(health_data, ensure_ascii=False, indent=2)
        }
    return None

# =============================================================================
# JSON-RPC 2.0 Handler
# =============================================================================

def handle_json_rpc(request_data: Dict[str, Any], agent_id: str = "agent-local", client_ip: str = "127.0.0.1") -> Dict[str, Any]:
    """Process an MCP JSON-RPC 2.0 request and return the response."""
    if not isinstance(request_data, dict):
        return {
            "jsonrpc": "2.0",
            "id": None,
            "error": {
                "code": -32600,
                "message": "Invalid Request: expected JSON object"
            }
        }

    msg_id = request_data.get("id")
    method = request_data.get("method", "")
    params = request_data.get("params") or {}

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {
                    "tools": {},
                    "resources": {}
                },
                "serverInfo": {
                    "name": "git-vault-mcp",
                    "version": "2.0.0"
                }
            }
        }

    elif method in ["notifications/initialized", "initialized"]:
        return {}

    elif method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

    elif method == "tools/list":
        tools_list = []
        for t in MCP_TOOLS:
            tools_list.append({
                "name": t["name"],
                "description": t["description"],
                "inputSchema": t["inputSchema"]
            })
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "tools": tools_list
            }
        }

    elif method == "resources/list":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "resources": MCP_RESOURCES
            }
        }

    elif method == "resources/read":
        uri = params.get("uri", "")
        res_data = read_mcp_resource(uri)
        if not res_data:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32602,
                    "message": f"Resource not found: {uri}"
                }
            }
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "contents": [res_data]
            }
        }

    elif method == "tools/call":
        tool_name = params.get("name", "")
        tool_args = params.get("arguments") or {}

        if tool_name not in TOOLS_MAP:
            log_audit_entry(
                tool_name=tool_name,
                args=tool_args,
                status="ERROR",
                message=f"未知工具: {tool_name}",
                agent_id=agent_id,
                client_ip=client_ip
            )
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32601,
                    "message": f"Tool not found: {tool_name}"
                }
            }

        tool_def = TOOLS_MAP[tool_name]
        try:
            result = tool_def["handler"](tool_args)
            status = "SUCCESS"
            msg = "[OK] 执行成功"
            if isinstance(result, dict) and result.get("blocked", False):
                status = "BLOCKED"
                msg = result.get("error", "合规或只读锁拦截")
            elif isinstance(result, dict) and not result.get("success", True):
                status = "ERROR"
                msg = result.get("error", "执行失败")

            log_audit_entry(
                tool_name=tool_name,
                args=tool_args,
                status=status,
                message=msg,
                agent_id=agent_id,
                client_ip=client_ip
            )

            is_err = status in ["BLOCKED", "ERROR"]
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": json.dumps(result, ensure_ascii=False, indent=2)
                        }
                    ],
                    "isError": is_err
                }
            }
        except Exception as e:
            log_audit_entry(
                tool_name=tool_name,
                args=tool_args,
                status="ERROR",
                message=str(e),
                agent_id=agent_id,
                client_ip=client_ip
            )
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {
                    "code": -32603,
                    "message": f"Internal execution error: {str(e)}"
                }
            }

    return {
        "jsonrpc": "2.0",
        "id": msg_id,
        "error": {
            "code": -32601,
            "message": f"Method not supported: {method}"
        }
    }

def run_stdio_server():
    """Run MCP server over standard I/O (JSON-RPC 2.0) with pure stream isolation."""
    # Capture original stdout for strict JSON-RPC responses only
    real_stdout = sys.stdout
    # Divert any uncontrolled print() or logs from submodules to stderr so stdout stays 100% clean
    sys.stdout = sys.stderr

    sys.stderr.write("[MCP_STDIO] Git-Vault Model Context Protocol Server 2.0 active on stdio\n")
    sys.stderr.flush()

    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue

            req = json.loads(line)
            res = handle_json_rpc(req, agent_id="agent-stdio", client_ip="stdio")
            if res:
                res = redaction.redact(res)
                real_stdout.write(json.dumps(res, ensure_ascii=False) + "\n")
                real_stdout.flush()
        except KeyboardInterrupt:
            break
        except Exception as e:
            sys.stderr.write(f"[MCP_STDIO_ERROR] {e}\n")
            sys.stderr.flush()

if __name__ == "__main__":
    run_stdio_server()
