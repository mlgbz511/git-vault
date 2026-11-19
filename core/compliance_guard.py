# core/compliance_guard.py
# Antigravity Git-Vault - Platform Rules & Compliance Guardrail
import os
import re
import json
import subprocess
import sys
from typing import Dict, List, Any, Tuple, Optional

from core.credential_types import KEY_TYPES

# Constants
GITEE_MAX_FILE_BYTES = 50 * 1024 * 1024     # 50MB
GITHUB_MAX_FILE_BYTES = 100 * 1024 * 1024  # 100MB
GITHUB_LFS_WARN_BYTES = 50 * 1024 * 1024   # 50MB
GITEE_MAX_REPO_BYTES = 500 * 1024 * 1024   # 500MB

# Panic Button State File
VAULT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE_FILE = os.path.join(VAULT_ROOT, "config", "runtime_state.json")

# --- Panic Button (Read-Only Lock) ---
def is_panic_button_active() -> bool:
    """Check if the global read-only lock (Panic Button) is enabled."""
    if not os.path.exists(STATE_FILE):
        return False
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            return bool(data.get("panic_button_locked", False))
    except Exception:
        return False

def set_panic_button(active: bool) -> bool:
    """Set the global read-only lock state."""
    data = {}
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {}
    data["panic_button_locked"] = bool(active)
    try:
        os.makedirs(os.path.dirname(STATE_FILE), exist_ok=True)
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return True
    except Exception:
        return False

def check_write_permission() -> Tuple[bool, str]:
    """Verify write permission before any commit or push action."""
    if is_panic_button_active():
        return False, "[GUARD][PANIC_BUTTON] 全局只读锁已开启：已切断所有 Commit 与 Push 操作，只允许读取与 Diff 查看。"
    return True, "[GUARD] 写入权限正常。"

def _prefix_pattern(key_type: str) -> str:
    """从 KEY_TYPES 取 token 前缀正则，禁止在本文件再写死一份。"""
    pattern = KEY_TYPES[key_type]["prefix_regex"]
    if not pattern:
        raise RuntimeError(f"KEY_TYPES['{key_type}'] 未定义 prefix_regex，拒绝降级为漏检")
    return pattern

# --- Secret Leak Patterns ---
SECRET_PATTERNS = [
    {
        "id": "aws_access_key",
        "name": "AWS Access Key ID",
        "pattern": r"\b(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}\b",
        "severity": "BLOCK"
    },
    {
        "id": "aws_secret_key",
        "name": "AWS Secret Access Key",
        "pattern": r"(?i)\baws_?(?:secret)?_?(?:access)?_?key\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{40})['\"]?",
        "severity": "BLOCK"
    },
    {
        "id": "github_pat_classic",
        "name": "GitHub Personal Access Token (Classic)",
        "pattern": r"\bghp_[a-zA-Z0-9]{36}\b",
        "severity": "BLOCK"
    },
    {
        "id": "github_pat_fine_grained",
        "name": "GitHub Personal Access Token (Fine-Grained)",
        "pattern": r"\bgithub_pat_[a-zA-Z0-9_]{82}\b",
        "severity": "BLOCK"
    },
    {
        "id": "github_oauth",
        "name": "GitHub OAuth Access Token",
        "pattern": r"\bgho_[a-zA-Z0-9]{36}\b",
        "severity": "BLOCK"
    },
    {
        "id": "github_app_user_token",
        "name": "GitHub App User Access Token (ghu_)",
        "pattern": _prefix_pattern("app_user_token"),
        "severity": "BLOCK"
    },
    {
        "id": "github_app_installation_token",
        "name": "GitHub App Installation Token (ghs_)",
        "pattern": _prefix_pattern("app_installation_token"),
        "severity": "BLOCK"
    },
    {
        "id": "github_oauth_refresh_token",
        "name": "GitHub OAuth Refresh Token (ghr_)",
        "pattern": _prefix_pattern("oauth_refresh_token"),
        "severity": "BLOCK"
    },
    {
        "id": "gitlab_pat",
        "name": "GitLab Personal Access Token (glpat-)",
        "pattern": _prefix_pattern("pat_gitlab"),
        "severity": "BLOCK"
    },
    {
        "id": "openai_api_key",
        "name": "OpenAI / LLM API Key",
        "pattern": r"\b(sk-[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9_-]{40,})\b",
        "severity": "BLOCK"
    },
    {
        "id": "anthropic_api_key",
        "name": "Anthropic API Key",
        "pattern": r"\bsk-ant-[a-zA-Z0-9_-]{20,}\b",
        "severity": "BLOCK"
    },
    {
        "id": "private_key",
        "name": "Private Cryptographic Key",
        "pattern": r"-----BEGIN (?:RSA|OPENSSH|DSA|EC|PGP) PRIVATE KEY-----",
        "severity": "BLOCK"
    },
    {
        "id": "db_connection_url",
        "name": "Database Connection String with Password",
        "pattern": r"\b(?:postgres|postgresql|mysql|mongodb|redis):\/\/[a-zA-Z0-9_-]+:[^@\s/]+@[a-zA-Z0-9._-]+",
        "severity": "BLOCK"
    },
    {
        "id": "gitee_pat_explicit",
        "name": "Gitee Access Token",
        "pattern": r"(?i)\b(?:gitee_token|gitee_pat|access_token)\s*[:=]\s*['\"]?([a-f0-9]{32})['\"]?",
        "severity": "BLOCK"
    },
    {
        "id": "cloudflare_token",
        "name": "Cloudflare API Token",
        "pattern": r"(?i)\b(?:cloudflare_api_token|cf_api_token|cloudflare_token|cf_token)\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{40})['\"]?",
        "severity": "BLOCK"
    }
]

# --- Contraband / Bypass Tool Patterns ---
CONTRABAND_FILENAME_PATTERNS = [
    r"(?i)\b(?:" + r"v2ray|xray-core|shadowsocks|trojan-go|clash\.meta|mihomo|naiveproxy|hysteria|frpc\.ini|frps\.ini)\b",
    r"(?i)\b(?:" + r"v2ray\.exe|xray\.exe|clash\.exe|trojan\.exe|shadowsocks\.exe)\b"
]

CONTRABAND_CONTENT_PATTERNS = [
    {
        "id": "proxy_protocol_uri",
        "name": "Proxy Protocol Link",
        "pattern": r"\b(?:" + r"vmess|vless|trojan|ss|ssr):\/\/[a-zA-Z0-9+/=_-]+",
        "severity": "BLOCK"
    },
    {
        "id": "proxy_core_source",
        "name": "VPN / Bypass Tool Core Source",
        "pattern": r"(?i)\b(?:" + r"v2ray" + r"\.core|" + r"shadowsocks" + r"-rust|github\.com\/xtls\/" + r"xray" + r"-core|" + r"clash" + r"-verge-rev)\b",
        "severity": "BLOCK"
    }
]

# --- Cryptomining Patterns ---
CRYPTOMINING_PATTERNS = [
    {
        "id": "cryptominer_signature",
        "name": "Cryptomining Executable / Protocol Signature",
        "pattern": r"(?i)\b(?:" + r"xm" + r"rig|" + r"stra" + r"tum\+tcp|" + r"stra" + r"tum\+ssl|" + r"monero" + r"ocean|" + r"hash" + r"vault\.pro|" + r"support" + r"xmr)\b",
        "severity": "BLOCK"
    }
]

def mask_sensitive(text: str) -> str:
    """Mask a secret string for safe logging and display."""
    if len(text) <= 8:
        return "********"
    return text[:4] + "*" * (len(text) - 8) + text[-4:]

def scan_text_for_secrets(text: str, source_label: str = "") -> List[Dict[str, Any]]:
    """Scan arbitrary text line-by-line for leaked credentials."""
    violations = []
    lines = text.splitlines()
    for line_idx, line in enumerate(lines, 1):
        for rule in SECRET_PATTERNS:
            matches = re.finditer(rule["pattern"], line)
            for m in matches:
                matched_str = m.group(0)
                violations.append({
                    "type": "SECRET_LEAK",
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "source": source_label,
                    "line_number": line_idx,
                    "matched_sample": mask_sensitive(matched_str),
                    "message": f"[{rule['severity']}][凭据防泄漏] 检测到 {rule['name']}，禁止提交明文凭据入库！"
                })
        # Cryptomining
        for rule in CRYPTOMINING_PATTERNS:
            if re.search(rule["pattern"], line):
                violations.append({
                    "type": "CRYPTOMINING",
                    "rule_id": rule["id"],
                    "rule_name": rule["name"],
                    "severity": rule["severity"],
                    "source": source_label,
                    "line_number": line_idx,
                    "matched_sample": "[挖矿/滥用签名]",
                    "message": f"[{rule['severity']}][合规拦截] 检测到违规加密货币挖矿/CI 滥用特征！"
                })
    return violations

def scan_diff_for_secrets(diff_text: str) -> List[Dict[str, Any]]:
    """Scan git diff for secrets, inspecting newly added lines only."""
    violations = []
    current_file = "unknown"
    current_line = 0

    lines = diff_text.splitlines()
    for line in lines:
        if line.startswith("+++ b/"):
            current_file = line[6:].strip()
            ext = os.path.splitext(current_file)[1].lower()
            if ext in {".exe", ".dll", ".so", ".dylib", ".msi"}:
                violations.append({
                    "type": "BINARY_POLLUTION",
                    "rule_id": "executable_binary_block",
                    "rule_name": "可执行二进制程序拦截",
                    "severity": "BLOCK",
                    "file": current_file,
                    "line_number": 1,
                    "matched_sample": f"[二进制扩展名: {ext}]",
                    "message": f"[BLOCK][二进制污染] 检测到新增可执行文件 '{current_file}'！严禁将编译产物提交入库，请通过 Releases 附件发布或配置 .gitignore 忽略。"
                })
            continue
        elif line.startswith("@@"):
            # @@ -old,count +new_start,count @@
            m = re.search(r"\+(\d+)", line)
            if m:
                current_line = int(m.group(1)) - 1
            continue

        # Skip compliance rules definition file and test suites to avoid false-positive self-matching
        norm_file = current_file.replace("\\", "/").lower()
        if norm_file.endswith("core/compliance_guard.py") or norm_file.startswith("tests/") or "/test" in norm_file:
            continue

        if line.startswith("+") and not line.startswith("+++"):
            current_line += 1
            added_content = line[1:]
            for rule in SECRET_PATTERNS:
                matches = re.finditer(rule["pattern"], added_content)
                for match in matches:
                    matched_str = match.group(0)
                    violations.append({
                        "type": "SECRET_LEAK",
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "severity": rule["severity"],
                        "file": current_file,
                        "line_number": current_line,
                        "matched_sample": mask_sensitive(matched_str),
                        "message": f"[{rule['severity']}][凭据泄漏] 文件 '{current_file}' 第 {current_line} 行包含 {rule['name']} ({mask_sensitive(matched_str)})！"
                    })
            for rule in CRYPTOMINING_PATTERNS:
                if re.search(rule["pattern"], added_content):
                    violations.append({
                        "type": "CRYPTOMINING",
                        "rule_id": rule["id"],
                        "rule_name": rule["name"],
                        "severity": rule["severity"],
                        "file": current_file,
                        "line_number": current_line,
                        "matched_sample": "[挖矿/滥用签名]",
                        "message": f"[{rule['severity']}][合规拦截] 文件 '{current_file}' 第 {current_line} 行包含挖矿/滥用签名！"
                    })
        elif not line.startswith("-"):
            current_line += 1

    return violations

IGNORED_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".idea", ".vscode", "dist", "build", ".next", ".nuxt", "logs", ".cache", ".tmp", ".npm"}
BINARY_EXTENSIONS = {
    ".pyc", ".pyo", ".pyd", ".exe", ".dll", ".so", ".dylib", ".bin",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".zip", ".tar", ".gz", ".7z", ".pdf", ".lock"
}

def check_file_sizes(repo_path: str, platform: str = "all") -> List[Dict[str, Any]]:
    """Scan working tree files for platform size limits (Gitee: 50MB, GitHub: 100MB)."""
    violations = []
    if not os.path.exists(repo_path):
        return violations

    total_size = 0
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]

        for f in files:
            full_path = os.path.join(root, f)
            rel_path = os.path.relpath(full_path, repo_path)
            try:
                sz = os.path.getsize(full_path)
                total_size += sz

                # Check Gitee 50MB limit
                if platform in ["all", "gitee"] and sz > GITEE_MAX_FILE_BYTES:
                    mb = sz / (1024 * 1024)
                    violations.append({
                        "type": "FILE_SIZE_LIMIT",
                        "platform": "gitee",
                        "severity": "BLOCK",
                        "file": rel_path,
                        "size_bytes": sz,
                        "message": f"[BLOCK][Gitee合规] 单文件 '{rel_path}' 体积 {mb:.1f}MB 超过 Gitee 50MB 硬限制，推送到 Gitee 将失败！"
                    })

                # Check GitHub 100MB limit
                if platform in ["all", "github"] and sz > GITHUB_MAX_FILE_BYTES:
                    mb = sz / (1024 * 1024)
                    violations.append({
                        "type": "FILE_SIZE_LIMIT",
                        "platform": "github",
                        "severity": "BLOCK",
                        "file": rel_path,
                        "size_bytes": sz,
                        "message": f"[BLOCK][GitHub合规] 单文件 '{rel_path}' 体积 {mb:.1f}MB 超过 GitHub 100MB 拒绝上限！"
                    })
                elif platform in ["all", "github"] and sz > GITHUB_LFS_WARN_BYTES:
                    mb = sz / (1024 * 1024)
                    violations.append({
                        "type": "FILE_SIZE_WARN",
                        "platform": "github",
                        "severity": "WARN",
                        "file": rel_path,
                        "size_bytes": sz,
                        "message": f"[WARN][GitHub建议] 单文件 '{rel_path}' 体积 {mb:.1f}MB 超过 50MB，建议使用 Git LFS 管理。"
                    })
            except Exception:
                pass

    if platform in ["all", "gitee"] and total_size > GITEE_MAX_REPO_BYTES:
        mb = total_size / (1024 * 1024)
        violations.append({
            "type": "REPO_SIZE_LIMIT",
            "platform": "gitee",
            "severity": "WARN",
            "size_bytes": total_size,
            "message": f"[WARN][Gitee配额] 仓库总预估大小 {mb:.1f}MB 超过 Gitee 500MB 建议配额，建议精简历史或拆分库。"
        })

    return violations

def scan_contraband_tools(repo_path: str) -> List[Dict[str, Any]]:
    """Scan for forbidden proxy, VPN, bypass or penetration tooling."""
    violations = []
    if not os.path.exists(repo_path):
        return violations

    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS]

        for f in files:
            rel_path = os.path.relpath(os.path.join(root, f), repo_path)
            norm_rel = rel_path.replace("\\", "/").lower()

            # Skip compliance guard itself and test files from false-positive self matching
            if norm_rel.endswith("core/compliance_guard.py") or "/test" in norm_rel or norm_rel.startswith("tests/"):
                continue

            # Check filename patterns
            for pat in CONTRABAND_FILENAME_PATTERNS:
                if re.search(pat, f):
                    violations.append({
                        "type": "CONTRABAND_TOOL",
                        "severity": "BLOCK",
                        "file": rel_path,
                        "message": f"[BLOCK][条例合规] 文件 '{rel_path}' 疑似包含翻墙/VPN/代理绕行工具，违反国内托管条例，禁止推送到公共平台！"
                    })
                    break

            # Content check for non-binary files smaller than 1MB
            ext = os.path.splitext(f)[1].lower()
            if ext in BINARY_EXTENSIONS:
                continue

            full_path = os.path.join(root, f)
            try:
                if os.path.getsize(full_path) < 1024 * 1024:
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as file_content:
                        text = file_content.read()
                        for c_rule in CONTRABAND_CONTENT_PATTERNS:
                            if re.search(c_rule["pattern"], text):
                                violations.append({
                                    "type": "CONTRABAND_TOOL_CONTENT",
                                    "severity": c_rule["severity"],
                                    "file": rel_path,
                                    "message": f"[{c_rule['severity']}][条例合规] 文件 '{rel_path}' 包含非法代理或翻墙工具核心协议/代码特征！"
                                })
                                break
            except Exception:
                pass

    return violations

def check_identity(author_name: str, author_email: str) -> List[Dict[str, Any]]:
    """Verify identity guardrails: detect banned accounts and warn."""
    issues = []
    combined = f"{author_name} {author_email}".lower()
    if "<owner>" in combined:
        issues.append({
            "type": "BANNED_IDENTITY",
            "severity": "WARN",
            "message": "[WARN][身份警示] 检测到提交作者信息包含被封禁账号关键字 '<owner>'，强烈建议切换为主开发者身份 (<owner>)！"
        })
    return issues

def format_commit_message(
    message: str,
    agent_name: Optional[str] = None,
    agent_email: str = "<bot-email>"
) -> str:
    """Ensure standard Co-authored-by signature is appended to commit message."""
    if not agent_name:
        try:
            from core import agent_detector
            agent_name = agent_detector.get_default_agent_signature()
        except Exception:
            agent_name = "GV_AGY_Gemini-3.8-Flash"
    trimmed = message.strip()
    co_author_signature = f"Co-authored-by: {agent_name} <{agent_email}>"
    if "co-authored-by:" in trimmed.lower():
        return trimmed
    return f"{trimmed}\n\n{co_author_signature}"

def run_repo_governance_gate(repo_path: str, timeout: int = 120) -> Dict[str, Any]:
    """执行仓库自身的治理门禁（.agents/scripts/check_governance.py --strict）。"""
    script = os.path.join(repo_path, ".agents", "scripts", "check_governance.py")
    if not os.path.exists(script):
        return {"ran": False, "passed": True}
    try:
        proc = subprocess.run(
            [sys.executable, script, "--strict"],
            cwd=repo_path, capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        return {"ran": True, "passed": proc.returncode == 0, "returncode": proc.returncode,
                "stdout": (proc.stdout or "")[-4000:], "stderr": (proc.stderr or "")[-2000:]}
    except Exception as e:
        return {"ran": True, "passed": False, "returncode": -1, "stdout": "", "stderr": str(e)}

def audit_pre_commit(
    repo_path: str,
    diff_text: str = "",
    author_name: str = "",
    author_email: str = ""
) -> Dict[str, Any]:
    """Execute full pre-commit compliance audit pipeline."""
    # 1. Panic button check
    can_write, panic_msg = check_write_permission()
    if not can_write:
        return {
            "passed": False,
            "blocked": True,
            "block_reason": panic_msg,
            "violations": [{
                "type": "PANIC_BUTTON_LOCK",
                "severity": "BLOCK",
                "message": panic_msg
            }]
        }

    violations = []

    # 2. Secret leak scan on diff
    if diff_text:
        diff_violations = scan_diff_for_secrets(diff_text)
        violations.extend(diff_violations)

    # 3. Contraband tooling scan
    tool_violations = scan_contraband_tools(repo_path)
    violations.extend(tool_violations)

    # 4. Identity check
    if author_name or author_email:
        id_issues = check_identity(author_name, author_email)
        violations.extend(id_issues)

    # 5. File size checks (working directory)
    size_violations = check_file_sizes(repo_path, platform="all")
    violations.extend(size_violations)

    gate = run_repo_governance_gate(repo_path)
    if gate.get("ran") and not gate.get("passed"):
        violations.append({
            "type": "REPO_GOVERNANCE_GATE",
            "severity": "BLOCK",
            "message": "仓内治理自检未通过：" + (gate.get("stdout") or gate.get("stderr") or "check_governance.py exit != 0"),
        })

    has_block = any(v.get("severity") == "BLOCK" for v in violations)
    return {
        "passed": not has_block,
        "blocked": has_block,
        "block_reason": "; ".join([v["message"] for v in violations if v.get("severity") == "BLOCK"]) if has_block else "",
        "violations": violations
    }

# --- Pre-Adoption Repository Security Audit & Remediation Engine ---
SENSITIVE_FILE_PATTERNS = [
    (r"^\.env(\.[a-zA-Z0-9_\-]+)?$", "CONFIG_EXPOSURE", "WARN", "环境变量配置文件 (.env) 处于未忽略状态，易导致线上环境机密外泄"),
    (r".*\.(pem|key|pfx|p12|pkcs12)$", "PRIVATE_KEY_EXPOSURE", "BLOCK", "私钥或证书文件 (.pem/.key) 处于未忽略状态，存在严重凭据泄漏风险"),
    (r"^(id_rsa|id_ed25519|id_ecdsa)$", "SSH_KEY_EXPOSURE", "BLOCK", "SSH 个人私钥处于未忽略状态，严禁提交到代码仓库"),
    (r".*(credential|secret|service_account).*\.json$", "CREDENTIAL_FILE", "BLOCK", "云服务凭据 JSON 文件处于未忽略状态"),
    (r".*\.(exe|dll|so|dylib|msi)$", "BINARY_POLLUTION", "WARN", "编译生成二进制文件处于未忽略状态，会导致 Git 仓库体积膨胀"),
    (r".*\.(zip|tar\.gz|7z|rar)$", "ARCHIVE_POLLUTION", "WARN", "大型压缩包处于未忽略状态，存在逃逸审计与体积膨胀风险"),
    (r".*\.(sqlite|sqlite3|db)$", "DATABASE_FILE", "WARN", "本地数据库文件处于未忽略状态，易泄露本地业务数据")
]

def scan_git_config_credentials(repo_path: str) -> List[Dict[str, Any]]:
    """检测 .git/config 中 remote URL 内嵌的明文凭据（userinfo），并只返回掩码样本。"""
    findings: List[Dict[str, Any]] = []
    cfg_path = os.path.join(repo_path, ".git", "config")
    if not os.path.exists(cfg_path):
        return findings
    try:
        lines = open(cfg_path, "r", encoding="utf-8", errors="ignore").read().splitlines()
    except Exception:
        return findings
    pat = re.compile(r"^\s*(url|pushurl)\s*=\s*(\S+://)([^/@\s]+)@(\S+)", re.IGNORECASE)
    for idx, line in enumerate(lines, 1):
        m = pat.match(line)
        if not m:
            continue
        masked_url = f"{m.group(2)}***@{m.group(4)}"
        findings.append({
            "category": "GIT_CONFIG_CREDENTIAL",
            "severity": "BLOCK",
            "file": ".git/config",
            "line": idx,
            "message": "[BLOCK][凭据泄漏] remote URL 内含明文 userinfo/Token；任何能读取 .git/config 的进程或工具都可获取",
            "sample": masked_url,
            "suggested_action": "switch_remote_to_ssh_or_credential_helper",
        })
    return findings


def audit_repository_readiness(repo_path: str) -> Dict[str, Any]:
    """Execute pre-adoption compliance audit on a repository before adding to managed registry."""
    norm_path = os.path.normpath(os.path.abspath(repo_path))
    if not os.path.exists(norm_path):
        return {"success": False, "error": f"仓库路径不存在: {norm_path}"}
        
    findings = []
    scanned_files_count = 0
    findings.extend(scan_git_config_credentials(norm_path))
    gitignore_path = os.path.join(norm_path, ".gitignore")
    
    # 1. 扫描未忽略的高危文件
    skip_scan_dirs = {".git", "node_modules", ".venv", "venv", "dist", "build", ".cache", "__pycache__"}
    
    for root, dirs, files in os.walk(norm_path):
        dirs[:] = [d for d in dirs if d.lower() not in skip_scan_dirs]
        for f in files:
            scanned_files_count += 1
            rel_file = os.path.relpath(os.path.join(root, f), norm_path).replace("\\", "/")
            
            # 校验是否命中敏感文件名规则
            f_lower = f.lower()
            for pat, cat, sev, msg in SENSITIVE_FILE_PATTERNS:
                if re.match(pat, f_lower, re.IGNORECASE):
                    # 检查 Git 跟踪状态与 .gitignore 固化状态
                    is_tracked = False
                    is_local_ignored = False
                    is_global_ignored = False
                    import subprocess

                    # 1. 检查是否已被 git 缓存跟踪 (极其危险)
                    try:
                        ls_chk = subprocess.run(
                            ["git", "ls-files", "--error-unmatch", rel_file],
                            cwd=norm_path,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            timeout=3
                        )
                        is_tracked = (ls_chk.returncode == 0)
                    except Exception:
                        is_tracked = False

                    # 2. 检查 git check-ignore 来源
                    try:
                        chk = subprocess.run(
                            ["git", "check-ignore", "-v", rel_file],
                            cwd=norm_path,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            timeout=3
                        )
                        if chk.returncode == 0:
                            v_out = chk.stdout.decode("utf-8", errors="ignore").strip()
                            # 规则源文件判定: 项目本地 .gitignore 还是全局 .gitignore_global
                            if v_out.startswith(".gitignore:") or os.path.normpath(gitignore_path) in os.path.normpath(v_out.split(":")[0]):
                                is_local_ignored = True
                            else:
                                is_global_ignored = True
                    except Exception:
                        pass

                    # 判定违规与脱敏需求
                    needs_finding = False
                    finding_sev = sev
                    finding_msg = msg

                    if is_tracked:
                        needs_finding = True
                        finding_sev = "BLOCK"
                        finding_msg = f"敏感文件已被 Git 索引跟踪，存在立即泄漏风险，需移出缓存并隔离: '{rel_file}'"
                    elif not is_local_ignored and not is_global_ignored:
                        needs_finding = True
                        finding_sev = sev
                        finding_msg = f"{msg}: '{rel_file}'"
                    elif not is_local_ignored and is_global_ignored:
                        # 仅全局忽略，项目本身尚未固化
                        needs_finding = True
                        finding_sev = "WARN"
                        finding_msg = f"项目未固化脱敏规则 (仅依赖本机全局防护): '{rel_file}'，协作者拉取将面临泄漏风险"

                    if needs_finding:
                        suggested_rule = rel_file if "/" not in rel_file else f"/{rel_file}"
                        if f_lower.startswith(".env"):
                            suggested_rule = ".env*\n!.env.example"
                        elif pat.endswith(")$"):
                            ext = f_lower.split(".")[-1]
                            suggested_rule = f"*.{ext}"
                            
                        findings.append({
                            "category": cat,
                            "severity": finding_sev,
                            "file": rel_file,
                            "line": 1,
                            "message": f"[{finding_sev}] {finding_msg}",
                            "sample": f,
                            "suggested_action": "add_gitignore",
                            "suggested_pattern": suggested_rule,
                            "remediation_label": "一键将该类文件写入 .gitignore 隔离"
                        })
                    break

            # 2. 抽样扫描代码源文件硬编码机密 (限常规脚本/配置文件，单文件限 300KB)
            ext = os.path.splitext(f_lower)[1]
            if ext in {".py", ".js", ".ts", ".json", ".yaml", ".yml", ".toml", ".sh", ".env", ".cfg", ".ini", ".conf"}:
                f_full = os.path.join(root, f)
                try:
                    sz = os.path.getsize(f_full)
                    if 0 < sz < 300 * 1024:
                        with open(f_full, "r", encoding="utf-8", errors="ignore") as fp:
                            content = fp.read()
                            secret_hits = scan_text_for_secrets(content, rel_file)
                            for hit in secret_hits:
                                findings.append({
                                    "category": "HARDCODED_SECRET",
                                    "severity": hit.get("severity", "BLOCK"),
                                    "file": rel_file,
                                    "line": hit.get("line_number", 1),
                                    "message": f"[{hit.get('severity', 'BLOCK')}] 源码硬编码机密: {hit.get('rule_name')} (位置: {rel_file}:{hit.get('line_number')})",
                                    "sample": hit.get("matched_sample", ""),
                                    "suggested_action": "vault_migrate",
                                    "suggested_env_var": "API_SECRET_TOKEN",
                                    "remediation_label": "转入 Git-Vault DPAPI 硬件保险箱，代码改用环境变量读取"
                                })
                except Exception:
                    pass

    # 3. 违规穿透工具扫描
    contraband_hits = scan_contraband_tools(norm_path)
    for c in contraband_hits:
        findings.append({
            "category": "CONTRABAND_TOOL",
            "severity": c.get("severity", "BLOCK"),
            "file": c.get("file", ""),
            "line": 1,
            "message": c.get("message", ""),
            "sample": "[违规工具二进制]",
            "suggested_action": "delete_or_ignore",
            "suggested_pattern": c.get("file", ""),
            "remediation_label": "清理移除违规二进制工具"
        })

    # 计算安全健康分与状态评级
    block_count = sum(1 for f in findings if f["severity"] == "BLOCK")
    warn_count = sum(1 for f in findings if f["severity"] == "WARN")
    
    if block_count > 0:
        status = "BLOCK"
        score = max(20, 100 - block_count * 30 - warn_count * 10)
    elif warn_count > 0:
        status = "WARN"
        score = max(60, 100 - warn_count * 15)
    else:
        status = "SAFE"
        score = 100

    desensitization_steps = []
    if any(f.get("suggested_action") == "add_gitignore" for f in findings):
        desensitization_steps.append("隔离高危文件: 一键将暴露的 .env、二进制生成物与密钥写入项目专属 .gitignore")
    if any(f.get("suggested_action") == "vault_migrate" for f in findings):
        desensitization_steps.append("迁移硬编码密钥: 一键将源码明文 Key 转存入 Windows DPAPI 硬件加密库，代码替换为环境变量读取")
    if any(f.get("suggested_action") == "delete_or_ignore" for f in findings):
        desensitization_steps.append("清理违规二进制: 从工作区删除违规穿透或挖矿特征工具")

    # 聚合可自动执行的脱敏建议
    remediations_map = {}
    for f in findings:
        if f.get("suggested_action") == "add_gitignore" and f.get("suggested_pattern"):
            pat = f["suggested_pattern"]
            if pat not in remediations_map:
                clean_pats = [p.strip() for p in pat.split("\n") if p.strip() and not p.strip().startswith("!")]
                remediations_map[pat] = {
                    "type": "add_gitignore",
                    "patterns": clean_pats,
                    "target": f.get("file", ""),
                    "action_summary": f.get("remediation_label", "一键写入 .gitignore 隔离")
                }
    remediations = list(remediations_map.values())

    return {
        "success": True,
        "repo_path": norm_path,
        "status": status,
        "score": score,
        "summary": {
            "scanned_files": scanned_files_count,
            "total_findings": len(findings),
            "total_violations": len(findings),
            "block_count": block_count,
            "warn_count": warn_count,
            "remediations_available": len(remediations)
        },
        "findings": findings,
        "remediations": remediations,
        "desensitization_steps": desensitization_steps,
        "has_gitignore": os.path.exists(gitignore_path)
    }

def remediate_gitignore_rules(repo_path: str, patterns: List[str]) -> Dict[str, Any]:
    """Append remediation patterns to repository .gitignore and optionally untrack cached files."""
    norm_path = os.path.normpath(os.path.abspath(repo_path))
    if not os.path.exists(norm_path):
        return {"success": False, "error": f"路径不存在: {norm_path}"}
        
    gitignore_file = os.path.join(norm_path, ".gitignore")
    existing_content = ""
    if os.path.exists(gitignore_file):
        try:
            with open(gitignore_file, "r", encoding="utf-8") as f:
                existing_content = f.read()
        except Exception:
            existing_content = ""

    clean_patterns = []
    existing_lines = {l.strip() for l in existing_content.splitlines()}
    
    for pat in patterns:
        for single in pat.split("\n"):
            s = single.strip()
            if s and s not in existing_lines:
                clean_patterns.append(s)
                existing_lines.add(s)
                
    if not clean_patterns:
        return {"success": True, "message": "规则已存在于 .gitignore，无需重复添加", "added_count": 0}

    append_header = "\n\n# --- Git-Vault Security Remediation (自动脱敏隔离规则) ---\n"
    new_text = existing_content
    if "# --- Git-Vault Security Remediation" not in existing_content:
        new_text += append_header
    else:
        new_text += "\n"
        
    new_text += "\n".join(clean_patterns) + "\n"
    
    try:
        with open(gitignore_file, "w", encoding="utf-8") as f:
            f.write(new_text)
            
        # 尝试将新规则中的文件从暂存区 untrack (git rm --cached)
        untracked_logs = []
        import subprocess
        for pat in clean_patterns:
            if not pat.startswith("#") and not pat.startswith("!"):
                try:
                    subprocess.run(
                        ["git", "rm", "-r", "--cached", "--ignore-unmatch", pat],
                        cwd=norm_path,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        timeout=5
                    )
                    untracked_logs.append(f"untracked {pat}")
                except Exception:
                    pass
                    
        return {
            "success": True,
            "message": f"成功将 {len(clean_patterns)} 条安全脱敏规则写入 .gitignore 并解除版本跟踪",
            "added_count": len(clean_patterns),
            "patterns": clean_patterns,
            "added_patterns": clean_patterns,
            "untracked_logs": untracked_logs
        }
    except Exception as e:
        return {"success": False, "error": f"写入 .gitignore 失败: {str(e)}"}
