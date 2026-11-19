# core/git_engine.py

# Antigravity Git-Vault - Core Git Engine

import subprocess

import os

import re

import json

import time

import copy

import threading

import queue

from datetime import datetime

from concurrent.futures import ThreadPoolExecutor

from typing import Dict, List, Any, Optional, Callable, Tuple

from core import compliance_guard, network_router
from core.redaction import redact, sanitize_url_credentials



CONFIG_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config")

MANAGED_REPOS_FILE = os.path.join(CONFIG_DIR, "managed_repos.json")

SYNC_STATE_FILE = os.path.join(CONFIG_DIR, "sync_state.json")

def load_sync_state() -> Dict[str, Any]:
    if not os.path.exists(SYNC_STATE_FILE):
        return {}
    try:
        with open(SYNC_STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_sync_state(state: Dict[str, Any]) -> bool:
    try:
        os.makedirs(os.path.dirname(SYNC_STATE_FILE), exist_ok=True)
        with open(SYNC_STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=False, indent=2)
        return True
    except Exception:
        return False

def update_repo_sync_state(repo_path: str, url: str, head_commit: str, branch: str = "main"):
    norm_path = os.path.normpath(repo_path).lower()
    state = load_sync_state()
    if norm_path not in state:
        state[norm_path] = {
            "path": repo_path,
            "branch": branch,
            "head": head_commit,
            "synced_targets": {},
            "last_sync_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    state[norm_path]["head"] = head_commit
    state[norm_path]["branch"] = branch
    state[norm_path]["last_sync_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    state[norm_path].setdefault("synced_targets", {})[sanitize_url_credentials(url)] = head_commit
    save_sync_state(state)

def update_local_tracking_refs(repo_path: str, url: str, branch: str, head_commit: str):
    """
    更新本地 refs/remotes/<remote_name>/<branch> 到指定 commit，消除因直接向 URL 推送导致的本地追踪分支落后。
    """
    if not head_commit:
        return
    norm_path = os.path.normpath(repo_path)
    remotes_res = run_git(["remote", "-v"], cwd=norm_path, timeout=5)
    if not remotes_res["success"] or not remotes_res["stdout"]:
        return

    clean_u = url.rstrip("/").rstrip(".git").lower()
    for line in remotes_res["stdout"].splitlines():
        parts = line.strip().split()
        if len(parts) >= 2:
            r_name, r_url = parts[0], parts[1]
            clean_r = r_url.rstrip("/").rstrip(".git").lower()
            if (clean_r in clean_u or clean_u in clean_r or
                ("github.com" in clean_r and "github.com" in clean_u) or
                ("gitee.com" in clean_r and "gitee.com" in clean_u) or
                ("gitlab.com" in clean_r and "gitlab.com" in clean_u)):
                run_git(["update-ref", f"refs/remotes/{r_name}/{branch}", head_commit], cwd=norm_path, timeout=5)


def get_repo_ahead_behind(repo_path: str, branch: Optional[str] = None) -> str:
    """
    计算本地分支与追踪远端分支的真实提前/落后计数 (+ahead/-behind)。
    优先 @{u}，次选 origin/{branch}，再选 github/gitee/gitlab/{branch}。
    """
    norm_path = os.path.normpath(repo_path)
    if not branch:
        b_res = run_git(["branch", "--show-current"], cwd=norm_path)
        branch = b_res["stdout"].strip() if b_res["success"] else "main"

    # 1. 尝试 upstream tracking @{u}
    rev_res = run_git(["rev-list", "--left-right", "--count", f"{branch}...@{{u}}"], cwd=norm_path, timeout=3)
    if rev_res["success"] and rev_res["stdout"]:
        parts = rev_res["stdout"].split()
        if len(parts) == 2:
            return f"+{parts[0]}/-{parts[1]}"

    # 2. 尝试 refs/remotes/origin/{branch}
    rev_res = run_git(["rev-list", "--left-right", "--count", f"{branch}...refs/remotes/origin/{branch}"], cwd=norm_path, timeout=3)
    if rev_res["success"] and rev_res["stdout"]:
        parts = rev_res["stdout"].split()
        if len(parts) == 2:
            return f"+{parts[0]}/-{parts[1]}"

    # 3. 尝试探测多端远程分支
    for r_name in ["github", "gitee", "gitlab"]:
        rev_res = run_git(["rev-list", "--left-right", "--count", f"{branch}...refs/remotes/{r_name}/{branch}"], cwd=norm_path, timeout=3)
        if rev_res["success"] and rev_res["stdout"]:
            parts = rev_res["stdout"].split()
            if len(parts) == 2:
                return f"+{parts[0]}/-{parts[1]}"

    return "0/0"

# In-Memory Cache for Repositories List (30s TTL for Instant Sub-Millisecond Rendering)

_REPOS_CACHE: Dict[str, Any] = {

    "data_all": None,

    "data_mine": None,

    "timestamp": 0.0,

    "ttl": 30.0

}

_CACHE_LOCK = threading.Lock()



def invalidate_repos_cache():

    """Invalidate in-memory repositories cache."""

    with _CACHE_LOCK:

        _REPOS_CACHE["data_all"] = None

        _REPOS_CACHE["data_mine"] = None

        _REPOS_CACHE["timestamp"] = 0.0





def run_git(args: List[str], cwd: Optional[str] = None, timeout: int = 20) -> Dict[str, Any]:

    cmd = ["git"] + args

    env = os.environ.copy()

    env["GIT_TERMINAL_PROMPT"] = "0"

    env["GIT_PAGER"] = "cat"

    env["GCM_INTERACTIVE"] = "never"

    env["GIT_ASKPASS"] = "echo"

    env["SSH_ASKPASS"] = "echo"

    try:

        proc = subprocess.run(

            cmd,

            cwd=cwd,

            env=env,

            stdout=subprocess.PIPE,

            stderr=subprocess.PIPE,

            text=True,

            encoding="utf-8",

            errors="replace",

            timeout=timeout

        )

        return {

            "success": proc.returncode == 0,

            "returncode": proc.returncode,

            "stdout": proc.stdout.rstrip(),

            "stderr": proc.stderr.rstrip()

        }

    except subprocess.TimeoutExpired:

        return {

            "success": False,

            "returncode": -1,

            "stdout": "",

            "stderr": f"Command timed out after {timeout}s: {' '.join(cmd)}"

        }

    except Exception as e:

        return {

            "success": False,

            "returncode": -2,

            "stdout": "",

            "stderr": str(e)

        }



def get_identity(cwd: Optional[str] = None) -> Dict[str, Any]:

    if cwd:
        name_res = run_git(["config", "user.name"], cwd=cwd)
        email_res = run_git(["config", "user.email"], cwd=cwd)
    else:
        name_res = run_git(["config", "--global", "user.name"])
        email_res = run_git(["config", "--global", "user.email"])

    helper_res = run_git(["config", "--global", "credential.helper"])

    return {

        "name": name_res["stdout"] if name_res["success"] else "",

        "email": email_res["stdout"] if email_res["success"] else "",

        "credential_helper": helper_res["stdout"] if helper_res["success"] else ""

    }



def set_identity(name: str, email: str, scope: str = "global", cwd: Optional[str] = None) -> Dict[str, Any]:

    logs = []

    scope_arg = "--global" if scope == "global" else "--local"

    if name:

        res = run_git(["config", scope_arg, "user.name", name], cwd=cwd)

        logs.append(f"Set {scope_arg} user.name: {'OK' if res['success'] else res['stderr']}")

    if email:

        res = run_git(["config", scope_arg, "user.email", email], cwd=cwd)

        logs.append(f"Set {scope_arg} user.email: {'OK' if res['success'] else res['stderr']}")

    return {"success": True, "logs": logs}

PROFILES_FILE = os.path.join(CONFIG_DIR, "git_profiles.json")

DEFAULT_GIT_PROFILES = [
    {
        "id": "github",
        "label": "GitHub",
        "name": "<owner>",
        "email": "<owner>@users.noreply.github.com",
        "platform": "github",
        "builtin": True
    },
    {
        "id": "gitlab",
        "label": "GitLab",
        "name": "<owner>",
        "email": "<owner>@users.noreply.gitlab.com",
        "platform": "gitlab",
        "builtin": True
    },
    {
        "id": "gitee",
        "label": "Gitee",
        "name": "<owner>",
        "email": "<owner>@users.noreply.gitee.com",
        "platform": "gitee",
        "builtin": True
    },
    {
        "id": "agent",
        "label": "GV_AGY_Gemini-2.5-Pro",
        "name": "GV_AGY_Gemini-2.5-Pro",
        "email": "<bot-email>",
        "platform": "agent",
        "builtin": True
    }
]


def load_git_profiles() -> Dict[str, Any]:
    if not os.path.exists(PROFILES_FILE):
        data = {
            "default_id": "github",
            "active_id": "github",
            "profiles": list(DEFAULT_GIT_PROFILES)
        }
        save_git_profiles_config(data)
        return data
    try:
        with open(PROFILES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            existing_ids = {p.get("id") for p in data.get("profiles", [])}
            for d in DEFAULT_GIT_PROFILES:
                if d["id"] not in existing_ids:
                    data.setdefault("profiles", []).append(d)
            if "default_id" not in data:
                data["default_id"] = "github"
            if "active_id" not in data:
                data["active_id"] = "github"
            changed = False
            for p in data.get("profiles", []):
                lbl = p.get("label", "")
                if " (默认)" in lbl or "(默认)" in lbl:
                    p["label"] = lbl.replace(" (默认)", "").replace("(默认)", "").strip()
                    changed = True
            if changed:
                save_git_profiles_config(data)
            return data
    except Exception:
        return {"default_id": "github", "active_id": "github", "profiles": list(DEFAULT_GIT_PROFILES)}


def set_default_git_profile(profile_id: str) -> Dict[str, Any]:
    data = load_git_profiles()
    target = None
    for p in data.get("profiles", []):
        if p.get("id") == profile_id:
            target = p
            break
    if not target:
        return {"success": False, "error": f"Profile '{profile_id}' not found"}
    data["default_id"] = profile_id
    save_git_profiles_config(data)
    return {"success": True, "default_id": profile_id, "profile": target}


def save_git_profiles_config(data: Dict[str, Any]) -> None:
    os.makedirs(CONFIG_DIR, exist_ok=True)
    with open(PROFILES_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)


def add_or_update_git_profile(label: str, name: str, email: str, profile_id: Optional[str] = None) -> Dict[str, Any]:
    data = load_git_profiles()
    profiles = data.get("profiles", [])
    if not profile_id:
        profile_id = f"custom_{int(time.time())}"
        new_prof = {
            "id": profile_id,
            "label": label.strip() or name.strip(),
            "name": name.strip(),
            "email": email.strip(),
            "platform": "custom",
            "builtin": False
        }
        profiles.append(new_prof)
    else:
        for p in profiles:
            if p.get("id") == profile_id:
                p["label"] = label.strip() or name.strip()
                p["name"] = name.strip()
                p["email"] = email.strip()
                break
    data["profiles"] = profiles
    save_git_profiles_config(data)
    return {"success": True, "id": profile_id, "profiles": profiles}


def delete_git_profile(profile_id: str) -> Dict[str, Any]:
    data = load_git_profiles()
    profiles = [p for p in data.get("profiles", []) if p.get("id") != profile_id or p.get("builtin", False)]
    data["profiles"] = profiles
    if data.get("active_id") == profile_id:
        data["active_id"] = "github"
    save_git_profiles_config(data)
    return {"success": True, "profiles": profiles}


def set_active_git_profile(profile_id: str, scope: str = "global", cwd: Optional[str] = None) -> Dict[str, Any]:
    data = load_git_profiles()
    target = None
    for p in data.get("profiles", []):
        if p.get("id") == profile_id:
            target = p
            break
    if not target:
        return {"success": False, "error": f"Profile '{profile_id}' not found"}

    set_identity(target["name"], target["email"], scope=scope, cwd=cwd)
    data["active_id"] = profile_id
    save_git_profiles_config(data)
    return {"success": True, "active_id": profile_id, "profile": target}




def load_managed_repos_config() -> Dict[str, Any]:

    default_cfg = {
        "managed_repos": [],
        "ignored_paths": [],
        "custom_identifiers": [],
        "filter_only_mine": True
    }

    if not os.path.exists(MANAGED_REPOS_FILE):
        data = default_cfg
    else:
        try:
            with open(MANAGED_REPOS_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = default_cfg

    # Ensure git-vault itself is always auto-managed if located in a Git repository
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if os.path.exists(os.path.join(base_dir, ".git")):
        norm_base = os.path.normpath(base_dir)
        existing_paths = {os.path.normpath(r.get("path", "")).lower() for r in data.get("managed_repos", [])}
        if norm_base.lower() not in existing_paths:
            data.setdefault("managed_repos", []).append({
                "path": norm_base,
                "name": "tools/git-vault",
                "is_my_repo": True,
                "owner": "<owner>",
                "added_by": "auto"
            })
            save_managed_repos_config(data)

    return data



def save_managed_repos_config(config: Dict[str, Any]) -> bool:

    try:

        os.makedirs(os.path.dirname(MANAGED_REPOS_FILE), exist_ok=True)

        with open(MANAGED_REPOS_FILE, "w", encoding="utf-8") as f:

            json.dump(config, f, indent=2, ensure_ascii=False)

        return True

    except Exception:

        return False





def get_repo_branch_fast(repo_path: str) -> str:

    """Read branch directly from .git/HEAD in <0.1ms."""

    head_file = os.path.join(repo_path, ".git", "HEAD")

    if os.path.exists(head_file):

        try:

            with open(head_file, "r", encoding="utf-8", errors="ignore") as f:

                head_content = f.read().strip()

            if head_content.startswith("ref: refs/heads/"):

                return head_content.replace("ref: refs/heads/", "")

            return head_content[:8]

        except Exception:

            pass

    return "main"



def sanitize_url_credentials(url: str) -> str:
    """隐藏 URL userinfo 中的账号/Token，仅保留协议、主机与路径。"""
    if not url:
        return url
    return re.sub(r"(://)[^/@\s]+@", r"\1***@", str(url))


def sanitize_remotes(remotes: Dict[str, Any]) -> Dict[str, Any]:
    """用于 API/MCP 输出：脱敏 fetch_url 与 push_urls，组件内部同步仍用原始 URL。"""
    if not isinstance(remotes, dict):
        return remotes
    out = dict(remotes)
    if out.get("fetch_url"):
        out["fetch_url"] = sanitize_url_credentials(out["fetch_url"])
    if isinstance(out.get("push_urls"), list):
        out["push_urls"] = [sanitize_url_credentials(u) for u in out["push_urls"]]
    return out


def get_repo_remotes_fast(repo_path: str) -> Dict[str, Any]:

    """Pure-file disk parser for .git/config, taking <1ms instead of 200ms subprocess."""

    config_file = os.path.join(repo_path, ".git", "config")

    fetch_url = ""

    push_urls = []

    if os.path.exists(config_file):

        try:

            with open(config_file, "r", encoding="utf-8", errors="ignore") as f:

                cfg_text = f.read()

            for m in re.finditer(r'\[remote\s+"([^"]+)"\](.*?)(?=\n\[|\Z)', cfg_text, re.DOTALL):

                rem_body = m.group(2)

                urls = re.findall(r'url\s*=\s*([^\r\n]+)', rem_body)

                pushs = re.findall(r'pushurl\s*=\s*([^\r\n]+)', rem_body)

                if urls and not fetch_url:

                    fetch_url = urls[0].strip()

                for u in (pushs or urls):

                    clean_u = u.strip()

                    if clean_u and clean_u not in push_urls:

                        push_urls.append(clean_u)

        except Exception:

            pass



    # Fallback to git subprocess only if config parsing yielded nothing

    if not fetch_url and not push_urls:

        return get_repo_remotes(repo_path)



    has_github = any("github.com" in u for u in push_urls)

    has_gitee = any("gitee.com" in u for u in push_urls)

    has_gitlab = any("gitlab.com" in u for u in push_urls)



    return {

        "fetch_url": fetch_url,

        "push_urls": push_urls,

        "is_triple_synced": has_github and has_gitee and has_gitlab,

        "has_github": has_github,

        "has_gitee": has_gitee,

        "has_gitlab": has_gitlab

    }



def get_user_identifiers() -> set:

    idents = set()

    ident = get_identity()

    if ident.get("name"):

        idents.add(ident["name"].strip().lower())

    if ident.get("email"):

        em = ident["email"].strip().lower()

        idents.add(em)

        if "@" in em:

            idents.add(em.split("@")[0].lower())

            

    try:

        from core import credential_vault

        accs = credential_vault.list_accounts_masked()

        for a in accs:

            if a.get("username"):

                idents.add(a["username"].strip().lower())

    except Exception:

        pass

        

    cfg = load_managed_repos_config()

    for ci in cfg.get("custom_identifiers", []):

        if ci.strip():

            idents.add(ci.strip().lower())

            

    for k in ["<owner>", "<owner>", "<owner>", "<owner>"]:

        idents.add(k)

        

    return idents



def detect_repo_ownership(repo_path: str, my_identifiers: Optional[set] = None, remotes_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:

    if my_identifiers is None:

        my_identifiers = get_user_identifiers()

        

    if remotes_data is None:

        remotes_data = get_repo_remotes_fast(repo_path)

    urls = []

    if remotes_data.get("fetch_url"):

        urls.append(remotes_data["fetch_url"])

    if remotes_data.get("push_url"):

        urls.append(remotes_data["push_url"])

    for r_urls in remotes_data.get("remotes", {}).values():

        if isinstance(r_urls, dict):

            if r_urls.get("fetch"): urls.append(r_urls["fetch"])

            if r_urls.get("push"): urls.append(r_urls["push"])

        elif isinstance(r_urls, list):

            urls.extend(r_urls)

            

    urls = list(dict.fromkeys([u.strip() for u in urls if u and u.strip()]))

    

    # 纯本地原创仓库 (未绑定远程源)

    if not urls:

        return {

            "is_my_repo": True,

            "owner": "本地原创",

            "type": "local_original",

            "label": "我的仓库 · 本地原创",

            "reason": "本地自建原创仓库 (未配置远程源)"

        }

        

    matched_owners = set()

    extracted_owners = []

    

    for url in urls:

        m = re.search(r"[:/]([a-zA-Z0-9_\-\.]+)/[a-zA-Z0-9_\-\.]+(?:\.git)?$", url)

        if m:

            owner = m.group(1).strip()

            extracted_owners.append(owner)

            if owner.lower() in my_identifiers:

                matched_owners.add(owner)

        else:

            for ident in my_identifiers:

                if f"/{ident}/" in url.lower() or f":{ident}/" in url.lower():

                    matched_owners.add(ident)

                    

    if matched_owners:

        owner_name = sorted(list(matched_owners))[0]

        is_banned_523 = ("<owner>" in [o.lower() for o in matched_owners])

        if is_banned_523:

            return {

                "is_my_repo": True,

                "owner": "<owner>",

                "type": "remote_match",

                "needs_migration": True,

                "label": "需迁移远端 (<owner> 已封禁)",

                "reason": "远程源仍指向被封禁账号 <owner>，无法推送，可一键转移至 <owner>"

            }

        return {

            "is_my_repo": True,

            "owner": owner_name,

            "type": "remote_match",

            "needs_migration": False,

            "label": f"我的仓库 · {owner_name}",

            "reason": f"远程源匹配个人/组织账号: {owner_name}"

        }

        

    # 若远程未匹配，再核验最近提交作者

    log_res = run_git(["log", "-3", "--format=%an|%ae"], cwd=repo_path)

    if log_res["success"] and log_res["stdout"]:

        for line in log_res["stdout"].splitlines():

            parts = line.strip().split("|")

            author_name = parts[0].strip().lower() if len(parts) > 0 else ""

            author_email = parts[1].strip().lower() if len(parts) > 1 else ""

            if author_name in my_identifiers or author_email in my_identifiers:

                return {

                    "is_my_repo": True,

                    "owner": parts[0],

                    "type": "author_match",

                    "label": f"我的仓库 · {parts[0]}",

                    "reason": f"提交历史匹配本人 Author: {parts[0]}"

                }

                

    # 否则判定为第三方下载仓库

    third_party_owner = extracted_owners[0] if extracted_owners else "外部开源"

    return {

        "is_my_repo": False,

        "owner": third_party_owner,

        "type": "third_party",

        "label": f"第三方开源 · {third_party_owner}",

        "reason": f"第三方克隆/下载项目 (Owner: {third_party_owner})"

    }



_health_cache = None

_health_cache_timestamp = 0.0

_health_cache_lock = threading.Lock()

HEALTH_CACHE_TTL = 60.0  # 60 秒全局安全防抖缓存，彻底杜绝短时高频 SSH 外部连接与风控



def check_platforms_health(force: bool = False) -> Dict[str, Any]:

    global _health_cache, _health_cache_timestamp

    now = time.time()

    if not force and _health_cache is not None and (now - _health_cache_timestamp < HEALTH_CACHE_TTL):

        cached = copy.deepcopy(_health_cache)

        cached["_cached"] = True

        cached["_cache_age_seconds"] = round(now - _health_cache_timestamp, 1)

        return cached



    with _health_cache_lock:

        now = time.time()

        if not force and _health_cache is not None and (now - _health_cache_timestamp < HEALTH_CACHE_TTL):

            cached = copy.deepcopy(_health_cache)

            cached["_cached"] = True

            cached["_cache_age_seconds"] = round(now - _health_cache_timestamp, 1)

            return cached



        # 联动凭据库

        vault_accounts = {}

        try:

            from core import credential_vault

            for acc in credential_vault.list_accounts_masked():

                p = acc.get("platform")

                if p and acc.get("has_token") and not acc.get("expiry_info", {}).get("is_expired", False):

                    vault_accounts[p] = acc

        except Exception:

            pass



        def probe_github():

            try:

                gh = subprocess.run(

                    ["ssh", "-T", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=2", "git@github.com"],

                    stdout=subprocess.PIPE,

                    stderr=subprocess.PIPE,

                    text=True,

                    encoding="utf-8",

                    errors="replace",

                    timeout=4

                )

                msg = (gh.stdout + gh.stderr).strip()

                if "successfully authenticated" in msg:

                    user_match = re.search(r"Hi ([\w-]+)!", msg)

                    user_name = user_match.group(1) if user_match else "OK"

                    return {"status": "authenticated", "user": user_name, "protocol": "SSH", "raw": msg}

                elif "github" in vault_accounts:

                    acc = vault_accounts["github"]

                    return {"status": "authenticated", "user": acc.get("username", "Token"), "protocol": "HTTPS", "raw": "HTTPS Token 凭据有效"}

                elif "Permission denied" in msg:

                    return {"status": "denied", "user": None, "protocol": "SSH", "raw": "Permission denied (publickey)"}

                else:

                    return {"status": "reachable", "user": None, "protocol": "UNKNOWN", "raw": msg[:100]}

            except Exception as e:

                if "github" in vault_accounts:

                    acc = vault_accounts["github"]

                    return {"status": "authenticated", "user": acc.get("username", "Token"), "protocol": "HTTPS", "raw": "HTTPS Token 凭据有效"}

                return {"status": "error", "user": None, "protocol": "ERROR", "raw": str(e)}



        def probe_gitee():

            try:

                ge = subprocess.run(

                    ["ssh", "-T", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=2", "git@gitee.com"],

                    stdout=subprocess.PIPE,

                    stderr=subprocess.PIPE,

                    text=True,

                    encoding="utf-8",

                    errors="replace",

                    timeout=4

                )

                msg = (ge.stdout + ge.stderr).strip()

                if "successfully authenticated" in msg:

                    user_match = re.search(r"Hi ([\w-]+)!", msg)

                    user_name = user_match.group(1) if user_match else "OK"

                    return {"status": "authenticated", "user": user_name, "protocol": "SSH", "raw": msg}

                elif "gitee" in vault_accounts:

                    acc = vault_accounts["gitee"]

                    return {"status": "authenticated", "user": acc.get("username", "Token"), "protocol": "HTTPS", "raw": "HTTPS Token 凭据有效且已激活"}

                elif "Permission denied" in msg:

                    return {"status": "denied", "user": None, "protocol": "SSH", "raw": "Permission denied (Need to add SSH Key or use HTTPS)"}

                else:

                    return {"status": "reachable", "user": None, "protocol": "UNKNOWN", "raw": msg[:100]}

            except Exception as e:

                if "gitee" in vault_accounts:

                    acc = vault_accounts["gitee"]

                    return {"status": "authenticated", "user": acc.get("username", "Token"), "protocol": "HTTPS", "raw": "HTTPS Token 凭据有效且已激活"}

                return {"status": "error", "user": None, "protocol": "ERROR", "raw": str(e)}



        def probe_gitlab():

            try:

                gl = subprocess.run(

                    ["ssh", "-T", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=4", "git@gitlab.com"],

                    stdout=subprocess.PIPE,

                    stderr=subprocess.PIPE,

                    text=True,

                    encoding="utf-8",

                    errors="replace",

                    timeout=6

                )

                msg = (gl.stdout + gl.stderr).strip()

                if "Welcome to GitLab" in msg:

                    m = re.search(r"Welcome to GitLab, @([a-zA-Z0-9_\-\.]+)", msg)

                    user = m.group(1) if m else "<owner>"

                    return {"status": "authenticated", "user": user, "protocol": "SSH", "raw": msg}

                elif "gitlab" in vault_accounts:

                    acc = vault_accounts["gitlab"]

                    return {"status": "authenticated", "user": acc.get("username", "Token"), "protocol": "HTTPS", "raw": "HTTPS Token 凭据有效"}

                elif "Permission denied" in msg:

                    return {"status": "denied", "user": None, "protocol": "SSH", "raw": "Permission denied (Need SSH Key or HTTPS)"}

                elif "Connection closed" in msg or "timed out" in msg or "400 Bad Request" in msg or "refused" in msg:

                    raw_desc = "Cloudflare / 443 备用通道受网络阻断 (400 Bad Request)" if ("400 Bad Request" in msg or "Connection closed" in msg) else msg[:100]

                    return {"status": "network_blocked", "user": None, "protocol": "SSH", "raw": raw_desc}

                else:

                    return {"status": "reachable", "user": None, "protocol": "UNKNOWN", "raw": msg[:100]}

            except Exception as e:

                if "gitlab" in vault_accounts:

                    acc = vault_accounts["gitlab"]

                    return {"status": "authenticated", "user": acc.get("username", "Token"), "protocol": "HTTPS", "raw": "HTTPS Token 凭据有效"}

                return {"status": "error", "user": None, "protocol": "ERROR", "raw": str(e)}



        results = {}

        with ThreadPoolExecutor(max_workers=3) as executor:

            fut_gh = executor.submit(probe_github)

            fut_ge = executor.submit(probe_gitee)

            fut_gl = executor.submit(probe_gitlab)

            results["github"] = fut_gh.result()

            results["gitee"] = fut_ge.result()

            results["gitlab"] = fut_gl.result()



        _health_cache = results

        _health_cache_timestamp = time.time()

        res_copy = copy.deepcopy(results)

        res_copy["_cached"] = False

        return res_copy



def manual_add_repo(repo_path: str, alias: str = "") -> Dict[str, Any]:

    norm_path = os.path.normpath(os.path.abspath(repo_path))

    if not os.path.exists(norm_path):

        return {"success": False, "error": f"路径不存在: {norm_path}"}

    git_dir = os.path.join(norm_path, ".git")

    if not os.path.exists(git_dir):

        return {"success": False, "error": f"该目录下未检测到 .git 目录: {norm_path}"}

        

    cfg = load_managed_repos_config()

    # 解除忽略

    norm_lower = norm_path.lower()

    cfg["ignored_paths"] = [p for p in cfg.get("ignored_paths", []) if os.path.normpath(p).lower() != norm_lower]

    

    # 获取详细信息

    name = alias.strip() if alias.strip() else os.path.basename(norm_path)

    branch_res = run_git(["branch", "--show-current"], cwd=norm_path)

    branch = branch_res["stdout"] if branch_res["success"] else "main"

    status_res = run_git(["status", "--porcelain"], cwd=norm_path)

    is_clean = len(status_res["stdout"].strip()) == 0 if status_res["success"] else False

    ahead_res = run_git(["rev-list", "--count", "@{upstream}..HEAD"], cwd=norm_path)

    ahead_behind = f"+{ahead_res['stdout'].strip()}" if ahead_res["success"] else "0/0"

    remotes = get_repo_remotes(norm_path)

    ownership = detect_repo_ownership(norm_path)

    

    # 写入 managed_repos

    managed_list = [r for r in cfg.get("managed_repos", []) if os.path.normpath(r.get("path", "")).lower() != norm_lower]

    repo_entry = {

        "path": norm_path,

        "name": name,

        "is_my_repo": True,

        "owner": ownership.get("owner", "manual"),

        "added_by": "manual"

    }

    managed_list.append(repo_entry)

    cfg["managed_repos"] = managed_list

    save_managed_repos_config(cfg)

    

    return {

        "success": True,

        "repo": {

            "name": name,

            "path": norm_path,

            "branch": branch,

            "is_clean": is_clean,

            "ahead_behind": ahead_behind,

            "remotes": sanitize_remotes(remotes),

            "ownership": ownership,

            "added_by": "manual"

        }

    }



def ignore_repo(repo_path: str) -> Dict[str, Any]:

    norm_path = os.path.normpath(os.path.abspath(repo_path))

    cfg = load_managed_repos_config()

    norm_lower = norm_path.lower()

    

    # 加入 ignored_paths

    ignored = cfg.get("ignored_paths", [])

    if not any(os.path.normpath(p).lower() == norm_lower for p in ignored):

        ignored.append(norm_path)

    cfg["ignored_paths"] = ignored

    

    # 从 managed_repos 中移除

    cfg["managed_repos"] = [r for r in cfg.get("managed_repos", []) if os.path.normpath(r.get("path", "")).lower() != norm_lower]

    save_managed_repos_config(cfg)

    return {"success": True, "ignored_path": norm_path}



def unignore_repo(repo_path: str) -> Dict[str, Any]:

    norm_path = os.path.normpath(os.path.abspath(repo_path))

    norm_lower = norm_path.lower()

    cfg = load_managed_repos_config()

    cfg["ignored_paths"] = [p for p in cfg.get("ignored_paths", []) if os.path.normpath(p).lower() != norm_lower]

    save_managed_repos_config(cfg)

    return {"success": True, "unignored_path": norm_path}



def archive_repo(repo_path: str, reason: str = "") -> Dict[str, Any]:
    """
    应用层软归档仓库：
    在 managed_repos.json 中打上 is_archived=True 标记及时间戳。
    物理文件完全原位保留，不执行任何破坏性移动或删除。
    """
    norm_path = os.path.normpath(os.path.abspath(repo_path))
    norm_lower = norm_path.lower()
    cfg = load_managed_repos_config()
    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    found = False
    for r in cfg.get("managed_repos", []):
        if os.path.normpath(r.get("path", "")).lower() == norm_lower:
            r["is_archived"] = True
            r["archived_at"] = now_str
            if reason.strip():
                r["archive_reason"] = reason.strip()
            found = True
            break

    if not found:
        cfg.setdefault("managed_repos", []).append({
            "path": norm_path,
            "name": os.path.basename(norm_path),
            "is_my_repo": True,
            "added_by": "manual",
            "is_archived": True,
            "archived_at": now_str,
            "archive_reason": reason.strip()
        })

    save_managed_repos_config(cfg)
    invalidate_repos_cache()
    return {"success": True, "path": norm_path, "is_archived": True, "archived_at": now_str}



def unarchive_repo(repo_path: str) -> Dict[str, Any]:
    """
    解除仓库软归档状态：恢复为日常活跃受管仓库。
    """
    norm_path = os.path.normpath(os.path.abspath(repo_path))
    norm_lower = norm_path.lower()
    cfg = load_managed_repos_config()

    for r in cfg.get("managed_repos", []):
        if os.path.normpath(r.get("path", "")).lower() == norm_lower:
            r["is_archived"] = False
            r.pop("archived_at", None)
            r.pop("archive_reason", None)
            break

    save_managed_repos_config(cfg)
    invalidate_repos_cache()
    return {"success": True, "path": norm_path, "is_archived": False}



def scan_repositories(workspace_root: str = "<vault-root>", depth: int = 3, only_mine: bool = True) -> List[Dict[str, Any]]:

    detailed = scan_repositories_detailed(workspace_root=workspace_root, depth=depth, only_mine=only_mine)

    return detailed.get("repos", [])





def get_repo_last_commit_fast(repo_path: str) -> Tuple[int, str]:
    """
    Ultra-fast last commit timestamp extraction (<0.1ms).
    Directly parses binary tail of .git/logs/HEAD without spawning git subprocess.
    Falls back to .git/index or .git/refs mtime.
    Returns (epoch_timestamp, relative_time_string).
    """
    ts = 0
    git_dir = os.path.join(repo_path, ".git")
    logs_head = os.path.join(git_dir, "logs", "HEAD")
    if os.path.exists(logs_head):
        try:
            with open(logs_head, "rb") as f:
                f.seek(max(0, os.path.getsize(logs_head) - 1024))
                lines = f.read().decode("utf-8", errors="ignore").strip().splitlines()
                if lines:
                    last_line = lines[-1]
                    parts = last_line.split("\t")[0].split()
                    if len(parts) >= 2:
                        ts = int(parts[-2])
        except Exception:
            pass

    if ts <= 0:
        index_file = os.path.join(git_dir, "index")
        if os.path.exists(index_file):
            try:
                ts = int(os.path.getmtime(index_file))
            except Exception:
                pass
    if ts <= 0 and os.path.exists(git_dir):
        try:
            ts = int(os.path.getmtime(git_dir))
        except Exception:
            ts = int(time.time())

    now = time.time()
    diff = max(0, int(now - ts))
    if diff < 60:
        rel = "刚刚"
    elif diff < 3600:
        rel = f"{diff // 60}分钟前"
    elif diff < 86400:
        rel = f"{diff // 3600}小时前"
    elif diff < 86400 * 30:
        days = diff // 86400
        rel = "昨天" if days == 1 else f"{days}天前"
    else:
        rel = datetime.fromtimestamp(ts).strftime("%Y-%m-%d")

    return ts, rel


def _inspect_single_repo_worker(mr_entry: Dict[str, Any], my_identifiers: set, ignored_set: set) -> Optional[Dict[str, Any]]:

    full_path = os.path.normpath(mr_entry.get("path", ""))

    norm_lower = full_path.lower()

    

    if norm_lower in ignored_set:

        return None

        

    git_dir = os.path.join(full_path, ".git")

    if not os.path.exists(git_dir):

        return None

        

    name = mr_entry.get("name") or os.path.basename(full_path)

    added_by = mr_entry.get("added_by", "auto")

    

    # 极速解析分支与远程源 (耗时 < 1ms)

    branch = get_repo_branch_fast(full_path)

    remotes = get_repo_remotes_fast(full_path)

    

    if added_by == "manual":

        ownership = {

            "is_my_repo": True,

            "owner": "manual",

            "type": "manual_added",

            "label": "受管仓库 · 手动添加",

            "reason": "由用户手动指定添加受管"

        }

    else:

        ownership = detect_repo_ownership(full_path, my_identifiers, remotes_data=remotes)

        

    # 单独检查工作区是否干净 (单次 git 命令)

    status_res = run_git(["status", "--porcelain"], cwd=full_path)

    is_clean = len(status_res["stdout"].strip()) == 0 if status_res["success"] else False

    

    commit_ts, commit_rel = get_repo_last_commit_fast(full_path)
    ahead_behind = get_repo_ahead_behind(full_path, branch)

    return {
        "name": name,
        "path": full_path,
        "branch": branch,
        "is_clean": is_clean,
        "ahead_behind": ahead_behind,
        "remotes": sanitize_remotes(remotes),
        "ownership": ownership,
        "added_by": added_by,
        "updated_at": commit_ts,
        "updated_relative": commit_rel,
        "is_archived": mr_entry.get("is_archived", False),
        "archived_at": mr_entry.get("archived_at", ""),
        "archive_reason": mr_entry.get("archive_reason", "")
    }



def get_managed_repositories_fast(

    workspace_root: str = "<vault-root>",

    depth: int = 3,

    only_mine: bool = True,

    force_refresh: bool = False,

    force_scan: bool = False

) -> Dict[str, Any]:

    """

    High-Performance Repository Loader:

    1. Returns cached result instantly (<1ms) if valid within 30s TTL unless force_refresh or force_scan.

    2. Concurrent parallel state extraction via ThreadPoolExecutor from managed_repos.json (1~2s) avoiding recursive 1161 dir walks.

    3. Seamlessly falls back to deep directory walk only if managed_repos.json is empty or force_scan=True.

    """

    now = time.time()

    cache_key = "data_mine" if only_mine else "data_all"

    

    if not force_refresh and not force_scan:

        with _CACHE_LOCK:

            cached_data = _REPOS_CACHE.get(cache_key)

            ts = _REPOS_CACHE.get("timestamp", 0.0)

            ttl = _REPOS_CACHE.get("ttl", 30.0)

            if cached_data is not None and (now - ts) < ttl:

                # Return instant memory cache with flag

                cached_res = copy.deepcopy(cached_data)

                cached_res["source"] = "memory_cache"

                return cached_res

                

    cfg = load_managed_repos_config()

    managed_list = cfg.get("managed_repos", [])

    

    # If no persisted repos or explicitly requested full scan, run detailed directory walk

    if not managed_list or force_scan:

        result = scan_repositories_detailed(workspace_root=workspace_root, depth=depth, only_mine=only_mine)

        with _CACHE_LOCK:

            _REPOS_CACHE[cache_key] = copy.deepcopy(result)

            _REPOS_CACHE["timestamp"] = time.time()

        result["source"] = "full_disk_scan"

        return result

        

    # High-speed parallel loading from managed_repos.json

    ignored_set = {os.path.normpath(p).lower() for p in cfg.get("ignored_paths", [])}

    my_identifiers = get_user_identifiers()

    

    repos = []

    my_repos_count = 0

    ignored_third_party_count = 0

    

    with ThreadPoolExecutor(max_workers=min(12, len(managed_list) or 1)) as executor:

        futures = [

            executor.submit(_inspect_single_repo_worker, mr, my_identifiers, ignored_set)

            for mr in managed_list

        ]

        for f in futures:

            try:

                repo_info = f.result()

                if not repo_info:

                    continue

                is_mine = repo_info.get("ownership", {}).get("is_my_repo", False)

                if is_mine:

                    my_repos_count += 1

                else:

                    ignored_third_party_count += 1

                    

                if only_mine and not is_mine:

                    continue

                repos.append(repo_info)

            except Exception:

                pass

                

    # Sort repos: mine first, then alphabetically by name

    repos.sort(key=lambda r: (not r.get("ownership", {}).get("is_my_repo", False), -r.get("updated_at", 0), r.get("name", "").lower()))

    

    archived_count = sum(1 for r in repos if r.get("is_archived", False))
    active_count = len(repos) - archived_count

    result = {

        "repos": repos,

        "stats": {

            "total_found": len(repos),

            "active_count": active_count,

            "archived_count": archived_count,

            "my_repos_count": my_repos_count,

            "ignored_third_party_count": ignored_third_party_count,

            "ignored_paths_count": len(ignored_set),

            "scanned_dirs_count": len(managed_list)

        },

        "trace": [

            {

                "time": datetime.now().strftime("%H:%M:%S"),

                "type": "fast_load",

                "message": f"高速并发载入 {len(repos)} 个受管仓库 (耗时优化 90%)"

            }

        ],

        "filter_only_mine": only_mine,

        "workspace_root": workspace_root,

        "source": "managed_config_fast"

    }

    

    with _CACHE_LOCK:

        _REPOS_CACHE[cache_key] = copy.deepcopy(result)

        _REPOS_CACHE["timestamp"] = time.time()

        

    return result



def scan_repositories_detailed(

    workspace_root: str = "<vault-root>",

    depth: int = 3,

    only_mine: bool = True,

    callback: Optional[Callable[[Dict[str, Any]], None]] = None

) -> Dict[str, Any]:

    cfg = load_managed_repos_config()

    ignored_set = {os.path.normpath(p).lower() for p in cfg.get("ignored_paths", [])}

    my_identifiers = get_user_identifiers()

    

    trace: List[Dict[str, Any]] = []

    

    def log_event(event_type: str, message: str, extra: Optional[Dict[str, Any]] = None):

        t_str = datetime.now().strftime("%H:%M:%S")

        entry = {"time": t_str, "type": event_type, "message": message}

        if extra:

            entry.update(extra)

        trace.append(entry)

        if callback:

            try:

                callback(entry)

            except Exception:

                pass



    log_event("init", f"启动探测器: 根目录={workspace_root}, 最大深度={depth}, 仅我的仓库={only_mine}")



    discovered_paths = set()

    raw_candidates = [] # (name, full_path, added_by)

    scanned_dirs_count = 0



    # 1. 递归扫描指定 workspace_root

    if os.path.exists(workspace_root):

        norm_root = os.path.normpath(os.path.abspath(workspace_root))

        root_depth = norm_root.count(os.sep)

        

        # 深度与跳过黑名单 (包含 Windows 系统与重型构建目录)

        skip_dirs = {

            ".git", "node_modules", ".venv", "venv", "env", "dist", "build",

            ".cache", "bin", "obj", "__pycache__", ".idea", ".vscode",

            "$recycle.bin", "system volume information", "recovery", "msocache",

            "config.msi", "program files", "program files (x86)", "windows",

            "appdata", "local settings", "programdata",

            "文件恢复", "found.000", "found.001", "diskgenius", "easyrecovery",

            "视频类", "迅雷下载", "thunder download", "baidunetdiskdownload",

            ".gradle", ".cargo", ".nuget", ".rustup", "vendor", ".terraform"

        }

        

        for root, dirs, files in os.walk(norm_root):

            scanned_dirs_count += 1

            curr_depth = root.count(os.sep) - root_depth

            if curr_depth >= depth:

                dirs.clear()

                continue

                

            dirs[:] = [d for d in dirs if d.lower() not in skip_dirs]

            

            # 定期报告扫描排查进度

            if scanned_dirs_count % 10 == 1 or scanned_dirs_count <= 5:

                log_event("scanning", f"正在排查目录 ({scanned_dirs_count}): {root}", {"current_dir": root, "scanned_dirs": scanned_dirs_count})

            

            if os.path.exists(os.path.join(root, ".git")):

                norm_p = os.path.normpath(root)

                rel_name = os.path.relpath(norm_p, norm_root)

                if rel_name == ".":

                    rel_name = os.path.basename(norm_p)

                raw_candidates.append((rel_name.replace("\\", "/"), norm_p, "auto"))

                discovered_paths.add(norm_p.lower())

                log_event("found_git", f"发现 Git 仓库: {norm_p}", {"repo_path": norm_p, "name": rel_name})

                dirs.clear()



    # 2. 合并手动添加的受管仓库 (若在扫描目录外但物理存在)

    for mr in cfg.get("managed_repos", []):

        m_path = os.path.normpath(mr.get("path", ""))

        m_lower = m_path.lower()

        if m_lower not in discovered_paths and os.path.exists(os.path.join(m_path, ".git")):

            r_name = mr.get("name") or os.path.basename(m_path)

            raw_candidates.append((r_name, m_path, "manual"))

            discovered_paths.add(m_lower)

            log_event("found_manual", f"合并手动受管仓库: {m_path}", {"repo_path": m_path, "name": r_name})



    # 3. 解析与所有权分类过滤

    repos = []

    total_found = 0

    my_repos_count = 0

    ignored_third_party_count = 0

    

    for name, full_path, added_by in raw_candidates:

        norm_lower = full_path.lower()

        if norm_lower in ignored_set:

            log_event("ignored_path", f"跳过已忽略仓库: {name} ({full_path})", {"repo_path": full_path})

            continue

            

        total_found += 1

        

        # Fast branch parsing from .git/HEAD

        branch = "main"

        head_path = os.path.join(full_path, ".git", "HEAD")

        if os.path.exists(head_path):

            try:

                with open(head_path, "r", encoding="utf-8", errors="ignore") as f_h:

                    head_c = f_h.read().strip()

                if head_c.startswith("ref: refs/heads/"):

                    branch = head_c[len("ref: refs/heads/"):]

            except Exception:

                pass

        

        status_res = run_git(["status", "--porcelain"], cwd=full_path, timeout=2)
        is_clean = len(status_res["stdout"].strip()) == 0 if status_res["success"] else True
        ahead_behind = get_repo_ahead_behind(full_path, branch)

        remotes = get_repo_remotes_fast(full_path)

        

        if added_by == "manual":

            ownership = {

                "is_my_repo": True,

                "owner": "manual",

                "type": "manual_added",

                "label": "受管仓库 · 手动添加",

                "reason": "由用户手动指定添加受管"

            }

        else:

            ownership = detect_repo_ownership(full_path, my_identifiers)

            

        is_mine = ownership.get("is_my_repo", False)

        if is_mine:

            my_repos_count += 1

            log_event("match_mine", f"所有权匹配成功: [{name}] -> {ownership.get('label')}", {"name": name, "ownership": ownership})

        else:

            ignored_third_party_count += 1

            log_event("filter_third_party", f"第三方开源克隆: [{name}] -> {ownership.get('label')} (已自动过滤)", {"name": name, "ownership": ownership})

            

        if only_mine and not is_mine:

            continue

            

        mr_match = managed_paths.get(norm_lower) if 'managed_paths' in locals() else None
        if not mr_match:
            mr_match = next((mr for mr in cfg.get("managed_repos", []) if os.path.normpath(mr.get("path", "")).lower() == norm_lower), None)

        commit_ts, commit_rel = get_repo_last_commit_fast(full_path)
        repos.append({
            "name": name,
            "path": full_path,
            "branch": branch,
            "is_clean": is_clean,
            "ahead_behind": ahead_behind,
            "remotes": sanitize_remotes(remotes),
            "ownership": ownership,
            "added_by": added_by,
            "updated_at": commit_ts,
            "updated_relative": commit_rel,
            "is_archived": mr_match.get("is_archived", False) if mr_match else False,
            "archived_at": mr_match.get("archived_at", "") if mr_match else "",
            "archive_reason": mr_match.get("archive_reason", "") if mr_match else ""
        })



    # 4. 自动将探测到的“我的仓库”持久化写入 managed_repos.json

    managed_list = cfg.get("managed_repos", [])

    managed_paths = {os.path.normpath(r.get("path", "")).lower(): r for r in managed_list}

    newly_persisted_count = 0

    

    for r in repos:

        if r.get("ownership", {}).get("is_my_repo", False):

            p_lower = os.path.normpath(r["path"]).lower()

            if p_lower not in managed_paths:

                entry = {

                    "path": r["path"],

                    "name": r["name"],

                    "is_my_repo": True,

                    "owner": r.get("ownership", {}).get("owner", ""),

                    "added_by": r.get("added_by", "auto_scan")

                }

                managed_list.append(entry)

                managed_paths[p_lower] = entry

                newly_persisted_count += 1

                

    if newly_persisted_count > 0:

        cfg["managed_repos"] = managed_list

        save_managed_repos_config(cfg)

        log_event("persisted", f"已成功将 {newly_persisted_count} 个新发现仓库持久化载入受管系统配置 (managed_repos.json)", {"persisted_count": newly_persisted_count})



    repos.sort(key=lambda r: (not r.get("ownership", {}).get("is_my_repo", False), -r.get("updated_at", 0), r.get("name", "").lower()))
    log_event("done", f"探测完毕！遍历 {scanned_dirs_count} 个目录，发现 {total_found} 个仓库，纳入 {my_repos_count} 个我的仓库，过滤 {ignored_third_party_count} 个第三方项目")



    return {

        "repos": repos,

        "stats": {

            "total_found": total_found,

            "active_count": sum(1 for r in repos if not r.get("is_archived", False)),

            "archived_count": sum(1 for r in repos if r.get("is_archived", False)),

            "my_repos_count": my_repos_count,

            "ignored_third_party_count": ignored_third_party_count,

            "ignored_paths_count": len(ignored_set),

            "scanned_dirs_count": scanned_dirs_count

        },

        "trace": trace,

        "filter_only_mine": only_mine,

        "workspace_root": workspace_root

    }





def _get_repo_remotes_raw(repo_path: str) -> Dict[str, Any]:

    res = run_git(["remote", "-v"], cwd=repo_path)

    lines = res["stdout"].splitlines() if res["success"] else []

    

    fetch_url = ""

    push_urls = []

    

    # Try git remote get-url --all --push origin

    all_push = run_git(["remote", "get-url", "--all", "--push", "origin"], cwd=repo_path)

    if all_push["success"] and all_push["stdout"]:

        push_urls = [u.strip() for u in all_push["stdout"].splitlines() if u.strip()]

    

    for line in lines:

        parts = line.split()

        if len(parts) >= 3:

            name, url, typ = parts[0], parts[1], parts[2]

            if name == "origin" and typ == "(fetch)":

                fetch_url = url

            if typ == "(push)" and url not in push_urls:

                push_urls.append(url)



    # Detect platforms

    has_github = any("github.com" in u for u in push_urls)

    has_gitee = any("gitee.com" in u for u in push_urls)

    has_gitlab = any("gitlab.com" in u for u in push_urls)



    return {

        "fetch_url": fetch_url,

        "push_urls": push_urls,

        "is_triple_synced": has_github and has_gitee and has_gitlab,

        "has_github": has_github,

        "has_gitee": has_gitee,

        "has_gitlab": has_gitlab

    }



def get_repo_remotes(repo_path: str) -> Dict[str, Any]:
    """Public view: never returns URL userinfo/tokens."""
    return sanitize_remotes(_get_repo_remotes_raw(repo_path))


def configure_triple_remotes(repo_path: str, github_url: str, gitee_url: str, gitlab_url: str) -> Dict[str, Any]:

    for _label, _url in (("GitHub", github_url), ("Gitee", gitee_url), ("GitLab", gitlab_url)):
        if _url and re.search(r"://[^/@\s]+@", _url):
            return {"success": False, "error": f"[SECURITY] {_label} URL 含明文凭据 (userinfo)，请改用 SSH 或凭据管理器"}

    logs = []

    # 1. Set origin fetch url

    existing_origin = run_git(["remote", "get-url", "origin"], cwd=repo_path)

    if existing_origin["success"]:

        r1 = run_git(["remote", "set-url", "origin", github_url], cwd=repo_path)

        logs.append(f"Set origin: {r1['success']}")

    else:

        r1 = run_git(["remote", "add", "origin", github_url], cwd=repo_path)

        logs.append(f"Add origin: {r1['success']}")

        

    # 2. Reset push URLs

    run_git(["remote", "set-url", "--push", "origin", github_url], cwd=repo_path)

    logs.append(f"Added Push URL (GitHub): {github_url}")

    

    if gitee_url:

        run_git(["remote", "set-url", "--add", "--push", "origin", gitee_url], cwd=repo_path)

        logs.append(f"Added Push URL (Gitee): {gitee_url}")

        

    if gitlab_url:

        run_git(["remote", "set-url", "--add", "--push", "origin", gitlab_url], cwd=repo_path)

        logs.append(f"Added Push URL (GitLab): {gitlab_url}")

        

    return {"success": True, "logs": logs, "remotes": sanitize_remotes(get_repo_remotes(repo_path))}



SYNC_AUDIT_LOG_FILE = os.path.join(CONFIG_DIR, "sync_audit_logs.json")



def load_sync_audit_logs(limit: int = 50) -> List[Dict[str, Any]]:

    if not os.path.exists(SYNC_AUDIT_LOG_FILE):

        return []

    try:

        with open(SYNC_AUDIT_LOG_FILE, "r", encoding="utf-8") as f:

            data = json.load(f)

            return data[:limit] if isinstance(data, list) else []

    except Exception:

        return []



def record_sync_audit_log(entry: Dict[str, Any]) -> None:

    logs = load_sync_audit_logs(limit=100)

    logs.insert(0, redact(entry))

    if len(logs) > 100:

        logs = logs[:100]

    try:

        with open(SYNC_AUDIT_LOG_FILE, "w", encoding="utf-8") as f:

            json.dump(logs, f, indent=2, ensure_ascii=False)

    except Exception:

        pass



def diagnose_push_failure(target: str, url: str, stdout: str, stderr: str, repo_name: str = "") -> Dict[str, Any]:

    raw = (stdout + "\n" + stderr).strip()

    norm_lower = raw.lower()

    clean_name = repo_name or url.rstrip("/").split("/")[-1].replace(".git", "")

    

    # 1. Repository Not Found

    if "repository not found" in norm_lower or "the project you were looking for could not be found" in norm_lower:

        action_url = ""

        action_label = ""

        if "github.com" in url or target.lower() == "github":

            action_url = f"https://github.com/new?name={clean_name}"

            action_label = f"前往 GitHub 快速预填创建仓库 [{clean_name}]"

        elif "gitlab.com" in url or target.lower() == "gitlab":

            action_url = "https://gitlab.com/projects/new"

            action_label = f"前往 GitLab 创建新项目 [{clean_name}]"

        elif "gitee.com" in url or target.lower() == "gitee":

            action_url = "https://gitee.com/projects/new"

            action_label = f"前往 Gitee 创建新仓库 [{clean_name}]"

            

        return {

            "code": "REPO_NOT_FOUND_ON_REMOTE",

            "level": "action_required",

            "title": f"远程平台尚未创建该仓库 ({target} 不支持客户端 Push 自动建库)",

            "reason": (

                f"{target} 官方规范要求必须先在网页后台或通过 API 创建同名空仓库，然后方可接收客户端的 Git 推送。\n"

                f"(注：GitLab 支持 SSH push 自动建库，但 GitHub/Gitee 均关闭了此功能以防误建库)"

            ),

            "suggestion": f"请先点击下方链接在 {target} 后台创建同名仓库，完成后直接点击【单独重试推送】即可推入！",

            "action_url": action_url,

            "action_label": action_label,

            "retry_target": target.lower()

        }

        

    # 2. Permission Denied (Public Key)

    if "permission denied (publickey)" in norm_lower or "permission denied" in norm_lower:

        return {

            "code": "SSH_PERMISSION_DENIED",

            "level": "error",

            "title": f"SSH 密钥鉴权失败或公钥未授权",

            "reason": f"{target} 拒绝了当前本地 SSH 密钥的握手请求，可能是该平台的后台尚未录入此公钥，或本地未选用正确的密钥文件。",

            "suggestion": "请确认本地公钥已导入对应平台的 SSH Keys 配置列表，并在本地 ~/.ssh/config 中配置了该 Host 的 IdentityFile 映射。",

            "action_url": "https://github.com/settings/keys" if "github" in target.lower() else "",

            "action_label": "管理 GitHub SSH Keys" if "github" in target.lower() else "",

            "retry_target": target.lower()

        }

        

    # 3. Connection Timeout / Port Blocked

    if "connection timed out" in norm_lower or "operation timed out" in norm_lower or "port 22: connection timed out" in norm_lower:

        return {

            "code": "NETWORK_PORT_TIMEOUT",

            "level": "error",

            "title": f"网络连接超时 (22 端口被运营商阻断)",

            "reason": f"国内部分运营商防火墙对海外平台的 22 端口存在阻断或严重丢包。",

            "suggestion": "建议在 ~/.ssh/config 中切换为 443 备用端口，或在 Git-Vault 网络路由设置中配置本地代理通道。",

            "action_url": "",

            "action_label": "",

            "retry_target": target.lower()

        }

        

    # 4. Non-Fast-Forward Reject

    if "non-fast-forward" in norm_lower or "fetch first" in norm_lower or "updates were rejected" in norm_lower:

        return {

            "code": "REJECTED_NON_FAST_FORWARD",

            "level": "warn",

            "title": "推送被拒绝 (远程分支包含未合并的提交)",

            "reason": "远程仓库已存在新的提交历史，本地分支落后于远程分支。",

            "suggestion": "建议先执行拉取合并 (git pull)，或在确认覆盖的情况下使用强推同步。",

            "action_url": "",

            "action_label": "",

            "retry_target": target.lower()

        }

        

    # 5. Default

    return {

        "code": "UNKNOWN_ERROR",

        "level": "warn",

        "title": "推送命令执行返回非零退出码",

        "reason": raw[:200] if raw else "未知原因",

        "suggestion": "请查看下方完整控制台 Stderr 日志进行定位。",

        "action_url": "",

        "action_label": "",

        "retry_target": target.lower()

    }



def strip_sensitive_tokens(text: str) -> str:
    """Scrub sensitive embedded tokens, basic auth credentials, and PATs from git logs/errors."""
    if not text:
        return ""
    # 1. Scrub basic auth credentials in URLs: https://user:token@domain -> https://***@domain
    text = re.sub(r'(https?://)[^:\s/@]+:[^@\s/]+@', r'\1***@', text)
    text = re.sub(r'(https?://)[^:\s/@]+@', r'\1***@', text)
    # 2. Scrub standard PAT patterns (ghp_, glpat-, etc.)
    text = re.sub(r'(ghp_[a-zA-Z0-9]{20,})', r'ghp_***[REDACTED]', text)
    text = re.sub(r'(glpat-[a-zA-Z0-9\-_]{15,})', r'glpat-***[REDACTED]', text)
    return text


def _execute_single_push(repo_path: str, branch: str, url: str, repo_name: str) -> Dict[str, Any]:
    """Execute push to a single remote target with proxy, auth, and diff detection."""
    label = url
    if "github.com" in url: label = "GitHub"
    elif "gitee.com" in url: label = "Gitee"
    elif "gitlab.com" in url: label = "GitLab"

    extra_args = network_router.get_git_extra_args(url)
    push_url = url

    # SECURITY: never put DPAPI token into argv/URL. Convert SSH/HTTPS to a clean
    # HTTPS URL and let git call our credential helper; token only crosses a pipe.
    helper_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "git_credential_helper.py")
    needs_helper = False
    if "gitee.com" in url and url.startswith("https://") and "@" not in url:
        needs_helper = True
    elif "gitlab.com" in url:
        needs_helper = True
        if url.startswith("git@gitlab.com:"):
            push_url = "https://gitlab.com/" + url.split("git@gitlab.com:", 1)[1]
        elif url.startswith("https://") and "@" not in url:
            push_url = url
    elif "github.com" in url:
        needs_helper = True
        if url.startswith("git@github.com:"):
            push_url = "https://github.com/" + url.split("git@github.com:", 1)[1]
        elif url.startswith("https://") and "@" not in url:
            push_url = url

    if needs_helper:
        extra_args.extend(["-c", "credential.helper=",
                           "-c", f'credential.helper=!python "{helper_path}"'])

    push_cmd = extra_args + ["push", push_url, branch]
    t0 = time.time()
    push_res = run_git(push_cmd, cwd=repo_path, timeout=45)
    duration_ms = int((time.time() - t0) * 1000)

    clean_stdout = strip_sensitive_tokens(push_res["stdout"])
    clean_stderr = strip_sensitive_tokens(push_res["stderr"])
    combined_output = f"{clean_stdout}\n{clean_stderr}".strip()

    # 差异智能识别:
    # 1) 是否已是最新 (Everything up-to-date)
    is_up_to_date = "everything up-to-date" in combined_output.lower()

    # 2) 是否成功推送新提交 (commit range: e.g. 13998c3..3f3f7b9)
    commit_range_match = re.search(r"([0-9a-f]{7,40}\.\.[0-9a-f]{7,40})", combined_output)
    pushed_range = commit_range_match.group(1) if commit_range_match else None

    # 如果输出中包含 Everything up-to-date，即便因为网络/RPC断开产生退出码（如HTTP 422），云端实质上也已对齐最新提交
    is_success = push_res["success"] or is_up_to_date

    status_text = "UP_TO_DATE" if is_up_to_date else ("PUSHED" if is_success else "FAILED")
    status_badge = "已是最新 (无差异)" if is_up_to_date else (f"推送成功 ({pushed_range})" if pushed_range else ("推送成功" if is_success else "推送失败"))

    diag = None
    if not is_success:
        diag = diagnose_push_failure(label, url, clean_stdout, clean_stderr, repo_name=repo_name)

    return {
        "target": label,
        "url": url,
        "success": is_success,
        "up_to_date": is_up_to_date,
        "status": status_text,
        "status_badge": status_badge,
        "pushed_range": pushed_range,
        "exit_code": 0 if is_success else 1,
        "duration_ms": duration_ms,
        "stdout": clean_stdout,
        "stderr": clean_stderr,
        "diagnosis": diag
    }


def _sync_repository_impl(repo_path: str, branch: Optional[str] = None, target_platform: Optional[str] = None, force: bool = False) -> Dict[str, Any]:
    # 1. Panic button check
    can_write, panic_msg = compliance_guard.check_write_permission()
    if not can_write:
        return {
            "repo": os.path.basename(repo_path),
            "branch": branch or "main",
            "success": False,
            "blocked": True,
            "error": panic_msg,
            "results": [{
                "target": "PanicButton",
                "url": "",
                "success": False,
                "duration_ms": 0,
                "stdout": "",
                "stderr": panic_msg,
                "diagnosis": {
                    "code": "PANIC_BUTTON_LOCKED",
                    "level": "error",
                    "title": "紧急只读锁处于锁定状态",
                    "reason": panic_msg,
                    "suggestion": "请在顶部控制台解除只读锁定后重试。"
                }
            }]
        }

    if not branch:
        b_res = run_git(["branch", "--show-current"], cwd=repo_path)
        branch = b_res["stdout"].strip() if b_res["success"] else "main"

    remotes = _get_repo_remotes_raw(repo_path)
    targets = remotes["push_urls"]
    if not targets and remotes["fetch_url"]:
        targets = [remotes["fetch_url"]]

    # Filter by specific target platform if requested
    if target_platform:
        t_low = target_platform.lower()
        filtered = [u for u in targets if t_low in u.lower()]
        if filtered:
            targets = filtered

    for _u in targets:
        if re.search(r"://[^/@\s]+@", _u):
            return {"repo": os.path.basename(repo_path), "branch": branch, "success": False,
                    "error": "远程 URL 含明文凭据 (userinfo)，已阻止同步；请改用 SSH 或凭据管理器"}

    if not targets:
        return {
            "repo": os.path.basename(repo_path),
            "branch": branch,
            "success": False,
            "error": "未找到任何远程推送目标地址 (Push URLs)",
            "results": []
        }

    repo_name = os.path.basename(repo_path)
    head_res = run_git(["rev-parse", "HEAD"], cwd=repo_path)
    local_head = head_res["stdout"].strip() if head_res["success"] else ""

    status_res = run_git(["status", "--porcelain"], cwd=repo_path, timeout=5)
    uncommitted_files = [l[3:].strip() for l in status_res["stdout"].splitlines() if l.strip()]
    has_uncommitted = len(uncommitted_files) > 0

    # 推送前差异预检 (Diff Pre-Check)
    # 若非强制模式且本地已记录各远端已同步到当前 HEAD，直接 0ms 短路完成
    sync_state = load_sync_state()
    repo_key = os.path.normpath(repo_path).lower()
    synced_targets = sync_state.get(repo_key, {}).get("synced_targets", {})

    if local_head and not force and all(synced_targets.get(sanitize_url_credentials(u)) == local_head for u in targets):
        short_circuit_results = []
        for url in targets:
            label = url
            if "github.com" in url: label = "GitHub"
            elif "gitee.com" in url: label = "Gitee"
            elif "gitlab.com" in url: label = "GitLab"
            short_circuit_results.append({
                "target": label,
                "url": url,
                "success": True,
                "up_to_date": True,
                "status": "UP_TO_DATE",
                "status_badge": "已是最新 (无差异)",
                "pushed_range": None,
                "exit_code": 0,
                "duration_ms": 0,
                "stdout": f"Everything up-to-date (本地提交 {local_head[:7]} 已全量同步)",
                "stderr": "",
                "diagnosis": None
            })
        for u in targets:
            update_local_tracking_refs(repo_path, u, branch, local_head)
        audit_entry = {
            "id": f"sync_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{int(time.time()*1000)%1000}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "repo": repo_name,
            "repo_path": repo_path,
            "branch": branch,
            "head": local_head,
            "has_uncommitted_changes": has_uncommitted,
            "uncommitted_count": len(uncommitted_files),
            "uncommitted_files": uncommitted_files[:10],
            "duration_ms": 0,
            "success": True,
            "up_to_date": True,
            "short_circuited": True,
            "total_targets": len(targets),
            "success_targets": len(targets),
            "results": short_circuit_results
        }
        record_sync_audit_log(audit_entry)
        return {
            "repo": repo_name,
            "repo_path": repo_path,
            "branch": branch,
            "head": local_head,
            "has_uncommitted_changes": has_uncommitted,
            "uncommitted_count": len(uncommitted_files),
            "uncommitted_files": uncommitted_files[:10],
            "success": True,
            "up_to_date": True,
            "short_circuited": True,
            "duration_ms": 0,
            "audit_id": audit_entry["id"],
            "timestamp": audit_entry["timestamp"],
            "results": short_circuit_results
        }

    # 多端真正并发分发 (True Concurrency via ThreadPoolExecutor)
    overall_t0 = time.time()
    results = []
    with ThreadPoolExecutor(max_workers=min(4, len(targets))) as executor:
        future_map = {
            executor.submit(_execute_single_push, repo_path, branch, url, repo_name): url
            for url in targets
        }
        for future in future_map:
            try:
                res = future.result()
                results.append(res)
            except Exception as ex:
                url = future_map[future]
                results.append({
                    "target": url,
                    "url": url,
                    "success": False,
                    "up_to_date": False,
                    "status": "FAILED",
                    "status_badge": "执行异常",
                    "pushed_range": None,
                    "exit_code": 1,
                    "duration_ms": 0,
                    "stdout": "",
                    "stderr": str(ex),
                    "diagnosis": None
                })

    # 更新本地多端已同步 commit 状态与追踪分支
    if local_head:
        for r in results:
            if r["success"]:
                update_repo_sync_state(repo_path, r["url"], local_head, branch)
                update_local_tracking_refs(repo_path, r["url"], branch, local_head)

    all_success = all(r["success"] for r in results) if results else False
    all_up_to_date = all(r.get("up_to_date", False) for r in results) if results else False
    total_duration_ms = int((time.time() - overall_t0) * 1000)

    audit_entry = {
        "id": f"sync_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{int(time.time()*1000)%1000}",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "repo": repo_name,
        "repo_path": repo_path,
        "branch": branch,
        "head": local_head,
        "has_uncommitted_changes": has_uncommitted,
        "uncommitted_count": len(uncommitted_files),
        "uncommitted_files": uncommitted_files[:10],
        "duration_ms": total_duration_ms,
        "success": all_success,
        "up_to_date": all_up_to_date,
        "total_targets": len(results),
        "success_targets": sum(1 for r in results if r["success"]),
        "results": results
    }

    record_sync_audit_log(audit_entry)

    return {
        "repo": repo_name,
        "repo_path": repo_path,
        "branch": branch,
        "head": local_head,
        "has_uncommitted_changes": has_uncommitted,
        "uncommitted_count": len(uncommitted_files),
        "uncommitted_files": uncommitted_files[:10],
        "success": all_success,
        "up_to_date": all_up_to_date,
        "duration_ms": total_duration_ms,
        "audit_id": audit_entry["id"],
        "timestamp": audit_entry["timestamp"],
        "results": results
    }


def sync_repository(*args, **kwargs):
    """Public sync result: redact any URL userinfo/token before returning."""
    return redact(_sync_repository_impl(*args, **kwargs))


def _sync_repository_stream_impl(repo_path: str, branch: Optional[str] = None, target_platform: Optional[str] = None, force: bool = False):
    """Generator yielding real-time SSE progress events for concurrent repository push synchronization."""
    can_write, panic_msg = compliance_guard.check_write_permission()
    if not can_write:
        yield {
            "type": "error",
            "percent": 100,
            "message": f"[BLOCKED] 紧急只读锁处于锁定状态: {panic_msg}",
            "result": {
                "repo": os.path.basename(repo_path),
                "branch": branch or "main",
                "success": False,
                "blocked": True,
                "error": panic_msg,
                "results": []
            }
        }
        return

    if not branch:
        b_res = run_git(["branch", "--show-current"], cwd=repo_path)
        branch = b_res["stdout"].strip() if b_res["success"] else "main"

    remotes = _get_repo_remotes_raw(repo_path)
    targets = remotes["push_urls"]
    if not targets and remotes["fetch_url"]:
        targets = [remotes["fetch_url"]]

    if target_platform:
        t_low = target_platform.lower()
        filtered = [u for u in targets if t_low in u.lower()]
        if filtered:
            targets = filtered

    for _u in targets:
        if re.search(r"://[^/@\s]+@", _u):
            yield {"repo": os.path.basename(repo_path), "branch": branch, "success": False,
                   "error": "远程 URL 含明文凭据 (userinfo)，已阻止同步；请改用 SSH 或凭据管理器"}
            return

    if not targets:
        yield {
            "type": "error",
            "percent": 100,
            "message": "[FAIL] 未找到任何远程推送目标地址 (Push URLs)",
            "result": {
                "repo": os.path.basename(repo_path),
                "branch": branch,
                "success": False,
                "error": "未找到任何远程推送目标地址 (Push URLs)",
                "results": []
            }
        }
        return

    total = len(targets)
    repo_name = os.path.basename(repo_path)
    head_res = run_git(["rev-parse", "HEAD"], cwd=repo_path)
    local_head = head_res["stdout"].strip() if head_res["success"] else ""

    status_res = run_git(["status", "--porcelain"], cwd=repo_path, timeout=5)
    uncommitted_files = [l[3:].strip() for l in status_res["stdout"].splitlines() if l.strip()]
    has_uncommitted = len(uncommitted_files) > 0

    yield {
        "type": "init",
        "repo": repo_name,
        "branch": branch,
        "total": total,
        "percent": 10,
        "message": f"预检差异: 比对本地提交 ({local_head[:7]}) 与多端同步记录..."
    }

    # 1. 差异预检短路检查
    sync_state = load_sync_state()
    repo_key = os.path.normpath(repo_path).lower()
    synced_targets = sync_state.get(repo_key, {}).get("synced_targets", {})

    if local_head and not force and all(synced_targets.get(sanitize_url_credentials(u)) == local_head for u in targets):
        short_circuit_results = []
        for url in targets:
            label = url
            if "github.com" in url: label = "GitHub"
            elif "gitee.com" in url: label = "Gitee"
            elif "gitlab.com" in url: label = "GitLab"
            short_circuit_results.append({
                "target": label,
                "url": url,
                "success": True,
                "up_to_date": True,
                "status": "UP_TO_DATE",
                "status_badge": "已是最新 (无差异)",
                "pushed_range": None,
                "exit_code": 0,
                "duration_ms": 0,
                "stdout": f"Everything up-to-date (本地提交 {local_head[:7]} 已全量同步)",
                "stderr": "",
                "diagnosis": None
            })
        for u in targets:
            update_local_tracking_refs(repo_path, u, branch, local_head)
        audit_entry = {
            "id": f"sync_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{int(time.time()*1000)%1000}",
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "repo": repo_name,
            "repo_path": repo_path,
            "branch": branch,
            "head": local_head,
            "has_uncommitted_changes": has_uncommitted,
            "uncommitted_count": len(uncommitted_files),
            "uncommitted_files": uncommitted_files[:10],
            "duration_ms": 0,
            "success": True,
            "up_to_date": True,
            "short_circuited": True,
            "total_targets": total,
            "success_targets": total,
            "results": short_circuit_results
        }
        for u in targets:
            update_local_tracking_refs(repo_path, u, branch, local_head)
        audit_entry["head"] = local_head
        audit_entry["has_uncommitted_changes"] = has_uncommitted
        audit_entry["uncommitted_count"] = len(uncommitted_files)
        audit_entry["uncommitted_files"] = uncommitted_files[:10]
        record_sync_audit_log(audit_entry)
        short_msg = f"【提交已对齐，工作区有未提交改动】云端已对齐最新 Commit ({local_head[:7]})，但本地有 {len(uncommitted_files)} 个未提交文件" if has_uncommitted else f"【已是最新】本地提交 ({local_head[:7]}) 与全部云端源完全一致，0 差异，无需重复推送"
        yield {
            "type": "complete",
            "percent": 100,
            "success": True,
            "up_to_date": True,
            "short_circuited": True,
            "duration_ms": 0,
            "message": short_msg,
            "result": audit_entry
        }
        return

    # 2. 真正的并发分发 (True Concurrency via Threads + Queue)
    yield {
        "type": "progress",
        "percent": 20,
        "message": f"并发启动: 发现 {total} 个目标远程源，多线程并行推送中..."
    }

    overall_t0 = time.time()
    evt_queue = queue.Queue()
    done_count = 0

    def _worker(url, idx):
        evt_queue.put({"type": "worker_start", "url": url, "index": idx})
        res = _execute_single_push(repo_path, branch, url, repo_name)
        evt_queue.put({"type": "worker_done", "url": url, "index": idx, "result": res})

    threads = []
    for idx, url in enumerate(targets):
        t = threading.Thread(target=_worker, args=(url, idx + 1), daemon=True)
        threads.append(t)
        t.start()

    results_dict = {}
    while done_count < total:
        try:
            item = evt_queue.get(timeout=0.1)
            if item["type"] == "worker_start":
                u = item["url"]
                lbl = "GitHub" if "github.com" in u else ("Gitee" if "gitee.com" in u else ("GitLab" if "gitlab.com" in u else u))
                cur_pct = int(20 + (done_count / total) * 70)
                yield {
                    "type": "progress",
                    "platform": lbl,
                    "percent": cur_pct,
                    "message": f"正在向 {lbl} 并行推送中..."
                }
            elif item["type"] == "worker_done":
                done_count += 1
                r_item = item["result"]
                results_dict[item["url"]] = r_item
                done_pct = int(20 + (done_count / total) * 75)
                yield {
                    "type": "platform_done",
                    "platform": r_item["target"],
                    "index": done_count,
                    "total": total,
                    "percent": done_pct,
                    "success": r_item["success"],
                    "up_to_date": r_item.get("up_to_date", False),
                    "status_badge": r_item["status_badge"],
                    "duration_ms": r_item["duration_ms"],
                    "message": f"[{done_count}/{total}] {r_item['target']} {r_item['status_badge']} ({r_item['duration_ms']}ms)"
                }
        except queue.Empty:
            continue

    for t in threads:
        t.join(timeout=1.0)

    # 保持原 targets 顺序组装结果
    results = [results_dict[u] for u in targets if u in results_dict]
    total_duration_ms = int((time.time() - overall_t0) * 1000)

    # 更新本地多端已同步 commit 状态与追踪分支
    if local_head:
        for r in results:
            if r["success"]:
                update_repo_sync_state(repo_path, r["url"], local_head, branch)
                update_local_tracking_refs(repo_path, r["url"], branch, local_head)

    all_success = all(r["success"] for r in results) if results else False
    all_up_to_date = all(r.get("up_to_date", False) for r in results) if results else False

    audit_entry = {
        "id": f"sync_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{int(time.time()*1000)%1000}",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "repo": repo_name,
        "repo_path": repo_path,
        "branch": branch,
        "head": local_head,
        "has_uncommitted_changes": has_uncommitted,
        "uncommitted_count": len(uncommitted_files),
        "uncommitted_files": uncommitted_files[:10],
        "duration_ms": total_duration_ms,
        "success": all_success,
        "up_to_date": all_up_to_date,
        "total_targets": len(results),
        "success_targets": sum(1 for r in results if r["success"]),
        "results": results
    }

    try:
        record_sync_audit_log(audit_entry)
    except Exception:
        pass

    if all_up_to_date:
        summary_msg = f"【已是最新】全部远程源已是最新 (0 差异)，耗时 {total_duration_ms/1000:.1f}s"
    elif all_success:
        summary_msg = f"[SUCCESS] 全部远程源并发推送完毕，耗时 {total_duration_ms/1000:.1f}s"
    else:
        summary_msg = f"[WARN] 推送完成但存在失败源，耗时 {total_duration_ms/1000:.1f}s"

    yield {
        "type": "complete",
        "percent": 100,
        "success": all_success,
        "up_to_date": all_up_to_date,
        "duration_ms": total_duration_ms,
        "message": summary_msg,
        "result": audit_entry
    }





def sync_repository_stream(*args, **kwargs):
    for _evt in _sync_repository_stream_impl(*args, **kwargs):
        yield redact(_evt)


def get_repository_full_detail(repo_path: str) -> Dict[str, Any]:

    """Retrieve comprehensive metadata, recent commits, working tree status, and remotes for Level-2 view."""

    norm_path = os.path.normpath(os.path.abspath(repo_path))

    if not os.path.exists(os.path.join(norm_path, ".git")):

        return {"success": False, "error": f"不是有效的 Git 仓库路径: {norm_path}"}



    repo_name = os.path.basename(norm_path)



    # Current branch

    b_res = run_git(["branch", "--show-current"], cwd=norm_path)

    branch = b_res["stdout"].strip() if b_res["success"] and b_res["stdout"] else "main"



    # Status porcelain

    st_res = run_git(["status", "--porcelain"], cwd=norm_path)

    changes = []

    if st_res["success"] and st_res["stdout"]:

        for l in st_res["stdout"].splitlines():

            if len(l) >= 3:

                changes.append({"code": l[:2], "file": l[3:].strip()})

    is_clean = len(changes) == 0



    # Ahead / behind

    ahead_behind = "0/0"

    rev_res = run_git(["rev-list", "--left-right", "--count", f"{branch}...@{{u}}"], cwd=norm_path)

    if rev_res["success"] and rev_res["stdout"]:

        parts = rev_res["stdout"].split()

        if len(parts) == 2:

            ahead_behind = f"+{parts[0]}/-{parts[1]}"



    # Commits log (last 15)

    log_fmt = "%H%x1f%h%x1f%an%x1f%ae%x1f%ad%x1f%ar%x1f%s"

    log_res = run_git(["log", "-n", "15", f"--pretty=format:{log_fmt}", "--date=iso"], cwd=norm_path)

    commits = []

    if log_res["success"] and log_res["stdout"]:

        for line in log_res["stdout"].splitlines():

            parts = line.split("")

            if len(parts) >= 7:

                commits.append({

                    "hash": parts[0],

                    "short_hash": parts[1],

                    "author": parts[2],

                    "email": parts[3],

                    "date": parts[4],

                    "relative": parts[5],

                    "subject": parts[6]

                })



    # Remotes

    remotes = get_repo_remotes(norm_path)

    user_identifiers = get_user_identifiers()

    ownership = detect_repo_ownership(norm_path, my_identifiers=user_identifiers, remotes_data=remotes)



    # Detailed remote items

    remote_cards = []

    all_remote_urls = remotes.get("push_urls", [])

    if not all_remote_urls and remotes.get("fetch_url"):

        all_remote_urls = [remotes.get("fetch_url")]



    for u in all_remote_urls:

        plat = "other"

        plat_label = "其他远程源"

        auth_hint = "标准 Git 凭据"

        if "github.com" in u:

            plat = "github"

            plat_label = "GitHub"

            auth_hint = "SSH <owner> (Port 443 极速路由)" if "git@" in u else "HTTPS Token"

        elif "gitee.com" in u:

            plat = "gitee"

            plat_label = "Gitee"

            auth_hint = "HTTPS <owner> (OAuth 直连)" if "https://" in u else "SSH 密钥"

        elif "gitlab.com" in u:

            plat = "gitlab"

            plat_label = "GitLab"

            auth_hint = "SSH <owner> (Port 443 极速路由)" if "git@" in u else "HTTPS Token"



        remote_cards.append({

            "platform": plat,

            "label": plat_label,

            "url": sanitize_url_credentials(u),

            "auth_hint": auth_hint,

            "is_ssh": u.startswith("git@") or "ssh://" in u

        })



    # Branches list

    br_res = run_git(["branch", "--list"], cwd=norm_path)

    branches = []

    if br_res["success"] and br_res["stdout"]:

        for b in br_res["stdout"].splitlines():

            clean_b = b.replace("*", "").strip()

            is_curr = b.strip().startswith("*")

            branches.append({"name": clean_b, "current": is_curr})



    # Gitignore status

    gi_path = os.path.join(norm_path, ".gitignore")

    has_gitignore = os.path.exists(gi_path)



    return {

        "success": True,

        "name": repo_name,

        "path": norm_path,

        "branch": branch,

        "is_clean": is_clean,

        "ahead_behind": ahead_behind,

        "changes": changes,

        "changes_count": len(changes),

        "commits": commits,

        "commits_count": len(commits),

        "remotes": sanitize_remotes(remotes),

        "remote_cards": remote_cards,

        "ownership": ownership,

        "branches": branches,

        "has_gitignore": has_gitignore

    }



# --- Code Diff Inspector & Compliance Scanning ---

def get_repo_diff(repo_path: str, staged_only: bool = False) -> Dict[str, Any]:

    """Retrieve structured diff for unstaged and staged changes with real-time compliance secret scan."""

    norm_path = os.path.normpath(repo_path)
    if not os.path.exists(norm_path):
        # Auto-heal path if mangled by JS escape sequence (e.g. \t or missing slashes)
        clean_name = os.path.basename(repo_path.replace('\t', '/').replace('\\', '/')).lower()
        for r in load_managed_repos_config().get("managed_repos", []):
            p = r.get("path", "")
            if os.path.basename(p).lower() == clean_name and os.path.exists(p):
                norm_path = p
                break
        if not os.path.exists(norm_path):
            return {"success": False, "error": f"Path not found: {repo_path}"}
    repo_path = norm_path



    status_res = run_git(["status", "--porcelain"], cwd=repo_path)

    file_statuses = []

    if status_res["success"] and status_res["stdout"]:

        for line in status_res["stdout"].splitlines():

            if len(line) >= 3:

                st = line[:2]

                fpath = line[3:].strip()

                file_statuses.append({"status": st, "path": fpath})



    # Diff stats

    stat_unstaged = run_git(["diff", "--stat"], cwd=repo_path)

    stat_staged = run_git(["diff", "--cached", "--stat"], cwd=repo_path)



    # Raw diffs

    diff_unstaged = run_git(["diff"], cwd=repo_path)

    diff_staged = run_git(["diff", "--cached"], cwd=repo_path)



    unstaged_text = diff_unstaged["stdout"] if diff_unstaged["success"] else ""

    staged_text = diff_staged["stdout"] if diff_staged["success"] else ""



    combined_diff = staged_text if staged_only else (staged_text + "\n" + unstaged_text)

    violations = compliance_guard.scan_diff_for_secrets(combined_diff)



    return {

        "success": True,

        "repo": os.path.basename(repo_path),

        "path": repo_path,

        "files": file_statuses,

        "stat_unstaged": stat_unstaged["stdout"] if stat_unstaged["success"] else "",

        "stat_staged": stat_staged["stdout"] if stat_staged["success"] else "",

        "diff_unstaged": unstaged_text,

        "diff_staged": staged_text,

        "has_changes": bool(file_statuses),

        "violations": violations

    }



# --- Commit History & Commit Builder ---

def get_repo_commits(repo_path: str, count: int = 30) -> Dict[str, Any]:

    """Retrieve recent commits with author, date, message, and Co-authored-by detection."""

    if not os.path.exists(repo_path):

        return {"success": False, "error": f"Path not found: {repo_path}", "commits": []}



    # Format: H(hash)%x09 h(short)%x09 an(name)%x09 ae(email)%x09 ad(date)%x09 s(subject)%x09 b(body)%x1e

    log_res = run_git(

        ["log", f"-n{count}", "--pretty=format:%H%x09%h%x09%an%x09%ae%x09%ad%x09%s%x09%b%x1e", "--date=short"],

        cwd=repo_path

    )

    if not log_res["success"]:

        return {"success": False, "error": log_res["stderr"], "commits": []}



    commits = []

    raw = log_res["stdout"].strip()

    if raw:

        entries = raw.split("\x1e")

        for e in entries:

            e = e.strip()

            if not e:

                continue

            parts = e.split("\t")

            if len(parts) >= 6:

                body = parts[6].strip() if len(parts) > 6 else ""

                has_coauthor = "co-authored-by" in body.lower() or "co-authored-by" in parts[5].lower()

                commits.append({

                    "hash": parts[0],

                    "short_hash": parts[1],

                    "author_name": parts[2],

                    "author_email": parts[3],

                    "date": parts[4],

                    "subject": parts[5],

                    "body": body,

                    "has_coauthor": has_coauthor

                })



    return {"success": True, "repo": os.path.basename(repo_path), "commits": commits}



def create_commit(

    repo_path: str,

    message: str,

    stage_all: bool = True,

    agent_name: Optional[str] = None,

    agent_email: str = "<bot-email>",

    author_mode: str = "co_author"

) -> Dict[str, Any]:

    """Create a git commit protected by compliance guard and auto Co-authored-by signature."""

    if not os.path.exists(repo_path):

        return {"success": False, "error": f"Path not found: {repo_path}"}



    # 1. Panic button check

    can_write, panic_msg = compliance_guard.check_write_permission()

    if not can_write:

        return {"success": False, "blocked": True, "error": panic_msg}



    # 2. Stage changes if requested

    if stage_all:

        add_res = run_git(["add", "-A"], cwd=repo_path)

        if not add_res["success"]:

            return {"success": False, "error": f"Git add failed: {add_res['stderr']}"}



    # 3. Get staged diff for audit

    staged_diff_res = run_git(["diff", "--cached"], cwd=repo_path)

    staged_diff = staged_diff_res["stdout"] if staged_diff_res["success"] else ""



    identity = get_identity(cwd=repo_path)

    author_name = identity.get("name", "")

    author_email = identity.get("email", "")



    # 4. Compliance audit

    audit = compliance_guard.audit_pre_commit(

        repo_path=repo_path,

        diff_text=staged_diff,

        author_name=author_name,

        author_email=author_email

    )

    if audit.get("blocked", False):

        if stage_all:

            run_git(["reset"], cwd=repo_path)

        return {

            "success": False,

            "blocked": True,

            "error": f"[GUARD][COMMIT_BLOCKED] 合规熔断拦截：{audit.get('block_reason', '存在安全违规项')}",

            "violations": audit.get("violations", [])

        }



    # 5. Format commit message with Agent signature
    if not agent_name:
        try:
            from core import agent_detector
            agent_name = agent_detector.get_default_agent_signature()
        except Exception:
            agent_name = "GV_AGY_Gemini-3.8-Flash"

    formatted_msg = compliance_guard.format_commit_message(
        message=message,
        agent_name=agent_name,
        agent_email=agent_email
    )

    # 6. Execute commit
    commit_cmd = ["commit", "-m", formatted_msg]
    if author_mode == "primary_agent":
        commit_cmd.extend(["--author", f"{agent_name} <{agent_email}>"])
    commit_res = run_git(commit_cmd, cwd=repo_path)

    if not commit_res["success"]:

        return {

            "success": False,

            "error": commit_res["stderr"] or commit_res["stdout"]

        }



    head_res = run_git(["rev-parse", "--short", "HEAD"], cwd=repo_path)

    commit_hash = head_res["stdout"] if head_res["success"] else ""



    return {

        "success": True,

        "commit_hash": commit_hash,

        "message": formatted_msg,

        "raw_output": commit_res["stdout"],

        "violations": audit.get("violations", [])

    }



# --- System Explorer, VS Code, and Terminal Launchers ---

def _create_desktop_startupinfo(visible: bool = True) -> subprocess.STARTUPINFO:

    """Create STARTUPINFO targeting the physical interactive desktop WinSta0\\Default."""

    si = subprocess.STARTUPINFO()

    si.dwFlags = subprocess.STARTF_USESHOWWINDOW

    si.wShowWindow = 1 if visible else 0  # 1 = SW_SHOWNORMAL

    # 强制将子进程窗口渲染目标投递至物理显示器的交互桌面

    try:

        si.lpDesktop = r"WinSta0\Default"

    except Exception:

        pass

    return si



def open_in_explorer(repo_path: str) -> Dict[str, Any]:

    """Open repository folder in Windows Explorer targeting user physical desktop."""

    norm_path = os.path.normpath(os.path.abspath(repo_path))

    if not os.path.exists(norm_path):

        return {"success": False, "error": f"路径不存在: {norm_path}"}

    

    # 策略 1: 跨桌面穿透启动 explorer.exe，显式注入 lpDesktop = WinSta0\Default

    try:

        si = _create_desktop_startupinfo(visible=True)

        p = subprocess.Popen(["explorer.exe", norm_path], startupinfo=si)

        return {"success": True, "path": norm_path, "launcher": "desktop_piercing_explorer", "pid": p.pid}

    except Exception:

        pass



    # 策略 2: 通过 ShellExecuteW 显式传递 SW_SHOWNORMAL (1)

    try:

        import ctypes

        res = ctypes.windll.shell32.ShellExecuteW(None, "explore", norm_path, None, None, 1)

        if res > 32:

            return {"success": True, "path": norm_path, "launcher": "shellexecute_explore"}

        res2 = ctypes.windll.shell32.ShellExecuteW(None, "open", norm_path, None, None, 1)

        if res2 > 32:

            return {"success": True, "path": norm_path, "launcher": "shellexecute_open"}

    except Exception:

        pass



    # 策略 3: 系统 start 兜底

    try:

        os.system(f'start explorer.exe "{norm_path}"')

        return {"success": True, "path": norm_path, "launcher": "system_start_explorer"}

    except Exception as e:

        return {"success": False, "error": str(e)}



def open_in_vscode(repo_path: str) -> Dict[str, Any]:

    """Open repository in VS Code targeting user physical desktop."""

    import shutil

    norm_path = os.path.normpath(os.path.abspath(repo_path))

    if not os.path.exists(norm_path):

        return {"success": False, "error": f"路径不存在: {norm_path}"}

    code_bin = shutil.which("code")

    if not code_bin:

        return {

            "success": False,

            "error": "未检测到 VS Code (code 命令行未安装或未加入环境变量 PATH)。已将路径复制到剪贴板。"

        }

    try:

        si = _create_desktop_startupinfo(visible=True)

        p = subprocess.Popen([code_bin, norm_path], startupinfo=si)

        return {"success": True, "path": norm_path, "launcher": "desktop_piercing_code", "pid": p.pid}

    except Exception as e:

        return {"success": False, "error": str(e)}



def open_in_terminal(repo_path: str) -> Dict[str, Any]:

    """Open detached PowerShell terminal targeting user physical desktop."""

    norm_path = os.path.normpath(os.path.abspath(repo_path))

    if not os.path.exists(norm_path):

        return {"success": False, "error": f"路径不存在: {norm_path}"}

    

    # 策略 1: 跨桌面穿透启动 Windows Terminal 或 PowerShell，显式指定 lpDesktop = WinSta0\Default

    try:

        import shutil

        si = _create_desktop_startupinfo(visible=True)

        CREATE_NEW_CONSOLE = 0x00000010

        wt_bin = shutil.which("wt.exe")

        if wt_bin:

            p = subprocess.Popen([wt_bin, "-d", norm_path], startupinfo=si)

            return {"success": True, "path": norm_path, "launcher": "desktop_piercing_wt", "pid": p.pid}



        p = subprocess.Popen(

            ["powershell.exe", "-NoExit", "-NoLogo", "-Command", f"Set-Location -LiteralPath '{norm_path}'"],

            creationflags=CREATE_NEW_CONSOLE,

            startupinfo=si

        )

        return {"success": True, "path": norm_path, "launcher": "desktop_piercing_powershell", "pid": p.pid}

    except Exception:

        pass



    # 策略 2: ShellExecuteW 显式传递 SW_SHOWNORMAL (1)

    try:

        import ctypes

        ps_args = f"-NoExit -NoLogo -Command Set-Location -LiteralPath '{norm_path}'"

        res = ctypes.windll.shell32.ShellExecuteW(None, "open", "powershell.exe", ps_args, None, 1)

        if res > 32:

            return {"success": True, "path": norm_path, "launcher": "powershell_shellexecute"}

    except Exception:

        pass



    return {"success": False, "error": "无法唤起终端"}



def migrate_repo_to_511(repo_path: str, new_user: str = "<owner>") -> Dict[str, Any]:

    """Migrate repository remotes from banned <owner> to new <owner>."""

    norm_path = os.path.normpath(os.path.abspath(repo_path))

    if not os.path.exists(norm_path):

        return {"success": False, "error": f"路径不存在: {norm_path}"}

    

    repo_name = os.path.basename(norm_path)

    changes = []



    # 1. 通过 git remote 获取所有已配置的远程源名字

    rem_proc = run_git(["remote"], cwd=norm_path)

    rem_names = [r.strip() for r in rem_proc["stdout"].splitlines() if r.strip()] if rem_proc["success"] else []



    target_ssh_url = f"git@github.com:{new_user}/{repo_name}.git"



    if rem_names:

        for r in rem_names:

            u_proc = run_git(["remote", "get-url", r], cwd=norm_path)

            cur_url = u_proc["stdout"].strip() if u_proc["success"] else ""

            if "<owner>" in cur_url:

                # 迁移为新账号专用的 SSH 目标地址

                set_res = run_git(["remote", "set-url", r, target_ssh_url], cwd=norm_path)

                if set_res["success"]:

                    changes.append(f"远程源 '{r}': 从 {cur_url} 升级迁移为 {target_ssh_url}")

                # 同时更新 push url

                run_git(["remote", "set-url", "--push", r, target_ssh_url], cwd=norm_path)

    else:

        # 无远程源，直接添加 origin

        add_res = run_git(["remote", "add", "origin", target_ssh_url], cwd=norm_path)

        if add_res["success"]:

            changes.append(f"新增远程源 'origin' -> {target_ssh_url}")



    # 2. 净化项目级提交者信息为 <owner>

    run_git(["config", "user.name", new_user], cwd=norm_path)

    changes.append(f"配置项目级 Git 作者: user.name={new_user}")



    # 彻底清理 .git/config 中的残留旧账号配置段 (如 Git LFS 端点等)

    git_cfg_path = os.path.join(norm_path, ".git", "config")

    if os.path.exists(git_cfg_path):

        try:

            with open(git_cfg_path, "r", encoding="utf-8", errors="ignore") as f_cfg:

                cfg_txt = f_cfg.read()

            if "<owner>" in cfg_txt:

                new_cfg_txt = cfg_txt.replace("<owner>", new_user)

                with open(git_cfg_path, "w", encoding="utf-8") as f_cfg:

                    f_cfg.write(new_cfg_txt)

                changes.append(f"净化 .git/config 中的残留旧账号配置段为 {new_user}")

        except Exception:

            pass



    # 3. 立即更新 managed_repos.json 保证持久化同步

    try:

        cfg = load_managed_repos_config()

        for mr in cfg.get("managed_repos", []):

            if os.path.normpath(mr.get("path", "")).lower() == norm_path.lower():

                mr["owner"] = new_user

        save_managed_repos_config(cfg)

    except Exception:

        pass

    invalidate_repos_cache()



    return {

        "success": True,

        "repo_path": norm_path,

        "repo_name": repo_name,

        "new_user": new_user,

        "target_url": target_ssh_url,

        "changes": changes,

        "message": f"成功将仓库迁移至 {new_user} 名下！您在 GitHub 511 后台创建同名仓库后即可直接推送。"

    }





def migrate_all_repos_to_511(new_user: str = "<owner>") -> Dict[str, Any]:

    """Batch migrate all repositories still associated with banned <owner> to <owner>."""

    cfg = load_managed_repos_config()

    managed_list = cfg.get("managed_repos", [])

    

    migrated_results = []

    failed_results = []

    my_identifiers = get_user_identifiers()

    

    for mr in managed_list:

        p = mr.get("path", "")

        if not os.path.exists(os.path.join(p, ".git")):

            continue

            

        remotes = get_repo_remotes_fast(p)

        ownership = detect_repo_ownership(p, my_identifiers=my_identifiers, remotes_data=remotes)

        

        if ownership.get("needs_migration") or mr.get("owner") == "<owner>":

            res = migrate_repo_to_511(p, new_user=new_user)

            if res.get("success"):

                migrated_results.append({

                    "name": mr.get("name") or os.path.basename(p),

                    "path": p,

                    "target_url": res.get("target_url")

                })

            else:

                failed_results.append({

                    "name": mr.get("name") or os.path.basename(p),

                    "path": p,

                    "error": res.get("error")

                })



    invalidate_repos_cache()

    return {

        "success": True,

        "total_migrated": len(migrated_results),

        "total_failed": len(failed_results),

        "migrated": migrated_results,

        "failed": failed_results,

        "message": f"批量迁移完成：共成功迁移 {len(migrated_results)} 个仓库至 {new_user} 名下。"

    }





def locate_folder_path(folder_name: str, hint_paths: Optional[List[str]] = None) -> List[str]:

    """Locate full absolute path for a picked folder name across workspaces fast."""

    if not folder_name:

        return []

    norm_name = folder_name.strip().lower()

    matches = []

    

    cfg = load_managed_repos_config()

    persisted_roots = [os.path.dirname(os.path.normpath(r.get("path", ""))) for r in cfg.get("managed_repos", []) if r.get("path")]

    

    search_roots = ["<vault-root>", "<path>\\AgentWorkSpace", "<path>\\workSpace", "<path>\\code"]

    if hint_paths:

        search_roots = hint_paths + search_roots

    search_roots = list(dict.fromkeys([p for p in persisted_roots + search_roots if p and os.path.exists(p)]))

    

    skip_lookup = {

        ".git", "node_modules", ".venv", "venv", "dist", "build", ".cache",

        "$recycle.bin", "system volume information", "recovery", "windows", "program files"

    }

    

    for sroot in search_roots:

        norm_sroot = os.path.normpath(sroot)

        if os.path.basename(norm_sroot).lower() == norm_name:

            if os.path.exists(os.path.join(norm_sroot, ".git")):

                matches.append(norm_sroot)

                break

        try:

            for root, dirs, files in os.walk(norm_sroot):

                dirs[:] = [d for d in dirs if d.lower() not in skip_lookup]

                if os.path.basename(root).lower() == norm_name:

                    if os.path.exists(os.path.join(root, ".git")):

                        matches.append(os.path.normpath(root))

                        dirs.clear()

                        break

                if root.count(os.sep) - norm_sroot.count(os.sep) >= 2:

                    dirs.clear()

        except Exception:

            pass

        if matches:

            break

            

    return list(dict.fromkeys(matches))



def trigger_backup(repo_paths: List[str], backup_dir: str = "<path>\\Git_Disaster_Backup") -> Dict[str, Any]:

    os.makedirs(backup_dir, exist_ok=True)

    results = []

    

    for path in repo_paths:

        name = os.path.basename(path)

        mirror_path = os.path.join(backup_dir, f"{name}.mirror.git")

        

        if os.path.exists(mirror_path):

            up_res = run_git(["remote", "update", "--prune"], cwd=mirror_path, timeout=30)

            results.append({

                "repo": name,

                "action": "incremental_update",

                "success": up_res["success"],

                "path": mirror_path,

                "output": up_res["stdout"] + up_res["stderr"]

            })

        else:

            cl_res = run_git(["clone", "--mirror", path, mirror_path], timeout=60)

            results.append({

                "repo": name,

                "action": "initial_clone",

                "success": cl_res["success"],

                "path": mirror_path,

                "output": cl_res["stdout"] + cl_res["stderr"]

            })

            

    return {"backup_dir": backup_dir, "results": results}





def create_github_remote_repo(

    repo_path: str,

    repo_name: Optional[str] = None,

    is_private: bool = True,

    token: Optional[str] = None,

    push_initial: bool = True

) -> Dict[str, Any]:

    """Create remote repository on GitHub under current user and push initial branch."""

    norm_path = os.path.normpath(os.path.abspath(repo_path))

    if not os.path.exists(os.path.join(norm_path, ".git")):

        return {"success": False, "error": f"不是有效的 Git 仓库路径: {norm_path}"}

    

    if not repo_name:

        repo_name = os.path.basename(norm_path)



    # Resolve GitHub PAT

    if not token:

        try:

            from core import credential_vault

            token = credential_vault.get_plain_token("github")

        except Exception:

            token = ""

            

    if not token:

        return {

            "success": False,

            "need_token": True,

            "error": "未检测到具有 repo 权限的 GitHub Personal Access Token (PAT)。请在弹窗中录入 Token 后重试。"

        }



    import urllib.request

    import urllib.error



    url = "https://api.github.com/user/repos"

    payload = {

        "name": repo_name,

        "private": is_private,

        "description": f"Repository {repo_name} managed by Git-Vault Enterprise",

        "auto_init": False

    }



    headers = {

        "Authorization": f"Bearer {token.strip()}",

        "Accept": "application/vnd.github+json",

        "User-Agent": "Git-Vault-Enterprise",

        "Content-Type": "application/json"

    }



    # 直连失败后自动走网络路由代理，最后回退到本机 11455（国内网络对 api.github.com 常有阻断）
    channels = [None]
    try:
        from core import network_router
        gh_route = network_router.load_network_routes().get("routes", {}).get("github", {})
        route_proxy = (gh_route.get("proxy_url") or "").strip()
        if route_proxy:
            channels.append(route_proxy)
    except Exception:
        pass
    env_proxy = os.environ.get("GITVAULT_GITHUB_API_PROXY", "").strip()
    if env_proxy:
        channels.append(env_proxy)
    channels.append("http://127.0.0.1:11455")
    deduped, seen = [], set()
    for c in channels:
        if c not in seen:
            seen.add(c)
            deduped.append(c)
    channels = deduped

    created = False
    channel_used = "direct"
    last_err = None
    for channel in channels:
        try:
            proxy_handler = urllib.request.ProxyHandler({"http": channel, "https": channel} if channel else {})
            opener = urllib.request.build_opener(proxy_handler)
            req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST")
            with opener.open(req, timeout=15) as resp:
                json.loads(resp.read().decode("utf-8"))
            created = True
            channel_used = channel or "direct"
            last_err = None
            break
        except urllib.error.HTTPError as e:
            err_body = e.read().decode("utf-8", errors="replace")
            if e.code == 422 and "already exists" in err_body.lower():
                created = False
                channel_used = channel or "direct"
                last_err = None
                break
            last_err = f"HTTP {e.code}: {err_body[:200]}"
            continue
        except Exception as e:
            last_err = f"{type(e).__name__}: {e}"
            continue

    if last_err is not None and not created:
        return {"success": False, "error": f"GitHub API 建库失败（直连与代理均不可用）: {last_err}"}



    # Automatically trigger initial push via SSH (可按需关闭，避免把历史一并带上去)

    sync_res = None

    if push_initial:

        sync_res = sync_repository(norm_path, target_platform="github")

    

    return {

        "success": True,

        "created": created,

        "pushed": bool(push_initial),

        "via": channel_used,

        "repo_name": repo_name,

        "repo_path": norm_path,

        "sync_result": sync_res,

        "message": f"成功{'创建并' if created else ''}推送到 GitHub <owner>/{repo_name}！"

    }



def create_gitlab_remote_repo(
    repo_path: str,
    repo_name: Optional[str] = None,
    is_private: bool = True,
    token: Optional[str] = None
) -> Dict[str, Any]:
    """Create remote repository on GitLab via API and push initial branch."""
    norm_path = os.path.normpath(os.path.abspath(repo_path))
    if not os.path.exists(os.path.join(norm_path, ".git")):
        return {"success": False, "error": f"不是有效的 Git 仓库路径: {norm_path}"}
    
    if not repo_name:
        repo_name = os.path.basename(norm_path)

    if not token:
        try:
            from core import credential_vault
            token = credential_vault.get_plain_token("gitlab")
        except Exception:
            token = ""

    if not token:
        return {
            "success": False,
            "need_token": True,
            "error": "未检测到 GitLab 访问令牌。请先在凭据库中配置。"
        }

    import urllib.request, urllib.error
    url = "https://gitlab.com/api/v4/projects"
    payload = {
        "name": repo_name,
        "visibility": "private" if is_private else "public",
        "description": f"Repository {repo_name} managed by Git-Vault",
        "initialize_with_readme": False
    }

    # Use proxy
    proxy_handler = urllib.request.ProxyHandler({'https': 'http://127.0.0.1:11455'})
    opener = urllib.request.build_opener(proxy_handler)

    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "PRIVATE-TOKEN": token.strip(),
            "Content-Type": "application/json",
            "User-Agent": "GitVault/1.0"
        },
        method="POST"
    )

    created = False
    try:
        with opener.open(req, timeout=15) as resp:
            resp_data = json.loads(resp.read().decode("utf-8"))
            created = True
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        if e.code == 400 and ("already exists" in err_body.lower() or "has already been taken" in err_body.lower()):
            created = False
        else:
            return {
                "success": False,
                "status_code": e.code,
                "error": f"GitLab API 建库失败 (HTTP {e.code}): {err_body}"
            }
    except Exception as e:
        return {"success": False, "error": f"请求 GitLab API 异常: {str(e)}"}

    # Automatically trigger sync
    sync_res = sync_repository(norm_path, target_platform="gitlab")
    return {
        "success": True,
        "created": created,
        "repo_name": repo_name,
        "repo_path": norm_path,
        "sync_result": sync_res,
        "message": f"成功{'创建并' if created else ''}推送到 GitLab <owner>/{repo_name}！"
    }






def batch_create_github_remote_repos(

    repo_paths: Optional[List[str]] = None,

    is_private: bool = True,

    token: Optional[str] = None

) -> Dict[str, Any]:

    """Batch create GitHub repositories for all managed repos needing GitHub remotes."""

    if not repo_paths:

        cfg = load_managed_repos_config()

        repo_paths = [r.get("path") for r in cfg.get("managed_repos", []) if r.get("path")]

        

    results = []

    success_count = 0

    fail_count = 0

    

    for rp in repo_paths:

        if not os.path.exists(os.path.join(rp, ".git")):

            continue

        res = create_github_remote_repo(rp, is_private=is_private, token=token)

        results.append(res)

        if res.get("success"):

            success_count += 1

        else:

            fail_count += 1

            

    return {

        "success": True,

        "total": len(results),

        "success_count": success_count,

        "fail_count": fail_count,

        "results": results,

        "message": f"批量建库完成：成功 {success_count} 个，失败 {fail_count} 个。"

    }



