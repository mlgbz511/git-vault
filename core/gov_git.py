# core/gov_git.py
# Git-Vault governance v3: structured status / branch / merge (rule 14 entry points)
from typing import Any, Dict, List, Optional

from core import compliance_guard, git_engine


def get_repo_status(repo_path: str) -> Dict[str, Any]:
    """结构化输出工作区状态（porcelain v1）。只读。"""
    probe = git_engine.run_git(["rev-parse", "--is-inside-work-tree"], cwd=repo_path)
    if not probe.get("success"):
        return {"success": False, "error": "Not a git repository: %s" % repo_path}
    st = git_engine.run_git(["status", "--porcelain=v1", "-b"], cwd=repo_path)
    if not st.get("success"):
        return {"success": False, "error": st.get("stderr") or st.get("stdout")}
    branch, ahead, behind = "", 0, 0
    staged, unstaged, untracked = [], [], []
    for raw in (st.get("stdout") or "").splitlines():
        if raw.startswith("##"):
            head = raw[2:].strip()
            branch = head.split("...")[0].strip()
            if "ahead " in head:
                try:
                    ahead = int(head.split("ahead ")[1].split("]")[0].split(",")[0])
                except Exception:
                    ahead = 0
            if "behind " in head:
                try:
                    behind = int(head.split("behind ")[1].split("]")[0].split(",")[0])
                except Exception:
                    behind = 0
            continue
        if len(raw) < 3:
            continue
        x, y, path = raw[0], raw[1], raw[3:]
        if x == "?" and y == "?":
            untracked.append(path)
            continue
        if x not in (" ", "?"):
            staged.append(path)
        if y not in (" ", "?"):
            unstaged.append(path)
    head_res = git_engine.run_git(["rev-parse", "--short", "HEAD"], cwd=repo_path)
    return {
        "success": True, "repo_path": repo_path, "branch": branch,
        "ahead": ahead, "behind": behind,
        "staged": staged, "unstaged": unstaged, "untracked": untracked,
        "is_clean": not (staged or unstaged or untracked),
        "last_commit": (head_res.get("stdout") or "").strip() if head_res.get("success") else "",
    }


def git_branch_manage(repo_path: str, action: str, name: str = "", base: str = "", confirm: bool = False) -> Dict[str, Any]:
    """列出/创建/切换/删除分支。删除需 confirm=true，当前分支禁删。"""
    if action not in ("list", "create", "switch", "delete"):
        return {"success": False, "error": "action 必须是 list/create/switch/delete"}
    if action != "list":
        can_write, panic_msg = compliance_guard.check_write_permission()
        if not can_write:
            return {"success": False, "blocked": True, "error": panic_msg}
    cur_res = git_engine.run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_path)
    current = (cur_res.get("stdout") or "").strip() if cur_res.get("success") else ""
    if action == "list":
        res = git_engine.run_git(["branch", "--format=%(refname:short)"], cwd=repo_path)
        branches = [b for b in (res.get("stdout") or "").splitlines() if b]
        return {"success": res.get("success", False), "branches": branches, "current": current,
                "error": res.get("stderr", "") if not res.get("success") else ""}
    if not name:
        return {"success": False, "error": "name 为必填项"}
    if action == "create":
        res = git_engine.run_git(["branch", name] + ([base] if base else []), cwd=repo_path)
    elif action == "switch":
        res = git_engine.run_git(["switch", name], cwd=repo_path)
        if not res.get("success"):
            res = git_engine.run_git(["checkout", name], cwd=repo_path)
    else:
        if not confirm:
            return {"success": False, "error": "删除分支需 confirm=true（规则 14 §2）"}
        if name == current:
            return {"success": False, "error": "不能删除当前分支 %s" % name}
        res = git_engine.run_git(["branch", "-d", name], cwd=repo_path)
    return {"success": res.get("success", False), "action": action, "name": name,
            "current": current, "stdout": res.get("stdout", ""), "stderr": res.get("stderr", "")}


def git_merge(repo_path: str, source: str, into: str = "main", strategy: str = "ff", dry_run: bool = True) -> Dict[str, Any]:
    """受控合并：ff / no-ff / squash。dry_run 用 --no-commit 探测冲突后 abort，不改工作树。"""
    can_write, panic_msg = compliance_guard.check_write_permission()
    if not can_write:
        return {"success": False, "blocked": True, "error": panic_msg}
    if strategy not in ("ff", "no-ff", "squash"):
        return {"success": False, "error": "strategy 必须是 ff/no-ff/squash"}
    cur_res = git_engine.run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_path)
    current = (cur_res.get("stdout") or "").strip() if cur_res.get("success") else ""
    if into and current and into != current:
        return {"success": False, "error": "当前分支是 %s，请先切换到 %s" % (current, into)}
    src = git_engine.run_git(["rev-parse", "--verify", source], cwd=repo_path)
    if not src.get("success"):
        return {"success": False, "error": "source 不存在: %s" % source}
    ff_res = git_engine.run_git(["merge-base", "--is-ancestor", "HEAD", source], cwd=repo_path)
    ff_possible = bool(ff_res.get("success"))
    if strategy == "ff" and not ff_possible:
        return {"success": False, "fast_forward": False, "current": current,
                "error": "非快进合并被拒绝（规则 14 §2 只允许 ff/squash）"}
    if dry_run:
        probe = git_engine.run_git(["merge", "--no-commit", "--no-ff", source], cwd=repo_path)
        conflict_res = git_engine.run_git(["diff", "--name-only", "--diff-filter=U"], cwd=repo_path)
        conflicts = [c for c in (conflict_res.get("stdout") or "").splitlines() if c] if conflict_res.get("success") else []
        git_engine.run_git(["merge", "--abort"], cwd=repo_path)
        return {"success": True, "dry_run": True, "current": current, "source": source,
                "fast_forward": ff_possible, "conflicts": conflicts, "clean": not conflicts,
                "stdout": (probe.get("stdout") or "")[-1500:], "stderr": (probe.get("stderr") or "")[-1500:]}
    if strategy == "ff":
        res = git_engine.run_git(["merge", "--ff-only", source], cwd=repo_path)
    elif strategy == "squash":
        res = git_engine.run_git(["merge", "--squash", source], cwd=repo_path)
    else:
        res = git_engine.run_git(["merge", "--no-ff", "-m", "merge %s into %s" % (source, current), source], cwd=repo_path)
    head_res = git_engine.run_git(["rev-parse", "--short", "HEAD"], cwd=repo_path)
    return {"success": res.get("success", False), "dry_run": False, "current": current,
            "strategy": strategy, "head": (head_res.get("stdout") or "").strip(),
            "stdout": res.get("stdout", ""), "stderr": res.get("stderr", "")}
