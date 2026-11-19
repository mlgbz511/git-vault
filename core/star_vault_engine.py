# core/star_vault_engine.py
# Antigravity Git-Vault - Star Vault Engine
# GitHub Star Asset Disaster Recovery, List Organization, and Multi-Cloud Cataloging

import os
import sys
import json
import time
import re
import threading
import urllib.request
import urllib.error
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Generator

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core import compliance_guard, credential_vault

CONFIG_DIR = os.path.join(BASE_DIR, "config")
VAULT_STARS_FILE = os.path.join(CONFIG_DIR, "starred_vault.json")
STARS_INDEX_FILE = os.path.join(BASE_DIR, "STARS_INDEX.md")

_VAULT_LOCK = threading.Lock()

LANGUAGE_COLORS: Dict[str, str] = {
    "Python": "#3572A5",
    "TypeScript": "#3178c6",
    "JavaScript": "#f1e05a",
    "Rust": "#dea584",
    "C++": "#f34b7d",
    "C": "#555555",
    "Go": "#00ADD8",
    "Java": "#b07219",
    "HTML": "#e34c26",
    "CSS": "#563d7c",
    "Shell": "#89e051",
    "Vue": "#41b883",
    "PHP": "#4F5D95",
    "Ruby": "#701516",
    "Swift": "#F05138",
    "Kotlin": "#A97BFF",
    "Markdown": "#083fa1",
    "Lua": "#000080",
    "Dart": "#00B4AB"
}

# 19 Repositories across 8 Lists recovered from banned account <owner>
DEFAULT_INITIAL_REPOSITORIES: List[Dict[str, Any]] = [
    {
        "full_name": "ConardLi/garden-skills",
        "owner": "ConardLi",
        "name": "garden-skills",
        "description": "ConardLi's open-source Skills collection, featuring web design, knowledge retrieval, image generation.",
        "primary_language": "JavaScript",
        "language_color": "#f1e05a",
        "stargazers_count": 14700,
        "lists": ["SKILL"],
        "html_url": "https://github.com/ConardLi/garden-skills",
        "starred_at": "2024-03-10T10:00:00Z",
        "source": "seed"
    },
    {
        "full_name": "anthropics/anthropic-quickstarts",
        "owner": "anthropics",
        "name": "anthropic-quickstarts",
        "description": "A collection of projects designed to help developers quickly build with Claude.",
        "primary_language": "TypeScript",
        "language_color": "#3178c6",
        "stargazers_count": 8900,
        "lists": ["SKILL"],
        "html_url": "https://github.com/anthropics/anthropic-quickstarts",
        "starred_at": "2024-03-12T11:00:00Z",
        "source": "seed"
    },
    {
        "full_name": "microsoft/autogen",
        "owner": "microsoft",
        "name": "autogen",
        "description": "A programming framework for agentic AI.",
        "primary_language": "Python",
        "language_color": "#3572A5",
        "stargazers_count": 32500,
        "lists": ["agent tool"],
        "html_url": "https://github.com/microsoft/autogen",
        "starred_at": "2023-10-15T08:00:00Z",
        "source": "seed"
    },
    {
        "full_name": "langchain-ai/langchain",
        "owner": "langchain-ai",
        "name": "langchain",
        "description": "Building applications with LLMs through composability.",
        "primary_language": "Python",
        "language_color": "#3572A5",
        "stargazers_count": 92100,
        "lists": ["agent tool"],
        "html_url": "https://github.com/langchain-ai/langchain",
        "starred_at": "2023-08-01T09:00:00Z",
        "source": "seed"
    },
    {
        "full_name": "Significant-Gravitas/AutoGPT",
        "owner": "Significant-Gravitas",
        "name": "AutoGPT",
        "description": "AutoGPT is the vision of accessible AI for everyone, to use and to build on.",
        "primary_language": "Python",
        "language_color": "#3572A5",
        "stargazers_count": 165200,
        "lists": ["agent tool"],
        "html_url": "https://github.com/Significant-Gravitas/AutoGPT",
        "starred_at": "2023-04-10T12:00:00Z",
        "source": "seed"
    },
    {
        "full_name": "run-llama/llama_index",
        "owner": "run-llama",
        "name": "llama_index",
        "description": "LlamaIndex is a data framework for your LLM applications.",
        "primary_language": "Python",
        "language_color": "#3572A5",
        "stargazers_count": 36400,
        "lists": ["agent tool"],
        "html_url": "https://github.com/run-llama/llama_index",
        "starred_at": "2023-09-20T14:00:00Z",
        "source": "seed"
    },
    {
        "full_name": "open-interpreter/open-interpreter",
        "owner": "open-interpreter",
        "name": "open-interpreter",
        "description": "A natural language interface for computers.",
        "primary_language": "Python",
        "language_color": "#3572A5",
        "stargazers_count": 51800,
        "lists": ["agent tool"],
        "html_url": "https://github.com/open-interpreter/open-interpreter",
        "starred_at": "2023-09-25T15:00:00Z",
        "source": "seed"
    },
    {
        "full_name": "astral-sh/uv",
        "owner": "astral-sh",
        "name": "uv",
        "description": "An extremely fast Python package and project manager, written in Rust.",
        "primary_language": "Rust",
        "language_color": "#dea584",
        "stargazers_count": 42100,
        "lists": ["?Tool?"],
        "html_url": "https://github.com/astral-sh/uv",
        "starred_at": "2024-02-18T10:00:00Z",
        "source": "seed"
    },
    {
        "full_name": "BurntSushi/ripgrep",
        "owner": "BurntSushi",
        "name": "ripgrep",
        "description": "ripgrep recursively searches directories for a regex pattern while respecting your gitignore.",
        "primary_language": "Rust",
        "language_color": "#dea584",
        "stargazers_count": 48300,
        "lists": ["?Tool?"],
        "html_url": "https://github.com/BurntSushi/ripgrep",
        "starred_at": "2022-01-10T10:00:00Z",
        "source": "seed"
    },
    {
        "full_name": "cloudflare/wrangler",
        "owner": "cloudflare",
        "name": "wrangler",
        "description": "The CLI for Cloudflare Workers.",
        "primary_language": "TypeScript",
        "language_color": "#3178c6",
        "stargazers_count": 6200,
        "lists": ["Cloudflare"],
        "html_url": "https://github.com/cloudflare/wrangler",
        "starred_at": "2023-05-15T08:00:00Z",
        "source": "seed"
    },
    {
        "full_name": "cloudflare/workers-sdk",
        "owner": "cloudflare",
        "name": "workers-sdk",
        "description": "Repository for Cloudflare Workers SDK tools and libraries.",
        "primary_language": "TypeScript",
        "language_color": "#3178c6",
        "stargazers_count": 4800,
        "lists": ["Cloudflare"],
        "html_url": "https://github.com/cloudflare/workers-sdk",
        "starred_at": "2023-06-20T09:00:00Z",
        "source": "seed"
    },
    {
        "full_name": "cloudflare/miniflare",
        "owner": "cloudflare",
        "name": "miniflare",
        "description": "Fully-local simulator for Cloudflare Workers.",
        "primary_language": "TypeScript",
        "language_color": "#3178c6",
        "stargazers_count": 2100,
        "lists": ["Cloudflare"],
        "html_url": "https://github.com/cloudflare/miniflare",
        "starred_at": "2023-07-01T10:00:00Z",
        "source": "seed"
    },
    {
        "full_name": "cloudflare/workerd",
        "owner": "cloudflare",
        "name": "workerd",
        "description": "The JavaScript / Wasm runtime that powers Cloudflare Workers.",
        "primary_language": "C++",
        "language_color": "#f34b7d",
        "stargazers_count": 5400,
        "lists": ["Cloudflare"],
        "html_url": "https://github.com/cloudflare/workerd",
        "starred_at": "2023-08-10T11:00:00Z",
        "source": "seed"
    },
    {
        "full_name": "kamranahmedse/developer-roadmap",
        "owner": "kamranahmedse",
        "name": "developer-roadmap",
        "description": "Interactive roadmaps, guides and other educational content for developers.",
        "primary_language": "TypeScript",
        "language_color": "#3178c6",
        "stargazers_count": 290400,
        "lists": ["Book"],
        "html_url": "https://github.com/kamranahmedse/developer-roadmap",
        "starred_at": "2022-03-05T12:00:00Z",
        "source": "seed"
    },
    {
        "full_name": "donnemartin/system-design-primer",
        "owner": "donnemartin",
        "name": "system-design-primer",
        "description": "Learn how to design large-scale systems. Prep for the system design interview.",
        "primary_language": "Python",
        "language_color": "#3572A5",
        "stargazers_count": 275100,
        "lists": ["Book"],
        "html_url": "https://github.com/donnemartin/system-design-primer",
        "starred_at": "2022-04-12T14:00:00Z",
        "source": "seed"
    },
    {
        "full_name": "godotengine/godot",
        "owner": "godotengine",
        "name": "godot",
        "description": "Free and open source 2D and 3D game engine.",
        "primary_language": "C++",
        "language_color": "#f34b7d",
        "stargazers_count": 91200,
        "lists": ["GAME"],
        "html_url": "https://github.com/godotengine/godot",
        "starred_at": "2023-01-20T16:00:00Z",
        "source": "seed"
    },
    {
        "full_name": "bevyengine/bevy",
        "owner": "bevyengine",
        "name": "bevy",
        "description": "A refreshingly simple data-driven game engine built in Rust.",
        "primary_language": "Rust",
        "language_color": "#dea584",
        "stargazers_count": 35100,
        "lists": ["GAME"],
        "html_url": "https://github.com/bevyengine/bevy",
        "starred_at": "2023-02-14T17:00:00Z",
        "source": "seed"
    },
    {
        "full_name": "google/antigravity-toolkit",
        "owner": "google",
        "name": "antigravity-toolkit",
        "description": "Developer tools for Advanced Agentic Coding and orchestrations.",
        "primary_language": "TypeScript",
        "language_color": "#3178c6",
        "stargazers_count": 1800,
        "lists": ["AGY"],
        "html_url": "https://github.com/google/antigravity-toolkit",
        "starred_at": "2024-04-01T18:00:00Z",
        "source": "seed"
    },
    {
        "full_name": "deepseek-ai/DeepSeek-V2",
        "owner": "deepseek-ai",
        "name": "DeepSeek-V2",
        "description": "A Strong, Economical, and Efficient Mixture-of-Experts Language Model.",
        "primary_language": "Python",
        "language_color": "#3572A5",
        "stargazers_count": 18900,
        "lists": ["DSH"],
        "html_url": "https://github.com/deepseek-ai/DeepSeek-V2",
        "starred_at": "2024-05-08T19:00:00Z",
        "source": "seed"
    }
]

DEFAULT_INITIAL_LISTS: List[Dict[str, Any]] = [
    {"id": "list_agent_tool", "name": "agent tool", "description": "Agentic AI tools and frameworks", "count": 5},
    {"id": "list_SKILL", "name": "SKILL", "description": "AI Agent skills and toolkits", "count": 2},
    {"id": "list_Tool", "name": "?Tool?", "description": "High performance developer CLI tools", "count": 2},
    {"id": "list_Book", "name": "Book", "description": "Educational architectures and roadmaps", "count": 2},
    {"id": "list_Cloudflare", "name": "Cloudflare", "description": "Cloudflare Workers and edge ecosystem", "count": 4},
    {"id": "list_GAME", "name": "GAME", "description": "Game engines and graphics frameworks", "count": 2},
    {"id": "list_AGY", "name": "AGY", "description": "Antigravity coding frameworks", "count": 1},
    {"id": "list_DSH", "name": "DSH", "description": "DeepSeek models and architectures", "count": 1}
]


def _format_stars_compact(stars: int) -> str:
    """Format star count to 14.7k or 920 format."""
    if stars >= 1000:
        return f"{stars / 1000:.1f}k".replace(".0k", "k")
    return str(stars)


def _recalculate_vault_stats(vault: Dict[str, Any]) -> None:
    """Recalculate list counts and language distribution."""
    repos = vault.get("repositories", [])
    lists = vault.get("lists", [])

    # Map of list name to count
    counts: Dict[str, int] = {}
    languages: Dict[str, int] = {}

    for r in repos:
        # Standardize fields
        r_lists = r.get("lists", [])
        if isinstance(r_lists, str):
            r_lists = [r_lists]
        r["lists"] = r_lists

        for l_name in r_lists:
            counts[l_name] = counts.get(l_name, 0) + 1

        lang = r.get("primary_language") or r.get("language") or "Other"
        r["primary_language"] = lang
        r["language"] = lang
        languages[lang] = languages.get(lang, 0) + 1

        if not r.get("language_color"):
            r["language_color"] = LANGUAGE_COLORS.get(lang, "#8b949e")

    # Update counts on existing lists
    seen_list_names = set()
    for l_obj in lists:
        name = l_obj.get("name", "")
        seen_list_names.add(name)
        cnt = counts.get(name, 0)
        l_obj["count"] = cnt
        l_obj["repo_count"] = cnt

    # Add missing lists if any repo references a new list
    for name, cnt in counts.items():
        if name and name not in seen_list_names:
            slug = re.sub(r'[^a-zA-Z0-9_-]', '_', name)
            lists.append({
                "id": f"list_{slug}",
                "name": name,
                "description": "",
                "count": cnt,
                "repo_count": cnt
            })

    vault["lists"] = lists
    vault["stats"] = {
        "total_stars": len(repos),
        "total_lists": len(lists),
        "languages": dict(sorted(languages.items(), key=lambda item: item[1], reverse=True))
    }


def load_starred_vault(vault_file: Optional[str] = None) -> Dict[str, Any]:
    """Load starred vault data, seeding initial data if file does not exist."""
    target_file = vault_file or VAULT_STARS_FILE
    with _VAULT_LOCK:
        if os.path.exists(target_file):
            try:
                with open(target_file, "r", encoding="utf-8") as f:
                    vault = json.load(f)
                    _recalculate_vault_stats(vault)
                    return vault
            except Exception as e:
                print(f"[StarVault] Load error: {e}, falling back to defaults")

        # Initialize defaults
        vault = {
            "version": "1.0",
            "last_sync": datetime.now().isoformat(),
            "account": "<owner>",
            "banned_source_account": "<owner>",
            "lists": [dict(l) for l in DEFAULT_INITIAL_LISTS],
            "repositories": [dict(r) for r in DEFAULT_INITIAL_REPOSITORIES]
        }
        _recalculate_vault_stats(vault)
        try:
            os.makedirs(os.path.dirname(target_file), exist_ok=True)
            with open(target_file, "w", encoding="utf-8") as f:
                json.dump(vault, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"[StarVault] Failed to save default seed: {e}")

        return vault


def save_starred_vault(vault: Dict[str, Any], vault_file: Optional[str] = None) -> bool:
    """Save starred vault to JSON disk atomically."""
    target_file = vault_file or VAULT_STARS_FILE
    with _VAULT_LOCK:
        try:
            _recalculate_vault_stats(vault)
            vault["last_sync"] = datetime.now().isoformat()
            os.makedirs(os.path.dirname(target_file), exist_ok=True)
            temp_file = target_file + ".tmp"
            with open(temp_file, "w", encoding="utf-8") as f:
                json.dump(vault, f, indent=2, ensure_ascii=False)
            if os.path.exists(target_file):
                os.replace(temp_file, target_file)
            else:
                os.rename(temp_file, target_file)
            return True
        except Exception as e:
            print(f"[StarVault] Save error: {e}")
            return False


def get_vault_summary(vault_file: Optional[str] = None) -> Dict[str, Any]:
    """Retrieve quick stats and list overview."""
    vault = load_starred_vault(vault_file)
    return {
        "account": vault.get("account", "<owner>"),
        "banned_source_account": vault.get("banned_source_account", "<owner>"),
        "last_sync": vault.get("last_sync", ""),
        "stats": vault.get("stats", {}),
        "lists": vault.get("lists", [])
    }


def query_vault(
    list_name: Optional[str] = None,
    search: Optional[str] = None,
    language: Optional[str] = None,
    vault_file: Optional[str] = None
) -> Dict[str, Any]:
    """Query repositories from vault with multi-dimension filtering."""
    vault = load_starred_vault(vault_file)
    repos = vault.get("repositories", [])
    
    filtered = []
    search_lower = (search or "").strip().lower()
    lang_filter = (language or "").strip()
    l_filter = (list_name or "").strip()

    for r in repos:
        # 1. List filter
        if l_filter and l_filter.lower() != "all":
            r_lists = r.get("lists", [])
            if l_filter not in r_lists:
                continue

        # 2. Language filter
        if lang_filter and lang_filter.lower() != "all":
            if (r.get("primary_language") or "").lower() != lang_filter.lower():
                continue

        # 3. Search query (matches full_name, description, owner)
        if search_lower:
            fn = r.get("full_name", "").lower()
            desc = (r.get("description") or "").lower()
            if search_lower not in fn and search_lower not in desc:
                continue

        # Compute formatted stars string for UI convenience
        st_count = r.get("stargazers_count", 0)
        r_copy = dict(r)
        r_copy["stars_compact"] = _format_stars_compact(st_count)
        filtered.append(r_copy)

    return {
        "success": True,
        "account": vault.get("account", "<owner>"),
        "banned_source_account": vault.get("banned_source_account", "<owner>"),
        "stats": vault.get("stats", {}),
        "lists": vault.get("lists", []),
        "total_matched": len(filtered),
        "repositories": filtered
    }


def merge_repos_into_vault(
    new_repos: List[Dict[str, Any]],
    default_list: Optional[str] = None,
    vault_file: Optional[str] = None
) -> Dict[str, Any]:
    """Incremental merge & dedup for repository assets."""
    vault = load_starred_vault(vault_file)
    repos = vault.get("repositories", [])
    repo_map: Dict[str, Dict[str, Any]] = {
        r.get("full_name", "").lower(): r for r in repos if r.get("full_name")
    }

    added_count = 0
    updated_count = 0

    for nr in new_repos:
        fn = (nr.get("full_name") or "").strip()
        if not fn or "/" not in fn:
            continue
        key = fn.lower()
        parts = fn.split("/")
        owner = nr.get("owner") or parts[0]
        name = nr.get("name") or parts[1]

        target_lists = nr.get("lists") or []
        if isinstance(target_lists, str):
            target_lists = [target_lists]
        if default_list and default_list not in target_lists:
            target_lists.append(default_list)

        lang = nr.get("primary_language") or "Other"
        lang_color = nr.get("language_color") or LANGUAGE_COLORS.get(lang, "#8b949e")

        if key in repo_map:
            # Update existing
            existing = repo_map[key]
            # Union of lists
            cur_lists = set(existing.get("lists", []))
            cur_lists.update(target_lists)
            existing["lists"] = sorted(list(cur_lists))

            # Enrich description & metadata if new has it and existing is empty
            if nr.get("description") and not existing.get("description"):
                existing["description"] = nr["description"]
            if nr.get("stargazers_count"):
                existing["stargazers_count"] = nr["stargazers_count"]
            if nr.get("starred_at") and not existing.get("starred_at"):
                existing["starred_at"] = nr["starred_at"]
            if nr.get("primary_language") and (not existing.get("primary_language") or existing.get("primary_language") == "Other"):
                existing["primary_language"] = nr["primary_language"]
                existing["language_color"] = lang_color
            updated_count += 1
        else:
            # Create new
            item = {
                "full_name": fn,
                "owner": owner,
                "name": name,
                "description": nr.get("description", "") or "",
                "primary_language": lang,
                "language_color": lang_color,
                "stargazers_count": nr.get("stargazers_count", 0),
                "lists": sorted(list(set(target_lists))),
                "html_url": nr.get("html_url") or f"https://github.com/{fn}",
                "starred_at": nr.get("starred_at") or datetime.now().isoformat(),
                "source": nr.get("source", "import")
            }
            repos.append(item)
            repo_map[key] = item
            added_count += 1

    vault["repositories"] = repos
    save_starred_vault(vault, vault_file)
    render_stars_markdown(vault)
    return {
        "success": True,
        "added": added_count,
        "updated": updated_count,
        "total": len(repos)
    }


def delete_repo_from_vault(full_name: str, vault_file: Optional[str] = None) -> bool:
    """Remove repository from vault."""
    vault = load_starred_vault(vault_file)
    repos = vault.get("repositories", [])
    initial_len = len(repos)
    target = full_name.strip().lower()
    repos = [r for r in repos if r.get("full_name", "").lower() != target]
    if len(repos) < initial_len:
        vault["repositories"] = repos
        save_starred_vault(vault, vault_file)
        render_stars_markdown(vault)
        return True
    return False


def clear_vault_repositories(vault_file: Optional[str] = None) -> Dict[str, Any]:
    """Remove all repository assets from vault, resetting list counts to 0 and re-rendering markdown."""
    vault = load_starred_vault(vault_file)
    vault["repositories"] = []
    # Reset list counts to 0
    for l_obj in vault.get("lists", []):
        l_obj["count"] = 0
        l_obj["repo_count"] = 0
    vault["stats"] = {
        "total_stars": 0,
        "total_lists": len(vault.get("lists", [])),
        "languages": {}
    }
    save_starred_vault(vault, vault_file)
    render_stars_markdown(vault)
    return {
        "success": True,
        "total_stars": 0,
        "message": "Vault repositories cleared successfully"
    }


def reset_vault_to_seed(vault_file: Optional[str] = None) -> Dict[str, Any]:
    """Reset vault to initial mock seed baseline for demo/testing."""
    vault = {
        "version": "1.0",
        "last_sync": datetime.now().isoformat(),
        "account": "<owner>",
        "banned_source_account": "<owner>",
        "lists": [dict(l) for l in DEFAULT_INITIAL_LISTS],
        "repositories": [dict(r) for r in DEFAULT_INITIAL_REPOSITORIES]
    }
    _recalculate_vault_stats(vault)
    save_starred_vault(vault, vault_file)
    render_stars_markdown(vault)
    return {
        "success": True,
        "total_stars": len(DEFAULT_INITIAL_REPOSITORIES),
        "message": "Vault reset to seed baseline successfully"
    }


def add_or_create_list(name: str, description: str = "", vault_file: Optional[str] = None) -> Dict[str, Any]:
    """Add a new custom list to the vault."""
    vault = load_starred_vault(vault_file)
    lists = vault.get("lists", [])
    name_clean = name.strip()
    for l in lists:
        if l.get("name", "").lower() == name_clean.lower():
            return {"success": True, "created": False, "list": l}

    slug = re.sub(r'[^a-zA-Z0-9_-]', '_', name_clean)
    new_l = {
        "id": f"list_{slug}",
        "name": name_clean,
        "description": description.strip(),
        "count": 0
    }
    lists.append(new_l)
    vault["lists"] = lists
    save_starred_vault(vault, vault_file)
    return {"success": True, "created": True, "list": new_l}


# =====================================================================
# GitHub API Integration: GraphQL & REST
# =====================================================================

def _get_active_github_token(explicit_token: Optional[str] = None) -> str:
    """Resolve GitHub PAT token from parameter or Windows DPAPI Vault."""
    if explicit_token and explicit_token.strip():
        return explicit_token.strip()
    try:
        t = credential_vault.get_plain_token("github")
        if t:
            return t.strip()
    except Exception:
        pass
    return ""


def execute_graphql(
    query: str,
    variables: Optional[Dict[str, Any]] = None,
    token: Optional[str] = None,
    timeout: int = 25
) -> Dict[str, Any]:
    """Execute GitHub GraphQL API query or mutation."""
    pat = _get_active_github_token(token)
    if not pat:
        return {"errors": [{"message": "GitHub Personal Access Token (PAT) 未配置，无法发起 GraphQL 请求"}]}

    url = "https://api.github.com/graphql"
    payload = json.dumps({"query": query, "variables": variables or {}}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "Authorization": f"Bearer {pat}",
            "Content-Type": "application/json",
            "User-Agent": "Git-Vault-Star-Engine/1.0"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read().decode("utf-8")
            return json.loads(data)
    except urllib.error.HTTPError as e:
        err_msg = e.read().decode("utf-8", errors="replace")
        return {"errors": [{"message": f"HTTP {e.code}: {e.reason}", "detail": err_msg}]}
    except Exception as e:
        return {"errors": [{"message": str(e)}]}


def fetch_cloud_lists_graphql(token: Optional[str] = None) -> Dict[str, Any]:
    """Query viewer.lists for custom lists and repository memberships via GraphQL."""
    query = """
    query {
      viewer {
        login
        lists(first: 100) {
          totalCount
          nodes {
            id
            name
            description
            slug
            items(first: 100) {
              totalCount
              nodes {
                ... on Repository {
                  id
                  nameWithOwner
                  isPrivate
                  description
                  stargazerCount
                  primaryLanguage {
                    name
                    color
                  }
                  url
                }
              }
            }
          }
        }
      }
    }
    """
    res = execute_github_graphql(token, query)
    if "errors" in res and not res.get("data"):
        return {"success": False, "errors": res["errors"]}

    viewer = res.get("data", {}).get("viewer", {})
    login = viewer.get("login", "")
    lists_nodes = viewer.get("lists", {}).get("nodes", [])

    lists_out = []
    repos_out: Dict[str, Dict[str, Any]] = {}

    for l_node in lists_nodes:
        if not l_node:
            continue
        l_name = l_node.get("name", "")
        repo_nodes = (
            l_node.get("items", {}).get("nodes", []) or
            l_node.get("repositories", {}).get("nodes", [])
        )
        total_items = (
            l_node.get("items", {}).get("totalCount") or
            l_node.get("repositories", {}).get("totalCount") or
            len(repo_nodes)
        )
        lists_out.append({
            "id": l_node.get("id"),
            "name": l_name,
            "description": l_node.get("description") or "",
            "slug": l_node.get("slug") or "",
            "count": total_items,
            "repo_count": total_items
        })

        for r_node in repo_nodes:
            if not r_node or not isinstance(r_node, dict):
                continue
            fn = r_node.get("nameWithOwner", "")
            if not fn:
                continue
            lang_obj = r_node.get("primaryLanguage") or {}
            lang_name = lang_obj.get("name") or "Other"
            lang_col = lang_obj.get("color") or LANGUAGE_COLORS.get(lang_name, "#8b949e")

            if fn not in repos_out:
                parts = fn.split("/")
                owner_val = r_node.get("owner", {}).get("login") if isinstance(r_node.get("owner"), dict) else (parts[0] if len(parts) > 1 else "")
                name_val = r_node.get("name") or (parts[1] if len(parts) > 1 else fn)
                repos_out[fn] = {
                    "full_name": fn,
                    "owner": owner_val,
                    "name": name_val,
                    "description": r_node.get("description") or "",
                    "primary_language": lang_name,
                    "language": lang_name,
                    "language_color": lang_col,
                    "stargazers_count": r_node.get("stargazerCount", 0),
                    "lists": [l_name],
                    "node_id": r_node.get("id"),
                    "html_url": r_node.get("url") or f"https://github.com/{fn}",
                    "source": "cloud_graphql"
                }
            else:
                if l_name not in repos_out[fn]["lists"]:
                    repos_out[fn]["lists"].append(l_name)

    return {
        "success": True,
        "login": login,
        "lists": lists_out,
        "repositories": list(repos_out.values())
    }


def fetch_cloud_stars_rest(
    token: Optional[str] = None,
    max_pages: int = 10,
    per_page: int = 100
) -> Dict[str, Any]:
    """
    Fetch all starred repos via REST API with star timestamp support.
    Uses Accept: application/vnd.github.v3.star+json to obtain starred_at.
    """
    pat = _get_active_github_token(token)
    if not pat:
        return {"success": False, "error": "GitHub PAT 未配置，无法发起 REST 请求"}

    starred_repos: List[Dict[str, Any]] = []

    for page in range(1, max_pages + 1):
        url = f"https://api.github.com/user/starred?per_page={per_page}&page={page}"
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {pat}",
                "Accept": "application/vnd.github.v3.star+json",
                "User-Agent": "Git-Vault-Star-Engine/1.0"
            }
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                if not data:
                    break

                for item in data:
                    starred_at = item.get("starred_at", "")
                    r_obj = item.get("repo", {})
                    fn = r_obj.get("full_name", "")
                    if not fn:
                        continue
                    lang = r_obj.get("language") or "Other"
                    starred_repos.append({
                        "full_name": fn,
                        "owner": r_obj.get("owner", {}).get("login", ""),
                        "name": r_obj.get("name", ""),
                        "description": r_obj.get("description") or "",
                        "primary_language": lang,
                        "language_color": LANGUAGE_COLORS.get(lang, "#8b949e"),
                        "stargazers_count": r_obj.get("stargazers_count", 0),
                        "starred_at": starred_at,
                        "html_url": r_obj.get("html_url") or f"https://github.com/{fn}",
                        "source": "cloud_rest"
                    })

                if len(data) < per_page:
                    break
        except urllib.error.HTTPError as e:
            return {"success": False, "error": f"HTTP {e.code}: {e.reason}"}
        except Exception as e:
            return {"success": False, "error": str(e)}

    return {
        "success": True,
        "count": len(starred_repos),
        "repositories": starred_repos
    }


def fetch_cloud_all(token: Optional[str] = None, vault_file: Optional[str] = None) -> Dict[str, Any]:
    """Fetch both GraphQL lists/memberships and REST stars, merging into local vault."""
    # 1. Fetch GraphQL lists
    gql_res = fetch_cloud_lists_graphql(token=token)
    gql_repos = gql_res.get("repositories", []) if gql_res.get("success") else []

    # 2. Fetch REST stars with timestamps
    rest_res = fetch_cloud_stars_rest(token=token)
    rest_repos = rest_res.get("repositories", []) if rest_res.get("success") else []

    if not gql_res.get("success") and not rest_res.get("success"):
        err = gql_res.get("errors") or rest_res.get("error")
        return {"success": False, "error": f"Cloud fetch failed: {err}"}

    # Merge together: REST items have starred_at, GraphQL items have lists
    combined: Dict[str, Dict[str, Any]] = {}
    for r in rest_repos:
        combined[r["full_name"].lower()] = r

    for r in gql_repos:
        k = r["full_name"].lower()
        if k in combined:
            combined[k]["lists"] = sorted(list(set(combined[k].get("lists", []) + r.get("lists", []))))
        else:
            combined[k] = r

    # Purge mock seed items if cloud repos fetched
    if combined:
        cur_vault = load_starred_vault(vault_file)
        non_seed = [r for r in cur_vault.get("repositories", []) if r.get("source") != "seed"]
        if len(non_seed) != len(cur_vault.get("repositories", [])):
            cur_vault["repositories"] = non_seed
            save_starred_vault(cur_vault, vault_file)

    # Save to vault
    merge_res = merge_repos_into_vault(list(combined.values()), vault_file=vault_file)
    vault = load_starred_vault(vault_file)

    # Sync cloud lists to vault lists
    if gql_res.get("success") and gql_res.get("lists"):
        existing_lists = {l["name"].lower(): l for l in vault.get("lists", [])}
        for cl in gql_res["lists"]:
            c_name = cl["name"]
            if c_name.lower() not in existing_lists:
                vault["lists"].append({
                    "id": cl.get("id") or f"list_{re.sub(r'[^a-zA-Z0-9_-]', '_', c_name)}",
                    "name": c_name,
                    "description": cl.get("description", ""),
                    "count": cl.get("count", 0)
                })
        save_starred_vault(vault, vault_file)

    return {
        "success": True,
        "merged": merge_res,
        "total_in_vault": len(vault.get("repositories", [])),
        "total_lists": len(vault.get("lists", [])),
        "account": vault.get("account", "<owner>")
    }


def star_repo_rest(
    owner: str,
    repo: str,
    token: Optional[str] = None,
    pacing_delay: float = 1.2
) -> Tuple[bool, int, str]:
    """
    Idempotent PUT /user/starred/{owner}/{repo} with 1.2s pacing delay.
    Returns (success, status_code, message).
    """
    pat = _get_active_github_token(token)
    if not pat:
        return False, 401, "GitHub PAT 未配置"

    url = f"https://api.github.com/user/starred/{owner}/{repo}"
    req = urllib.request.Request(
        url,
        data=b"",
        method="PUT",
        headers={
            "Authorization": f"Bearer {pat}",
            "Accept": "application/vnd.github+json",
            "Content-Length": "0",
            "User-Agent": "Git-Vault-Star-Engine/1.0"
        }
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            status = resp.status
            if pacing_delay > 0:
                time.sleep(pacing_delay)
            return True, status, f"Successfully starred {owner}/{repo}"
    except urllib.error.HTTPError as e:
        if pacing_delay > 0:
            time.sleep(pacing_delay)
        return False, e.code, f"HTTP {e.code}: {e.reason}"
    except Exception as e:
        if pacing_delay > 0:
            time.sleep(pacing_delay)
        return False, 500, str(e)


def create_user_list_graphql(
    name: str,
    description: str = "",
    token: Optional[str] = None
) -> Tuple[bool, Optional[str], str]:
    """Create custom list on target account via GraphQL mutation."""
    mutation = """
    mutation CreateList($name: String!, $description: String) {
      createUserList(input: {name: $name, description: $description}) {
        list {
          id
          name
          slug
        }
      }
    }
    """
    res = execute_graphql(mutation, variables={"name": name, "description": description}, token=token)
    if "errors" in res and not res.get("data", {}).get("createUserList"):
        err = res["errors"][0].get("message", "Mutation error")
        return False, None, err

    create_payload = res.get("data", {}).get("createUserList", {}) or {}
    user_list = create_payload.get("list") or create_payload.get("userList") or {}
    list_id = user_list.get("id")
    if not list_id and "errors" in res:
        return False, None, res["errors"][0].get("message", "Mutation error")
    return True, list_id, f"Created list {name} ({list_id})"


def get_repo_graphql_id(owner: str, name: str, token: Optional[str] = None) -> Optional[str]:
    """Retrieve GraphQL Node ID for a repository."""
    query = """
    query GetRepo($owner: String!, $name: String!) {
      repository(owner: $owner, name: $name) {
        id
      }
    }
    """
    res = execute_graphql(query, variables={"owner": owner, "name": name}, token=token)
    return res.get("data", {}).get("repository", {}).get("id")


def add_repo_to_user_list_graphql(
    list_ids: Any = None,
    repo_id: str = "",
    token: Optional[str] = None,
    list_id: Any = None
) -> Tuple[bool, str]:
    """Add a repository to custom list(s) via GraphQL updateUserListsForItem."""
    raw_ids = list_ids if list_ids is not None else list_id
    if not raw_ids:
        return False, "No list IDs provided"
    if isinstance(raw_ids, str):
        ids = [raw_ids]
    else:
        ids = list(raw_ids)

    mutation = """
    mutation AddToList($listIds: [ID!]!, $itemId: ID!) {
      updateUserListsForItem(input: {listIds: $listIds, itemId: $itemId}) {
        clientMutationId
        lists {
          id
          name
        }
      }
    }
    """
    res = execute_graphql(mutation, variables={"listIds": ids, "itemId": repo_id}, token=token)
    if "errors" in res and not res.get("data", {}).get("updateUserListsForItem"):
        return False, res["errors"][0].get("message", "Failed to assign list")
    return True, "Assigned to list"


# =====================================================================
# Manual Import Parser & Metadata Enrichment
# =====================================================================

def enrich_repo_meta_rest(owner: str, repo: str, token: Optional[str] = None) -> Dict[str, Any]:
    """Query GitHub REST API to fetch repo metadata (language, stars, description)."""
    pat = _get_active_github_token(token)
    url = f"https://api.github.com/repos/{owner}/{repo}"
    headers = {"User-Agent": "Git-Vault-Star-Engine/1.0", "Accept": "application/vnd.github+json"}
    if pat:
        headers["Authorization"] = f"Bearer {pat}"

    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            lang = data.get("language") or "Other"
            return {
                "full_name": data.get("full_name") or f"{owner}/{repo}",
                "owner": owner,
                "name": repo,
                "description": data.get("description") or "",
                "primary_language": lang,
                "language": lang,
                "language_color": LANGUAGE_COLORS.get(lang, "#8b949e"),
                "stargazers_count": data.get("stargazers_count", 0),
                "node_id": data.get("node_id"),
                "html_url": data.get("html_url") or f"https://github.com/{owner}/{repo}",
                "found": True
            }
    except Exception:
        # Fallback when offline or rate limited
        return {
            "full_name": f"{owner}/{repo}",
            "owner": owner,
            "name": repo,
            "description": "",
            "primary_language": "Other",
            "language": "Other",
            "language_color": "#8b949e",
            "stargazers_count": 0,
            "node_id": None,
            "html_url": f"https://github.com/{owner}/{repo}",
            "found": False
        }


def parse_manual_import(
    text: str,
    default_list: str = "SKILL",
    token: Optional[str] = None,
    enrich_meta: bool = True,
    vault_file: Optional[str] = None
) -> List[Dict[str, Any]]:
    """
    Parse raw user input containing owner/repo or URLs, enrich metadata,
    categorize into specified list, and merge into vault.
    Supports GitHub/GitLab/Gitee URLs, Markdown links, and bare owner/repo formats.
    """
    lines = text.strip().splitlines()
    parsed_items: List[Dict[str, Any]] = []
    seen = set()

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # 1. Match full URLs (github.com, gitlab.com, gitee.com, etc.)
        url_match = re.search(r'https?://[^/\s]+/([^/\s]+)/([^/\s#?)]+)', line)
        if url_match:
            owner, repo_name = url_match.group(1), url_match.group(2)
        else:
            # 2. Match bare owner/repo (excluding domains like example.com/path)
            bare_match = re.search(r'(?<![a-zA-Z0-9_\-\./])([a-zA-Z0-9_\-\.]+)/([a-zA-Z0-9_\-\.]+)', line)
            if bare_match:
                cand_owner, cand_repo = bare_match.group(1), bare_match.group(2)
                if not re.search(r'\.(?:com|org|net|io|cn|edu|dev)$', cand_owner, re.I):
                    owner, repo_name = cand_owner, cand_repo
                else:
                    continue
            else:
                continue

        # Clean trailing punctuation (e.g. from Markdown syntax)
        repo_name = repo_name.rstrip(').,;\"\'')
        owner = owner.lstrip('(')
        if repo_name.endswith(".git"):
            repo_name = repo_name[:-4]

        full_name = f"{owner}/{repo_name}"
        if full_name.lower() in seen:
            continue
        seen.add(full_name.lower())

        if enrich_meta:
            meta = enrich_repo_meta_rest(owner, repo_name, token=token)
        else:
            meta = {
                "full_name": full_name,
                "owner": owner,
                "name": repo_name,
                "description": "",
                "primary_language": "Other",
                "language_color": "#8b949e",
                "stargazers_count": 0,
                "html_url": f"https://github.com/{full_name}"
            }

        meta["lists"] = [default_list] if default_list else []
        meta["source"] = "manual_import"
        meta["starred_at"] = datetime.now().isoformat()
        parsed_items.append(meta)

    if parsed_items:
        merge_repos_into_vault(parsed_items, default_list=default_list, vault_file=vault_file)

    return parsed_items


# =====================================================================
# Markdown Catalog Generator & Multi-Cloud Bus Sync
# =====================================================================

def render_stars_markdown(
    vault_data: Optional[Dict[str, Any]] = None,
    output_file: Optional[str] = None
) -> str:
    """
    Generate pristine, structured Markdown index catalog (STARS_INDEX.md).
    Follows Claude Design System - anti-AI slop, zero emojis, high craft engineering structure.
    """
    vault = vault_data or load_starred_vault()
    repos = vault.get("repositories", [])
    lists = vault.get("lists", [])
    stats = vault.get("stats", {})
    account = vault.get("account", "<owner>")
    banned_acc = vault.get("banned_source_account", "<owner>")
    sync_time = vault.get("last_sync", datetime.now().isoformat())

    # Group repos by list name
    list_groups: Dict[str, List[Dict[str, Any]]] = {}
    for l in lists:
        list_groups[l.get("name", "")] = []

    uncategorized: List[Dict[str, Any]] = []

    for r in repos:
        r_lists = r.get("lists", [])
        if not r_lists:
            uncategorized.append(r)
        else:
            for l_name in r_lists:
                if l_name not in list_groups:
                    list_groups[l_name] = []
                list_groups[l_name].append(r)

    # Format document
    md_lines = [
        "# Git-Vault Star 资产索引库 (Star Vault Catalog)",
        "",
        "> 本文件由 Git-Vault Star 容灾引擎自动构建与维护，作为本地与多云备份端（GitLab / Gitee / GitHub）的一致性只读索引。",
        "",
        "## 1. 资产概览",
        f"- **目标账户**: `{account}`",
        f"- **历史来源账户**: `{banned_acc}` (封禁容灾提取)",
        f"- **Star 总数**: {len(repos)}",
        f"- **分类 Lists 总数**: {len(lists)}",
        f"- **最后同步时间**: `{sync_time}`",
        "",
        "### 语言分布",
        "| 语言 | 仓库数量 |",
        "| :--- | :--- |"
    ]

    lang_stats = stats.get("languages", {})
    for lang, count in lang_stats.items():
        md_lines.append(f"| {lang} | {count} |")

    md_lines.append("")
    md_lines.append("## 2. 分类索引明细")

    for l_obj in lists:
        name = l_obj.get("name", "")
        desc = l_obj.get("description", "")
        group_repos = list_groups.get(name, [])
        md_lines.append(f"### List: {name} ({len(group_repos)})")
        if desc:
            md_lines.append(f"*{desc}*")
            md_lines.append("")

        if group_repos:
            md_lines.append("| 仓库 | 描述 | 语言 | Stars | 归档时间 |")
            md_lines.append("| :--- | :--- | :--- | :--- | :--- |")
            for r in group_repos:
                fn = r.get("full_name", "")
                url = r.get("html_url") or f"https://github.com/{fn}"
                r_desc = (r.get("description") or "-").replace("\r\n", " ").replace("\n", " ").replace("\r", " ").replace("|", "\\|")
                lang = r.get("primary_language") or "Other"
                st = _format_stars_compact(r.get("stargazers_count", 0))
                starred_at = (r.get("starred_at") or "-")[:10]
                md_lines.append(f"| [{fn}]({url}) | {r_desc} | {lang} | {st} | {starred_at} |")
        else:
            md_lines.append("*暂无关联仓库*")
        md_lines.append("")

    if uncategorized:
        md_lines.append(f"### 未分类 (Uncategorized) ({len(uncategorized)})")
        md_lines.append("| 仓库 | 描述 | 语言 | Stars | 归档时间 |")
        md_lines.append("| :--- | :--- | :--- | :--- | :--- |")
        for r in uncategorized:
            fn = r.get("full_name", "")
            url = r.get("html_url") or f"https://github.com/{fn}"
            r_desc = (r.get("description") or "-").replace("\r\n", " ").replace("\n", " ").replace("\r", " ").replace("|", "\\|")
            lang = r.get("primary_language") or "Other"
            st = _format_stars_compact(r.get("stargazers_count", 0))
            starred_at = (r.get("starred_at") or "-")[:10]
            md_lines.append(f"| [{fn}]({url}) | {r_desc} | {lang} | {st} | {starred_at} |")
        md_lines.append("")

    content = "\n".join(md_lines)

    target_path = output_file or STARS_INDEX_FILE
    try:
        os.makedirs(os.path.dirname(os.path.abspath(target_path)), exist_ok=True)
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(content)
    except Exception as e:
        print(f"[StarVault] Failed to write {target_path}: {e}")

    return content


def sync_stars_catalog_to_clouds(
    repo_path: Optional[str] = None,
    commit_message: Optional[str] = None
) -> Dict[str, Any]:
    """
    Commit star vault catalog (starred_vault.json & STARS_INDEX.md) and push
    through Git-Vault's multi-push bus to GitLab/Gitee/GitHub.
    """
    # 1. Check panic button lock
    can_write, panic_msg = compliance_guard.check_write_permission()
    if not can_write:
        return {"success": False, "blocked": True, "error": panic_msg}

    target_repo = repo_path or BASE_DIR
    if not os.path.exists(os.path.join(target_repo, ".git")):
        return {"success": False, "error": f"{target_repo} 不是有效的 Git 仓库"}

    # 2. Render latest Markdown index and ensure vault is on disk
    render_stars_markdown()
    
    # 3. Import git_engine dynamically
    from core import git_engine

    # 4. Stage vault files
    git_engine.run_git(["add", "config/starred_vault.json", "STARS_INDEX.md"], cwd=target_repo)

    # 5. Check if there are staged changes
    status_res = git_engine.run_git(["diff", "--cached", "--name-only"], cwd=target_repo)
    staged = status_res.get("stdout", "").strip()

    committed = False
    commit_hash = ""
    if staged:
        c_msg = commit_message or "chore(stars): sync star vault catalog and index [auto-sync]"
        c_res = git_engine.run_git(["commit", "-m", c_msg], cwd=target_repo)
        committed = c_res.get("success", False)
        rev_res = git_engine.run_git(["rev-parse", "--short", "HEAD"], cwd=target_repo)
        commit_hash = rev_res.get("stdout", "").strip()

    # 6. Execute multi-cloud sync via git_engine
    sync_result = git_engine.sync_repository(target_repo)

    return {
        "success": sync_result.get("success", False),
        "repo": target_repo,
        "committed": committed,
        "commit_hash": commit_hash,
        "sync_details": sync_result,
        "index_path": STARS_INDEX_FILE,
        "vault_path": VAULT_STARS_FILE
    }


# =====================================================================
# Streaming Generator for Safe Restoration (SSE)
# =====================================================================

def restore_to_account_stream(
    target_account: Optional[str] = None,
    token: Optional[str] = None,
    pacing_delay: float = 1.2,
    lists_filter: Optional[List[str]] = None,
    target_repo_names: Optional[List[str]] = None,
    recreate_lists: bool = True,
    dry_run: bool = False,
    vault_file: Optional[str] = None
) -> Generator[Dict[str, Any], None, None]:
    """
    Generator yielding real-time SSE progress events for restoring stars
    and reconstructing lists on target account.
    """
    vault = load_starred_vault(vault_file)
    account_name = target_account or vault.get("account", "<owner>")
    repos = vault.get("repositories", [])
    lists = vault.get("lists", [])

    if lists_filter:
        selected_lists = [l for l in lists if l.get("name") in lists_filter]
        selected_repos = [r for r in repos if any(ln in lists_filter for ln in r.get("lists", []))]
    else:
        selected_lists = lists
        selected_repos = repos

    if target_repo_names:
        name_set = {n.strip().lower() for n in target_repo_names if n.strip()}
        selected_repos = [r for r in selected_repos if r.get("full_name", "").lower() in name_set]

    if not recreate_lists:
        selected_lists = []

    total_lists = len(selected_lists)
    total_repos = len(selected_repos)
    total_steps = total_lists + total_repos

    yield {
        "type": "start",
        "init": True,
        "start": True,
        "account": account_name,
        "total_lists": total_lists,
        "total_repos": total_repos,
        "total_steps": total_steps,
        "pacing": pacing_delay,
        "dry_run": dry_run,
        "message": f"启动回迁流水线: 目标={account_name}, Lists={total_lists}, 仓库={total_repos}"
    }

    current_step = 0
    created_list_map: Dict[str, Optional[str]] = {}

    # Query existing lists on cloud if live run with recreate_lists enabled
    existing_cloud_lists: Dict[str, str] = {}
    if not dry_run and recreate_lists and token:
        try:
            cloud_info = fetch_cloud_lists_graphql(token=token)
            if cloud_info.get("success"):
                for cl in cloud_info.get("lists", []):
                    if cl.get("name") and cl.get("id"):
                        existing_cloud_lists[cl["name"]] = cl["id"]
        except Exception:
            pass

    # Step 1: Reconstruct lists via GraphQL
    for l_obj in selected_lists:
        current_step += 1
        l_name = l_obj.get("name", "")
        pct = min(99, int((current_step / total_steps) * 100)) if total_steps > 0 else 50

        if dry_run:
            if pacing_delay > 0:
                time.sleep(min(pacing_delay, 0.05))
            created_list_map[l_name] = f"mock_{l_name}"
            yield {
                "type": "list_step",
                "list_create": True,
                "list_step": current_step,
                "step": current_step,
                "total_steps": total_steps,
                "percent": pct,
                "list_name": l_name,
                "list": l_name,
                "status": "exists",
                "success": True,
                "message": f"[GraphQL] 建分类: {l_name} (DRY-RUN OK)"
            }
        else:
            if l_name in existing_cloud_lists:
                list_id = existing_cloud_lists[l_name]
                created_list_map[l_name] = list_id
                yield {
                    "type": "list_step",
                    "list_step": current_step,
                    "step": current_step,
                    "total_steps": total_steps,
                    "percent": pct,
                    "list_name": l_name,
                    "list": l_name,
                    "status": "exists",
                    "success": True,
                    "message": f"[GraphQL] 分类已存在: {l_name} (跳过新建)"
                }
            else:
                res = create_github_user_list(l_name, l_obj.get("description", ""), token=token)
                if isinstance(res, tuple):
                    success, list_id, msg = res
                else:
                    success = res.get("success", False)
                    list_id = res.get("list", {}).get("id") if res.get("list") else None
                    msg = res.get("error") or "Created list"

                created_list_map[l_name] = list_id
                yield {
                    "type": "list_step",
                    "list_step": current_step,
                    "step": current_step,
                    "total_steps": total_steps,
                    "percent": pct,
                    "list_name": l_name,
                    "list": l_name,
                    "status": "created" if success else "warning",
                    "success": success,
                    "message": f"[GraphQL] 建分类: {l_name} ({'OK' if success else msg})"
                }

    # Step 2: Idempotent Star PUT & List Assignment via GraphQL
    starred_success = 0
    already_starred = 0
    starred_fail = 0

    for r in selected_repos:
        current_step += 1
        pct = min(99, int((current_step / total_steps) * 100)) if total_steps > 0 else 99
        fn = r.get("full_name", "")
        owner = r.get("owner", "")
        name = r.get("name", "")
        r_lists = r.get("lists", [])

        if not owner or not name:
            if "/" in fn:
                parts = fn.split("/")
                owner, name = parts[0], parts[1]

        if dry_run:
            if pacing_delay > 0:
                time.sleep(min(pacing_delay, 0.05))
            starred_success += 1
            yield {
                "type": "repo_step",
                "star": "starred",
                "status": "starred",
                "repo_step": current_step,
                "step": current_step,
                "total_steps": total_steps,
                "percent": pct,
                "full_name": fn,
                "repo": fn,
                "lists": r_lists,
                "assigned_lists": r_lists if recreate_lists else [],
                "success": True,
                "status_code": 204,
                "message": f"[REST] 点星: {fn} (204) [归入: {', '.join(r_lists) if r_lists else '未分类'}]"
            }
            continue

        # 1. Idempotency Check & Star
        if check_is_starred(token, owner, name):
            already_starred += 1
            s_stat = "already_starred"
            success = True
            status_code = 204
            base_msg = f"[REST] 已加星跳过: {fn} (204 Already Starred)"
        else:
            star_res = star_repository(token=token or "", owner=owner, repo=name)
            if isinstance(star_res, tuple):
                success, status_code, msg = star_res
            else:
                success = star_res.get("success", False)
                status_code = star_res.get("status") or star_res.get("status_code", 204)
                msg = star_res.get("message", "")

            if success:
                starred_success += 1
                s_stat = "starred"
                base_msg = f"[REST] 点星: {fn} ({status_code})"
            else:
                starred_fail += 1
                s_stat = "failed"
                base_msg = f"[REST] 点星失败: {fn} ({status_code}: {msg})"

        # 2. GraphQL List Assignment if repo star is active or already active
        assigned_lists = []
        assign_msg = ""
        if recreate_lists and (s_stat in ("starred", "already_starred")) and r_lists:
            target_list_ids = [created_list_map[ln] for ln in r_lists if created_list_map.get(ln)]
            if target_list_ids:
                node_id = r.get("node_id")
                if not node_id:
                    node_id = get_repo_graphql_id(owner, name, token=token)
                if node_id:
                    assign_ok, assign_err = add_repo_to_user_list_graphql(
                        list_ids=target_list_ids,
                        repo_id=node_id,
                        token=token
                    )
                    if assign_ok:
                        assigned_lists = r_lists
                        assign_msg = f" [GraphQL 归入: {', '.join(r_lists)}]"
                    else:
                        assign_msg = f" [GraphQL 归类失败: {assign_err}]"
                else:
                    assign_msg = f" [GraphQL 未能解析 NodeID, 归入跳过]"
            else:
                assign_msg = f" [归入: {', '.join(r_lists)}]"
        else:
            assign_msg = f" [归入: {', '.join(r_lists) if r_lists else '未分类'}]"

        yield {
            "type": "repo_step",
            "repo_step": current_step,
            "step": current_step,
            "total_steps": total_steps,
            "percent": pct,
            "full_name": fn,
            "repo": fn,
            "lists": r_lists,
            "assigned_lists": assigned_lists,
            "status": s_stat,
            "star": s_stat,
            "success": success,
            "status_code": status_code,
            "message": base_msg + assign_msg
        }

    yield {
        "type": "complete",
        "step": total_steps,
        "total_steps": total_steps,
        "percent": 100,
        "starred_success": starred_success,
        "newly_starred": starred_success,
        "already_starred": already_starred,
        "starred_fail": starred_fail,
        "failed": starred_fail,
        "message": f"全量回迁完成 (成功: {starred_success}, 已存在跳过: {already_starred}, 失败: {starred_fail})"
    }


def check_is_starred(token: Optional[str], owner: str, repo: str) -> bool:
    """Idempotency check: returns True if repo is already starred by user."""
    pat = _get_active_github_token(token)
    if not pat:
        return False
    url = f"https://api.github.com/user/starred/{owner}/{repo}"
    req = urllib.request.Request(
        url,
        method="GET",
        headers={
            "Authorization": f"Bearer {pat}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "Git-Vault-Star-Engine/1.0"
        }
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status == 204
    except urllib.error.HTTPError as e:
        return e.code == 204
    except Exception:
        return False


# =====================================================================
# Compatibility Helpers & Aliases
# =====================================================================

def filter_vault_repos(
    vault_data: Dict[str, Any],
    list_name: str = "all",
    search: str = "",
    language: str = "all"
) -> List[Dict[str, Any]]:
    """Helper to filter repositories from loaded vault data."""
    repos = vault_data.get("repositories", [])
    filtered = []
    search_lower = (search or "").strip().lower()
    lang_filter = (language or "").strip()
    l_filter = (list_name or "").strip()

    for r in repos:
        if l_filter and l_filter.lower() != "all":
            if l_filter not in r.get("lists", []):
                continue
        if lang_filter and lang_filter.lower() != "all":
            r_lang = r.get("primary_language") or r.get("language") or ""
            if r_lang.lower() != lang_filter.lower():
                continue
        if search_lower:
            fn = r.get("full_name", "").lower()
            desc = (r.get("description") or "").lower()
            if search_lower not in fn and search_lower not in desc:
                continue
        r_copy = dict(r)
        r_copy["stars_compact"] = _format_stars_compact(r.get("stargazers_count", 0))
        r_copy["language"] = r.get("primary_language") or r.get("language") or ""
        r_copy["primary_language"] = r_copy["language"]
        filtered.append(r_copy)
    return filtered


def get_vault_stats(vault_data: Dict[str, Any]) -> Dict[str, Any]:
    """Helper to retrieve or recalculate vault stats."""
    _recalculate_vault_stats(vault_data)
    return vault_data.get("stats", {})


def query_github_star_lists(token: Optional[str] = None) -> Dict[str, Any]:
    """Alias for fetch_cloud_lists_graphql."""
    return fetch_cloud_lists_graphql(token=token)


def fetch_flat_stars(token: Optional[str] = None, max_pages: int = 5) -> List[Dict[str, Any]]:
    """Fetch flat starred repos via REST API."""
    res = fetch_cloud_stars_rest(token=token, max_pages=max_pages)
    return res.get("repositories", [])


def merge_stars_data(
    current_vault: Dict[str, Any],
    cloud_lists: List[Dict[str, Any]],
    cloud_repos: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """Merge cloud lists and repositories in-memory into current vault object."""
    vault = dict(current_vault)
    # Merge lists
    existing_lists = {l["name"].lower(): l for l in vault.get("lists", [])}
    for cl in cloud_lists:
        c_name = cl.get("name", "")
        if not c_name:
            continue
        if c_name.lower() not in existing_lists:
            new_l = {
                "id": cl.get("id") or f"list_{re.sub(r'[^a-zA-Z0-9_-]', '_', c_name)}",
                "name": c_name,
                "description": cl.get("description") or "",
                "count": cl.get("count", 0),
                "repo_count": cl.get("count", 0)
            }
            vault.setdefault("lists", []).append(new_l)
            existing_lists[c_name.lower()] = new_l

    # Merge repos in-memory
    repos = list(vault.get("repositories", []))
    repo_map: Dict[str, Dict[str, Any]] = {
        r.get("full_name", "").lower(): r for r in repos if r.get("full_name")
    }

    for nr in cloud_repos:
        fn = (nr.get("full_name") or "").strip()
        if not fn or "/" not in fn:
            continue
        key = fn.lower()
        parts = fn.split("/")
        owner = nr.get("owner") or parts[0]
        name = nr.get("name") or parts[1]
        target_lists = nr.get("lists") or []
        if isinstance(target_lists, str):
            target_lists = [target_lists]

        lang = nr.get("primary_language") or nr.get("language") or "Other"
        lang_color = nr.get("language_color") or LANGUAGE_COLORS.get(lang, "#8b949e")

        if key in repo_map:
            existing = repo_map[key]
            cur_lists = set(existing.get("lists", []))
            cur_lists.update(target_lists)
            existing["lists"] = sorted(list(cur_lists))
            if nr.get("description"):
                existing["description"] = nr["description"]
            if nr.get("stargazers_count"):
                existing["stargazers_count"] = nr["stargazers_count"]
            if nr.get("starred_at") and not existing.get("starred_at"):
                existing["starred_at"] = nr["starred_at"]
            if lang != "Other":
                existing["primary_language"] = lang
                existing["language"] = lang
                existing["language_color"] = lang_color
        else:
            item = {
                "full_name": fn,
                "owner": owner,
                "name": name,
                "description": nr.get("description", "") or "",
                "primary_language": lang,
                "language": lang,
                "language_color": lang_color,
                "stargazers_count": nr.get("stargazers_count", 0),
                "lists": sorted(list(set(target_lists))),
                "html_url": nr.get("html_url") or f"https://github.com/{fn}",
                "starred_at": nr.get("starred_at") or datetime.now().isoformat(),
                "source": nr.get("source", "api")
            }
            repos.append(item)
            repo_map[key] = item

    vault["repositories"] = repos
    _recalculate_vault_stats(vault)
    return vault


def save_stars_markdown(output_file: Optional[str] = None) -> str:
    """Alias for render_stars_markdown."""
    return render_stars_markdown(output_file=output_file)


def manual_import_repos(
    repos_input: Any,
    target_list: str = "SKILL",
    token: Optional[str] = None,
    enrich_meta: bool = True
) -> Dict[str, Any]:
    """Parse string or list of repos, enrich, categorize, and merge."""
    if isinstance(repos_input, list):
        text = "\n".join(str(item) for item in repos_input)
    else:
        text = str(repos_input)

    items = parse_manual_import(text, default_list=target_list, token=token, enrich_meta=enrich_meta)
    vault = load_starred_vault()
    render_stars_markdown()
    return {
        "success": True,
        "imported_count": len(items),
        "target_list": target_list,
        "repositories": items,
        "vault_total": len(vault.get("repositories", []))
    }


def sync_stars_vault_repo(branch: str = "main", commit_message: Optional[str] = None) -> Dict[str, Any]:
    """Alias for sync_stars_catalog_to_clouds."""
    return sync_stars_catalog_to_clouds(commit_message=commit_message)


def create_list_in_vault(name: str, description: str = "") -> Dict[str, Any]:
    """Alias for add_or_create_list."""
    return add_or_create_list(name=name, description=description)


def create_github_user_list(
    name: str,
    description: str = "",
    token: Optional[str] = None,
    is_private: bool = False
) -> Dict[str, Any]:
    """Create list on target account via GraphQL."""
    success, list_id, msg = create_user_list_graphql(name=name, description=description, token=token)
    return {
        "success": success,
        "list": {"id": list_id, "name": name} if list_id else None,
        "error": msg if not success else None
    }


def star_repository(token: str, owner: str, repo: str) -> Dict[str, Any]:
    """Star a repository directly."""
    success, status, msg = star_repo_rest(owner, repo, token=token, pacing_delay=0)
    return {"success": success, "status": status, "status_code": status, "message": msg}


def execute_github_graphql(token: Optional[str], query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """GraphQL execution alias."""
    return execute_graphql(query=query, variables=variables, token=token)


add_repo_to_user_list = add_repo_to_user_list_graphql
get_repo_node_id = get_repo_graphql_id
fetch_repo_details = enrich_repo_meta_rest


