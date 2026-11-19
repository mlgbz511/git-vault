# core/agent_installer.py
# Antigravity & DSH Agent Visual Extension Installer
import os
import sys
import json
import shutil
from typing import Dict, List, Any, Optional

VAULT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if VAULT_ROOT not in sys.path:
    sys.path.insert(0, VAULT_ROOT)

from core import mcp_server

def get_user_gemini_paths() -> Dict[str, str]:
    """Detect Antigravity/Gemini paths on current machine."""
    user_home = os.environ.get("USERPROFILE") or os.environ.get("HOME") or "%USERPROFILE%"
    gemini_root = os.path.join(user_home, ".gemini")
    gemini_config = os.path.join(gemini_root, "config")
    gemini_antigravity = os.path.join(gemini_root, "antigravity")

    return {
        "gemini_root": gemini_root,
        "config_dir": gemini_config,
        "mcp_config_file": os.path.join(gemini_config, "mcp_config.json"),
        "plugins_target_dir": os.path.join(gemini_config, "plugins", "git-vault"),
        "schemas_target_dir": os.path.join(gemini_antigravity, "mcp", "git-vault")
    }

def generate_tool_schemas(schemas_dir: str) -> int:
    """Generate Antigravity-compatible JSON schemas and instructions.md for all tools."""
    os.makedirs(schemas_dir, exist_ok=True)

    # 1. instructions.md
    instructions_path = os.path.join(schemas_dir, "instructions.md")
    instructions_content = """# Git-Vault Enterprise MCP Tools Guide

Git-Vault provides enterprise-grade Git synchronization across GitHub, Gitee, and GitLab, hardware-level DPAPI secret protection, compliance gates, and Star disaster recovery.

## Recommended Workflow
1. Use `vault_check_panic` to confirm the system is in READ_WRITE mode before mutations.
2. Use `vault_audit_compliance` to scan for accidental secret leaks (OpenAI, GitHub tokens) and large files.
3. If leaks are detected, use `vault_remediate_gitignore` to auto-remediate untracked sensitive files.
4. Use `vault_commit_push` to commit with Co-authored-by and push to all 3 clouds simultaneously.
5. Use `vault_search_stars` to find open-source repositories and agent tools already in the user's curated vault.
"""
    with open(instructions_path, "w", encoding="utf-8") as f:
        f.write(instructions_content)

    # 2. Tool schema JSON files
    count = 0
    for tool in mcp_server.MCP_TOOLS:
        name = tool["name"]
        input_schema = tool.get("inputSchema", {})
        schema_def = {
            "name": name,
            "description": tool.get("description", ""),
            "parameters": {
                "$schema": "https://json-schema.org/draft/2020-12/schema",
                "properties": input_schema.get("properties", {}),
                "type": "object"
            }
        }
        if "required" in input_schema:
            schema_def["parameters"]["required"] = input_schema["required"]

        file_path = os.path.join(schemas_dir, f"{name}.json")
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(schema_def, f, ensure_ascii=False, indent=2)
        count += 1

    return count

def merge_mcp_config(config_file: str, command: str, args: List[str]) -> bool:
    """Safely merge git-vault into mcp_config.json preserving existing servers."""
    os.makedirs(os.path.dirname(config_file), exist_ok=True)
    data = {"mcpServers": {}}
    if os.path.exists(config_file):
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {"mcpServers": {}}

    if "mcpServers" not in data or not isinstance(data["mcpServers"], dict):
        data["mcpServers"] = {}

    data["mcpServers"]["git-vault"] = {
        "command": command,
        "args": args,
        "env": {
            "PYTHONIOENCODING": "utf-8"
        }
    }

    try:
        with open(config_file, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        return True
    except Exception as e:
        sys.stderr.write(f"[INSTALLER_ERR] Failed to write {config_file}: {e}\n")
        return False

def check_antigravity_status() -> Dict[str, Any]:
    """Check Antigravity extension and MCP integration status."""
    paths = get_user_gemini_paths()
    plugin_installed = os.path.exists(os.path.join(paths["plugins_target_dir"], "plugin.json"))
    schemas_exist = os.path.exists(paths["schemas_target_dir"]) and len(os.listdir(paths["schemas_target_dir"])) >= len(mcp_server.MCP_TOOLS)
    
    config_registered = False
    if os.path.exists(paths["mcp_config_file"]):
        try:
            with open(paths["mcp_config_file"], "r", encoding="utf-8") as f:
                cfg = json.load(f)
                config_registered = "git-vault" in cfg.get("mcpServers", {})
        except Exception:
            config_registered = False

    is_ready = plugin_installed and schemas_exist and config_registered

    return {
        "is_ready": is_ready,
        "plugin_installed": plugin_installed,
        "schemas_installed": schemas_exist,
        "config_registered": config_registered,
        "tools_count": len(mcp_server.MCP_TOOLS),
        "paths": paths
    }

def install_antigravity_plugin() -> Dict[str, Any]:
    """Execute one-click installation of Antigravity Plugin and tool schemas."""
    paths = get_user_gemini_paths()
    source_ext_dir = os.path.join(VAULT_ROOT, "extensions", "antigravity")

    # 1. Copy plugin files to ~/.gemini/config/plugins/git-vault
    os.makedirs(paths["plugins_target_dir"], exist_ok=True)
    if os.path.exists(source_ext_dir):
        for item in os.listdir(source_ext_dir):
            s = os.path.join(source_ext_dir, item)
            d = os.path.join(paths["plugins_target_dir"], item)
            if os.path.isdir(s):
                if os.path.exists(d):
                    shutil.rmtree(d, ignore_errors=True)
                shutil.copytree(s, d)
            else:
                shutil.copy2(s, d)

    # 2. Merge into ~/.gemini/config/mcp_config.json
    mcp_server_script = os.path.join(VAULT_ROOT, "core", "mcp_server.py")
    merge_res = merge_mcp_config(
        paths["mcp_config_file"],
        command="python",
        args=[mcp_server_script]
    )

    # 3. Generate native tool schemas in ~/.gemini/antigravity/mcp/git-vault
    schemas_count = generate_tool_schemas(paths["schemas_target_dir"])

    status = check_antigravity_status()
    status["success"] = merge_res and (schemas_count > 0)
    status["schemas_generated"] = schemas_count
    return status

def get_dsh_manifest() -> Dict[str, Any]:
    """Retrieve DSH plugin manifest specification."""
    dsh_manifest_file = os.path.join(VAULT_ROOT, "extensions", "dsh", "dsh.plugin.json")
    if os.path.exists(dsh_manifest_file):
        with open(dsh_manifest_file, "r", encoding="utf-8") as f:
            return json.load(f)
    return {
        "id": "dsh-git-vault",
        "name": "Git-Vault 安全网关与 Star 容灾",
        "type": "tool_provider",
        "mcp": {
            "serverUrl": "http://127.0.0.1:8765/mcp/sse",
            "transport": "sse"
        }
    }

def get_dsh_install_command() -> str:
    """Return standard DSH CLI plugin add command."""
    dsh_ext_path = os.path.join(VAULT_ROOT, "extensions", "dsh")
    return f"dsh plugin add \"{dsh_ext_path}\""
