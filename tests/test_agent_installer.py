# tests/test_agent_installer.py
import os
import sys
import unittest
import tempfile
import json
import shutil

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core import agent_installer, mcp_server

class TestAgentInstaller(unittest.TestCase):

    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="gitvault_agent_test_")

    def tearDown(self):
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_generate_antigravity_schemas(self):
        """Verify generator creates schema json for each tool in MCP_TOOLS and instructions.md."""
        schemas_dir = os.path.join(self.test_dir, "mcp_schemas", "git-vault")
        count = agent_installer.generate_tool_schemas(schemas_dir)
        self.assertEqual(count, len(mcp_server.MCP_TOOLS))
        self.assertTrue(os.path.exists(os.path.join(schemas_dir, "instructions.md")))

        # Check a specific tool schema
        commit_schema_path = os.path.join(schemas_dir, "vault_commit_push.json")
        self.assertTrue(os.path.exists(commit_schema_path))
        with open(commit_schema_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["name"], "vault_commit_push")
        self.assertIn("parameters", data)
        self.assertEqual(data["parameters"]["type"], "object")

    def test_merge_mcp_config(self):
        """Verify merging preserves existing servers and injects git-vault."""
        config_path = os.path.join(self.test_dir, "mcp_config.json")
        initial_content = {
            "mcpServers": {
                "cloudflare-docs": {"serverUrl": "https://docs.mcp.cloudflare.com/mcp"}
            }
        }
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(initial_content, f)

        res = agent_installer.merge_mcp_config(config_path, "python", ["<path>\\test\\mcp.py"])
        self.assertTrue(res)

        with open(config_path, "r", encoding="utf-8") as f:
            merged = json.load(f)

        self.assertIn("cloudflare-docs", merged["mcpServers"])
        self.assertIn("git-vault", merged["mcpServers"])
        self.assertEqual(merged["mcpServers"]["git-vault"]["command"], "python")

    def test_dsh_manifest_structure(self):
        """Verify DSH plugin manifest generator outputs compliant schema."""
        manifest = agent_installer.get_dsh_manifest()
        self.assertEqual(manifest["id"], "dsh-git-vault")
        self.assertEqual(manifest["type"], "tool_provider")
        self.assertIn("mcp", manifest)

if __name__ == "__main__":
    unittest.main()
