# tests/test_mcp_server_v2.py
# Git-Vault Model Context Protocol (MCP) 2.0 Comprehensive Test Suite
import os
import sys
import unittest
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core import mcp_server, compliance_guard

class TestMCPServerV2(unittest.TestCase):

    def setUp(self):
        compliance_guard.set_panic_button(False)

    def tearDown(self):
        compliance_guard.set_panic_button(False)

    def test_tools_list_v2_completeness(self):
        """Verify tools/list exposes all required tools including new compliance and star tools."""
        req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/list",
            "params": {}
        }
        res = mcp_server.handle_json_rpc(req)
        self.assertIn("result", res, "Response should have result")
        tools = res["result"].get("tools", [])
        tool_names = [t["name"] for t in tools]

        expected_tools = [
            "vault_list_repos",
            "vault_get_diff",
            "vault_commit_push",
            "vault_create_repo",
            "vault_audit_compliance",
            "vault_remediate_gitignore",
            "vault_check_panic",
            "vault_search_stars",
            "vault_query_lists",
            "vault_star_repo",
            "vault_proxy_api",
            "vault_get_audit_log"
        ]

        for expected in expected_tools:
            self.assertIn(expected, tool_names, f"Expected MCP tool [{expected}] to be registered")

    def test_resources_list_and_read(self):
        """Verify MCP resources protocol implementation (resources/list & resources/read)."""
        # 1. Test resources/list
        req_list = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "resources/list",
            "params": {}
        }
        res_list = mcp_server.handle_json_rpc(req_list)
        self.assertIn("result", res_list)
        resources = res_list["result"].get("resources", [])
        resource_uris = [r["uri"] for r in resources]

        self.assertIn("vault://stars/index.md", resource_uris)
        self.assertIn("vault://stars/catalog.json", resource_uris)
        self.assertIn("vault://system/health", resource_uris)

        # 2. Test resources/read on vault://stars/index.md
        req_read = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "resources/read",
            "params": {"uri": "vault://stars/index.md"}
        }
        res_read = mcp_server.handle_json_rpc(req_read)
        self.assertIn("result", res_read)
        contents = res_read["result"].get("contents", [])
        self.assertTrue(len(contents) > 0)
        self.assertEqual(contents[0]["uri"], "vault://stars/index.md")
        self.assertIn("text", contents[0])

    def test_vault_check_panic_tool(self):
        """Verify vault_check_panic reports correct lock status."""
        req = {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {
                "name": "vault_check_panic",
                "arguments": {}
            }
        }
        # Panic is OFF
        res = mcp_server.handle_json_rpc(req)
        content_text = res["result"]["content"][0]["text"]
        data = json.loads(content_text)
        self.assertFalse(data.get("locked"), "Panic should be false initially")

        # Turn Panic ON
        compliance_guard.set_panic_button(True)
        res_locked = mcp_server.handle_json_rpc(req)
        content_text_locked = res_locked["result"]["content"][0]["text"]
        data_locked = json.loads(content_text_locked)
        self.assertTrue(data_locked.get("locked"), "Panic should be true when active")

    def test_vault_audit_compliance_tool(self):
        """Verify vault_audit_compliance tool performs scan on given repo."""
        req = {
            "jsonrpc": "2.0",
            "id": 5,
            "method": "tools/call",
            "params": {
                "name": "vault_audit_compliance",
                "arguments": {
                    "repo_path": BASE_DIR
                }
            }
        }
        res = mcp_server.handle_json_rpc(req)
        self.assertIn("result", res)
        data = json.loads(res["result"]["content"][0]["text"])
        self.assertTrue(data.get("success"), "Compliance audit should execute cleanly")
        self.assertIn("compliant", data)

    def test_vault_search_stars_and_query_lists(self):
        """Verify vault_search_stars and vault_query_lists retrieve stored Star data."""
        # 1. Query lists
        req_lists = {
            "jsonrpc": "2.0",
            "id": 6,
            "method": "tools/call",
            "params": {
                "name": "vault_query_lists",
                "arguments": {}
            }
        }
        res_lists = mcp_server.handle_json_rpc(req_lists)
        lists_data = json.loads(res_lists["result"]["content"][0]["text"])
        self.assertTrue(lists_data.get("success"))
        self.assertTrue(lists_data.get("total_lists", 0) > 0)

        # 2. Search stars
        req_search = {
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/call",
            "params": {
                "name": "vault_search_stars",
                "arguments": {
                    "query": "",
                    "limit": 5
                }
            }
        }
        res_search = mcp_server.handle_json_rpc(req_search)
        search_data = json.loads(res_search["result"]["content"][0]["text"])
        self.assertTrue(search_data.get("success"))
        self.assertTrue(len(search_data.get("results", [])) > 0)

if __name__ == "__main__":
    unittest.main()
