# tests/test_star_vault_engine.py
# Antigravity Git-Vault - Unit Tests for Star Vault Engine

import os
import sys
import json
import tempfile
import unittest
from unittest.mock import patch, MagicMock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core import star_vault_engine


class TestStarVaultEngine(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_vault_file = os.path.join(self.temp_dir.name, "starred_vault.json")
        self.test_markdown_file = os.path.join(self.temp_dir.name, "STARS_INDEX.md")

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_default_seed_and_load(self):
        """Test vault initialization with 19 repos and 8 lists from <owner>."""
        vault = star_vault_engine.load_starred_vault(vault_file=self.test_vault_file)
        self.assertEqual(vault.get("version"), "1.0")
        self.assertEqual(vault.get("account"), "<owner>")
        self.assertEqual(vault.get("banned_source_account"), "<owner>")
        self.assertEqual(len(vault.get("repositories", [])), 19)
        self.assertEqual(len(vault.get("lists", [])), 8)

        # Check stats aggregation
        stats = vault.get("stats", {})
        self.assertEqual(stats.get("total_stars"), 19)
        self.assertEqual(stats.get("total_lists"), 8)
        self.assertIn("Python", stats.get("languages", {}))

    def test_filtering_and_querying(self):
        """Test filtering repos by list, language, and search query."""
        vault = star_vault_engine.load_starred_vault(vault_file=self.test_vault_file)

        # 1. Filter by list
        skill_repos = star_vault_engine.filter_vault_repos(vault, list_name="SKILL")
        self.assertEqual(len(skill_repos), 2)
        full_names = [r["full_name"] for r in skill_repos]
        self.assertIn("ConardLi/garden-skills", full_names)
        self.assertIn("anthropics/anthropic-quickstarts", full_names)

        # 2. Filter by language
        rust_repos = star_vault_engine.filter_vault_repos(vault, language="Rust")
        self.assertGreaterEqual(len(rust_repos), 2)
        rust_names = [r["full_name"] for r in rust_repos]
        self.assertIn("astral-sh/uv", rust_names)
        self.assertIn("BurntSushi/ripgrep", rust_names)

        # 3. Search query
        search_res = star_vault_engine.filter_vault_repos(vault, search="agent")
        self.assertGreater(len(search_res), 0)

    def test_incremental_merge_and_dedup(self):
        """Test merge_repos_into_vault dedupes by full_name and merges list memberships."""
        star_vault_engine.load_starred_vault(vault_file=self.test_vault_file)

        # Merge existing repo with new list tag
        update_item = [{
            "full_name": "astral-sh/uv",
            "lists": ["agent tool"]  # was "?Tool?"
        }]
        res = star_vault_engine.merge_repos_into_vault(update_item, vault_file=self.test_vault_file)
        self.assertEqual(res["added"], 0)
        self.assertEqual(res["updated"], 1)

        v_updated = star_vault_engine.load_starred_vault(vault_file=self.test_vault_file)
        uv_repo = next(r for r in v_updated["repositories"] if r["full_name"] == "astral-sh/uv")
        self.assertIn("?Tool?", uv_repo["lists"])
        self.assertIn("agent tool", uv_repo["lists"])

        # Add brand new repo
        new_item = [{
            "full_name": "torvalds/linux",
            "description": "Linux kernel source tree",
            "primary_language": "C",
            "lists": ["Kernel"]
        }]
        res2 = star_vault_engine.merge_repos_into_vault(new_item, vault_file=self.test_vault_file)
        self.assertEqual(res2["added"], 1)
        self.assertEqual(res2["total"], 20)

    def test_delete_repo_and_add_list(self):
        """Test deleting repository and creating a new list."""
        star_vault_engine.load_starred_vault(vault_file=self.test_vault_file)

        # Create list
        list_res = star_vault_engine.add_or_create_list("AI Infra", "Infrastructures for LLMs", vault_file=self.test_vault_file)
        self.assertTrue(list_res["success"])
        self.assertTrue(list_res["created"])

        # Delete repo
        deleted = star_vault_engine.delete_repo_from_vault("ConardLi/garden-skills", vault_file=self.test_vault_file)
        self.assertTrue(deleted)

        v_after = star_vault_engine.load_starred_vault(vault_file=self.test_vault_file)
        names = [r["full_name"] for r in v_after["repositories"]]
        self.assertNotIn("ConardLi/garden-skills", names)
        self.assertEqual(len(v_after["repositories"]), 18)

    def test_manual_import_parsing(self):
        """Test manual import parser with various line formats and URLs."""
        star_vault_engine.load_starred_vault(vault_file=self.test_vault_file)
        raw_input = """
        # Comment line to ignore
        https://github.com/vllm-project/vllm
        sgl-project/sglang
        https://github.com/ollama/ollama.git
        invalid line without slash
        vllm-project/vllm # Duplicate to dedupe
        """
        imported = star_vault_engine.parse_manual_import(
            raw_input,
            default_list="DSH",
            enrich_meta=False,
            vault_file=self.test_vault_file
        )
        self.assertEqual(len(imported), 3)
        fns = [r["full_name"] for r in imported]
        self.assertIn("vllm-project/vllm", fns)
        self.assertIn("sgl-project/sglang", fns)
        self.assertIn("ollama/ollama", fns)

        v_now = star_vault_engine.load_starred_vault(vault_file=self.test_vault_file)
        self.assertEqual(len(v_now["repositories"]), 19 + 3)

    def test_markdown_rendering(self):
        """Test STARS_INDEX.md catalog rendering per Claude Design System."""
        vault = star_vault_engine.load_starred_vault(vault_file=self.test_vault_file)
        md = star_vault_engine.render_stars_markdown(vault_data=vault, output_file=self.test_markdown_file)

        self.assertTrue(os.path.exists(self.test_markdown_file))
        self.assertIn("# Git-Vault Star 资产索引库 (Star Vault Catalog)", md)
        self.assertIn("## 1. 资产概览", md)
        self.assertIn("### List: agent tool", md)
        self.assertIn("### List: SKILL", md)
        self.assertIn("ConardLi/garden-skills", md)
        self.assertIn("| 仓库 | 描述 | 语言 | Stars | 归档时间 |", md)

    @patch("core.star_vault_engine.execute_graphql")
    def test_graphql_cloud_lists_fetch(self, mock_gql):
        """Test parsing of GraphQL viewer.lists response."""
        mock_gql.return_value = {
            "data": {
                "viewer": {
                    "login": "<owner>",
                    "lists": {
                        "totalCount": 1,
                        "nodes": [
                            {
                                "id": "list_123",
                                "name": "LLM Frameworks",
                                "description": "Frameworks",
                                "slug": "llm-frameworks",
                                "repositories": {
                                    "totalCount": 1,
                                    "nodes": [
                                        {
                                            "id": "repo_456",
                                            "nameWithOwner": "openai/openai-python",
                                            "description": "Python client library",
                                            "stargazerCount": 24000,
                                            "primaryLanguage": {"name": "Python", "color": "#3572A5"},
                                            "url": "https://github.com/openai/openai-python"
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                }
            }
        }
        res = star_vault_engine.fetch_cloud_lists_graphql(token="test_token")
        self.assertTrue(res["success"])
        self.assertEqual(res["login"], "<owner>")
        self.assertEqual(len(res["lists"]), 1)
        self.assertEqual(res["lists"][0]["name"], "LLM Frameworks")
        self.assertEqual(len(res["repositories"]), 1)
        self.assertEqual(res["repositories"][0]["full_name"], "openai/openai-python")
        self.assertEqual(res["repositories"][0]["lists"], ["LLM Frameworks"])

    @patch("urllib.request.urlopen")
    def test_rest_stars_fetch(self, mock_urlopen):
        """Test fetching stars via REST API with star+json timestamp."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps([
            {
                "starred_at": "2024-01-01T12:00:00Z",
                "repo": {
                    "full_name": "astral-sh/ruff",
                    "name": "ruff",
                    "owner": {"login": "astral-sh"},
                    "description": "An extremely fast Python linter",
                    "language": "Rust",
                    "stargazers_count": 35000,
                    "html_url": "https://github.com/astral-sh/ruff"
                }
            }
        ]).encode("utf-8")
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        res = star_vault_engine.fetch_cloud_stars_rest(token="test_token", max_pages=1, per_page=1)
        self.assertTrue(res["success"])
        self.assertEqual(res["count"], 1)
        self.assertEqual(res["repositories"][0]["full_name"], "astral-sh/ruff")
        self.assertEqual(res["repositories"][0]["starred_at"], "2024-01-01T12:00:00Z")

    @patch("urllib.request.urlopen")
    def test_star_repo_rest_put(self, mock_urlopen):
        """Test idempotent star PUT method."""
        mock_resp = MagicMock()
        mock_resp.status = 204
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        success, status, msg = star_vault_engine.star_repo_rest("owner", "repo", token="test_token", pacing_delay=0)
        self.assertTrue(success)
        self.assertEqual(status, 204)

    def test_restore_to_account_stream_dry_run(self):
        """Test streaming generator produces start, steps, and complete events."""
        star_vault_engine.load_starred_vault(vault_file=self.test_vault_file)
        events = list(star_vault_engine.restore_to_account_stream(
            target_account="<owner>",
            dry_run=True,
            pacing_delay=0,
            vault_file=self.test_vault_file
        ))
        self.assertGreater(len(events), 2)
        self.assertEqual(events[0]["type"], "start")
        self.assertEqual(events[0]["account"], "<owner>")

        # Check list steps
        list_events = [e for e in events if e["type"] == "list_step"]
        self.assertEqual(len(list_events), 8)

        # Check repo steps
        repo_events = [e for e in events if e["type"] == "repo_step"]
        self.assertEqual(len(repo_events), 19)

        # Check complete event
        self.assertEqual(events[-1]["type"], "complete")
        self.assertEqual(events[-1]["percent"], 100)

    @patch("core.star_vault_engine.execute_graphql")
    def test_graphql_user_list_items_field(self, mock_gql):
        """Test parsing of GraphQL viewer.lists when items field is present."""
        mock_gql.return_value = {
            "data": {
                "viewer": {
                    "login": "<owner>",
                    "lists": {
                        "totalCount": 1,
                        "nodes": [
                            {
                                "id": "list_999",
                                "name": "Agentic AI",
                                "description": "Agent ecosystem",
                                "slug": "agentic-ai",
                                "items": {
                                    "totalCount": 1,
                                    "nodes": [
                                        {
                                            "id": "repo_node_999",
                                            "nameWithOwner": "modelcontextprotocol/servers",
                                            "description": "MCP reference servers",
                                            "stargazerCount": 5400,
                                            "primaryLanguage": {"name": "TypeScript", "color": "#3178c6"},
                                            "url": "https://github.com/modelcontextprotocol/servers"
                                        }
                                    ]
                                }
                            }
                        ]
                    }
                }
            }
        }
        res = star_vault_engine.fetch_cloud_lists_graphql(token="test_token")
        self.assertTrue(res["success"])
        self.assertEqual(len(res["lists"]), 1)
        self.assertEqual(res["lists"][0]["name"], "Agentic AI")
        self.assertEqual(len(res["repositories"]), 1)
        self.assertEqual(res["repositories"][0]["full_name"], "modelcontextprotocol/servers")
        self.assertEqual(res["repositories"][0]["lists"], ["Agentic AI"])

    @patch("core.star_vault_engine.execute_graphql")
    def test_graphql_create_user_list_mutation(self, mock_gql):
        """Test createUserList mutation returning list object."""
        mock_gql.return_value = {
            "data": {
                "createUserList": {
                    "list": {
                        "id": "ul_12345",
                        "name": "TestingList",
                        "slug": "testinglist"
                    }
                }
            }
        }
        success, list_id, msg = star_vault_engine.create_user_list_graphql("TestingList", token="test_token")
        self.assertTrue(success)
        self.assertEqual(list_id, "ul_12345")
        self.assertIn("Created list TestingList", msg)

    @patch("core.star_vault_engine.execute_graphql")
    def test_graphql_add_repo_to_user_list_mutation(self, mock_gql):
        """Test updateUserListsForItem mutation with listIds and itemId."""
        mock_gql.return_value = {
            "data": {
                "updateUserListsForItem": {
                    "clientMutationId": None,
                    "lists": [{"id": "ul_12345", "name": "TestingList"}]
                }
            }
        }
        success, msg = star_vault_engine.add_repo_to_user_list_graphql(
            list_ids=["ul_12345"],
            repo_id="R_kgDO12345",
            token="test_token"
        )
        self.assertTrue(success)
        self.assertEqual(msg, "Assigned to list")
        # Verify variables passed to execute_graphql
        call_args = mock_gql.call_args[1]
        variables = call_args.get("variables", {})
        self.assertEqual(variables.get("listIds"), ["ul_12345"])
        self.assertEqual(variables.get("itemId"), "R_kgDO12345")

    def test_manual_import_git_urls_and_markdown(self):
        """Test manual import with GitLab/Gitee URLs and Markdown links."""
        star_vault_engine.load_starred_vault(vault_file=self.test_vault_file)
        raw_text = """
        https://gitlab.com/gitlab-org/gitlab-runner.git
        https://gitee.com/ascend/modelzoo
        - [FastAPI](https://github.com/tiangolo/fastapi)
        astral-sh/uv # modern python packaging
        """
        imported = star_vault_engine.parse_manual_import(
            raw_text,
            default_list="Toolbox",
            enrich_meta=False,
            vault_file=self.test_vault_file
        )
        self.assertEqual(len(imported), 4)
        fns = [r["full_name"] for r in imported]
        self.assertIn("gitlab-org/gitlab-runner", fns)
        self.assertIn("ascend/modelzoo", fns)
        self.assertIn("tiangolo/fastapi", fns)
        self.assertIn("astral-sh/uv", fns)

    @patch("core.star_vault_engine.add_repo_to_user_list_graphql")
    @patch("core.star_vault_engine.get_repo_graphql_id")
    @patch("core.star_vault_engine.star_repository")
    @patch("core.star_vault_engine.check_is_starred")
    @patch("core.star_vault_engine.create_github_user_list")
    @patch("core.star_vault_engine.fetch_cloud_lists_graphql")
    def test_restore_to_account_stream_live_flow(
        self, mock_fetch_lists, mock_create_list, mock_check_star,
        mock_star_repo, mock_get_repo_id, mock_add_to_list
    ):
        """Test live restore stream executes list creation, star PUT, and list assignment."""
        mock_fetch_lists.return_value = {"success": True, "lists": []}
        mock_create_list.return_value = (True, "mock_list_id_1", "Created")
        mock_check_star.return_value = False
        mock_star_repo.return_value = (True, 204, "Starred")
        mock_get_repo_id.return_value = "repo_node_1"
        mock_add_to_list.return_value = (True, "Assigned")

        star_vault_engine.load_starred_vault(vault_file=self.test_vault_file)
        events = list(star_vault_engine.restore_to_account_stream(
            token="test_pat",
            target_repo_names=["ConardLi/garden-skills"],
            recreate_lists=True,
            pacing_delay=0,
            dry_run=False,
            vault_file=self.test_vault_file
        ))

        # Check events
        types = [e["type"] for e in events]
        self.assertIn("start", types)
        self.assertIn("list_step", types)
        self.assertIn("repo_step", types)
        self.assertIn("complete", types)

        # Check that add_repo_to_user_list_graphql was called
        mock_add_to_list.assert_called()
        repo_event = next(e for e in events if e["type"] == "repo_step")
        self.assertTrue(repo_event["success"])
        self.assertIn("GraphQL 归入", repo_event["message"])


if __name__ == "__main__":
    unittest.main()

