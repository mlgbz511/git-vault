# tests/test_server_api.py
# Antigravity Git-Vault Server REST & SSE API Verification
import os
import sys
import time
import json
import threading
import urllib.request
import urllib.error
import unittest
import shutil
import subprocess
import tempfile
from unittest.mock import patch

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

import server
from core import compliance_guard

TEST_PORT = 18765

class TestServerAPI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compliance_guard.set_panic_button(False)
        cls._star_vault_path = os.path.join(BASE_DIR, "config", "starred_vault.json")
        cls._stars_index_path = os.path.join(BASE_DIR, "STARS_INDEX.md")
        cls._star_vault_backup = None
        cls._stars_index_backup = None
        if os.path.exists(cls._star_vault_path):
            with open(cls._star_vault_path, "r", encoding="utf-8") as f:
                cls._star_vault_backup = f.read()
        if os.path.exists(cls._stars_index_path):
            with open(cls._stars_index_path, "r", encoding="utf-8") as f:
                cls._stars_index_backup = f.read()

        cls.httpd = server.ThreadingHTTPServer(("127.0.0.1", TEST_PORT), server.GitVaultHandler)
        cls.server_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        compliance_guard.set_panic_button(False)
        if cls._star_vault_backup is not None:
            with open(cls._star_vault_path, "w", encoding="utf-8") as f:
                f.write(cls._star_vault_backup)
        if cls._stars_index_backup is not None:
            with open(cls._stars_index_path, "w", encoding="utf-8") as f:
                f.write(cls._stars_index_backup)

    def _make_git_repo(self, parent=None, prefix="git_vault_repo_"):
        """Portable fixture: temp git repo with one commit and one unstaged change."""
        repo = tempfile.mkdtemp(prefix=prefix, dir=parent)
        self.addCleanup(shutil.rmtree, repo, True)
        env = dict(
            os.environ,
            GIT_AUTHOR_NAME="git-vault test",
            GIT_AUTHOR_EMAIL="test@example.invalid",
            GIT_COMMITTER_NAME="git-vault test",
            GIT_COMMITTER_EMAIL="test@example.invalid",
        )
        subprocess.run(["git", "init", "-q", repo], check=True, capture_output=True)
        with open(os.path.join(repo, "a.txt"), "w", encoding="utf-8") as f:
            f.write("one\n")
        subprocess.run(["git", "-C", repo, "add", "a.txt"], check=True, capture_output=True, env=env)
        subprocess.run(["git", "-C", repo, "commit", "-q", "-m", "init"], check=True, capture_output=True, env=env)
        with open(os.path.join(repo, "a.txt"), "a", encoding="utf-8") as f:
            f.write("two\n")
        return repo

    def _get(self, path, timeout=30):
        url = f"http://127.0.0.1:{TEST_PORT}{path}"
        req = urllib.request.Request(url, headers={"Connection": "close"})
        for attempt in range(2):
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return resp.status, json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                try:
                    body = json.loads(e.read().decode("utf-8"))
                except Exception:
                    body = {}
                return e.code, body
            except (ConnectionResetError, urllib.error.URLError):
                if attempt == 0:
                    time.sleep(0.2)
                    continue
                raise

    def _post(self, path, payload=None, timeout=30):
        url = f"http://127.0.0.1:{TEST_PORT}{path}"
        data_bytes = json.dumps(payload or {}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=data_bytes,
            headers={"Content-Type": "application/json", "Connection": "close"}
        )
        for attempt in range(2):
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return resp.status, json.loads(resp.read().decode("utf-8"))
            except urllib.error.HTTPError as e:
                try:
                    body = json.loads(e.read().decode("utf-8"))
                except Exception:
                    body = {}
                return e.code, body
            except (ConnectionResetError, urllib.error.URLError):
                if attempt == 0:
                    time.sleep(0.2)
                    continue
                raise

    def test_panic_button_api(self):
        # 1. Get panic button
        status, data = self._get("/api/panic-button")
        self.assertEqual(status, 200)
        self.assertIn("locked", data)

        # 2. Toggle panic button to True
        status, data = self._post("/api/panic-button", {"locked": True})
        self.assertEqual(status, 200)
        self.assertTrue(data["locked"])
        self.assertTrue(compliance_guard.is_panic_button_active())

        # 3. Toggle back to False
        status, data = self._post("/api/panic-button", {"locked": False})
        self.assertEqual(status, 200)
        self.assertFalse(data["locked"])

    def test_repo_diff_api(self):
        vault_repo = self._make_git_repo()
        status, data = self._get(f"/api/repo/diff?path={urllib.parse.quote(vault_repo)}")
        self.assertEqual(status, 200)
        self.assertTrue(data["success"])
        self.assertIn("stat_unstaged", data)

    def test_repo_commits_api(self):
        vault_repo = self._make_git_repo()
        status, data = self._get(f"/api/repo/commits?path={urllib.parse.quote(vault_repo)}&count=5")
        self.assertEqual(status, 200)
        self.assertTrue(data["success"])
        self.assertTrue(len(data["commits"]) > 0)

    def test_network_routes_api(self):
        status, data = self._get("/api/network/routes")
        self.assertEqual(status, 200)
        self.assertIn("routes", data)
        self.assertEqual(data["routes"]["gitee"]["mode"], "direct")

        # Gitee lock in API
        status, update_res = self._post("/api/network/routes", {"platform": "gitee", "mode": "proxy"})
        self.assertEqual(status, 200)
        self.assertFalse(update_res["success"])

    def test_mcp_message_endpoint(self):
        rpc_payload = {
            "jsonrpc": "2.0",
            "id": 99,
            "method": "tools/list"
        }
        status, data = self._post("/mcp/message", rpc_payload)
        self.assertEqual(status, 200)
        self.assertEqual(data["jsonrpc"], "2.0")
        self.assertTrue(len(data["result"]["tools"]) >= 10)

    def test_compliance_scan_api(self):
        payload = {"text": "const token = '" + "ghp_" + "0" * 36 + "';"}
        status, data = self._post("/api/compliance/scan", payload)
        self.assertEqual(status, 200)
        self.assertFalse(data["passed"])
        self.assertTrue(data["count"] >= 1)

    def test_gitignore_api(self):
        status, data = self._get("/api/gitignore/status")
        self.assertEqual(status, 200)
        self.assertIn("presets", data)
        self.assertIn("custom_templates", data)
        self.assertIn("is_configured", data)

        # Apply strict preset
        status, post_data = self._post("/api/gitignore/apply", {"preset": "strict"})
        self.assertEqual(status, 200)
        self.assertTrue(post_data["success"])

        # Custom template save via API
        status, save_res = self._post("/api/gitignore/custom/save", {
            "id": "api_test_tmpl",
            "name": "API测试模板",
            "content": "temp/\n*.swp\n",
            "description": "自动化测试专用模板"
        })
        self.assertEqual(status, 200)
        self.assertTrue(save_res["success"])

        # Delete custom template via API
        status, del_res = self._post("/api/gitignore/custom/delete", {"id": "api_test_tmpl"})
        self.assertEqual(status, 200)
        self.assertTrue(del_res["success"])

        # 4. Clear all and reset to seed
        status, clear_res = self._post("/api/stars/clear-all", {})
        self.assertEqual(status, 200)
        self.assertTrue(clear_res["success"])
        self.assertEqual(clear_res["total_stars"], 0)

        status, reset_res = self._post("/api/stars/reset-seed", {})
        self.assertEqual(status, 200)
        self.assertTrue(reset_res["success"])
        self.assertEqual(reset_res["total_stars"], 19)

    def test_multi_account_api(self):
        # 1. 查询账号列表
        status, data = self._get("/api/vault/accounts")
        self.assertEqual(status, 200)
        self.assertIn("accounts", data)
        self.assertIn("repo_account_bindings", data)

        # 2. 新增账号
        status, save_res = self._post("/api/vault/account/save", {
            "platform": "github",
            "token": "ghp_" + "api_test_token_123456",
            "username": "api_user",
            "alias": "API测试账号",
            "is_default": False
        })
        self.assertEqual(status, 200)
        self.assertTrue(save_res["success"])
        acc_id = save_res["account_id"]

        # 3. 设为默认账号
        status, def_res = self._post("/api/vault/account/set-default", {"account_id": acc_id})
        self.assertEqual(status, 200)
        self.assertTrue(def_res["success"])

        # 4. 绑定仓库
        fake_repo = "<vault-root>\\api_test_repo"
        status, bind_res = self._post("/api/vault/repo-binding", {
            "repo_path": fake_repo,
            "platform": "github",
            "account_id": acc_id
        })
        self.assertEqual(status, 200)
        self.assertTrue(bind_res["success"])

        # 5. 删除账号
        status, del_res = self._post("/api/vault/account/delete", {"account_id": acc_id})
        self.assertEqual(status, 200)
        self.assertTrue(del_res["success"])

    def test_universal_secrets_api(self):
        # 1. 保存通用密钥
        status, save_res = self._post("/api/vault/secret/save", {
            "service": "openai",
            "secret": "sk-" + "proj-test1234567890",
            "env_var": "OPENAI_API_KEY",
            "category": "ai",
            "alias": "GPT-4o 自动化测试Key"
        })
        self.assertEqual(status, 200)
        self.assertTrue(save_res["success"])

        # 2. 查询通用密钥列表
        status, data = self._get("/api/vault/secrets?category=ai")
        self.assertEqual(status, 200)
        self.assertTrue(any(s["service"] == "openai" for s in data["secrets"]))

        # 3. 删除通用密钥
        status, del_res = self._post("/api/vault/secret/delete", {"service": "openai"})
        self.assertEqual(status, 200)
        self.assertTrue(del_res["success"])

    def test_repos_scan_and_management_api(self):
        # 1. 主动扫描探测 API
        workspace = tempfile.mkdtemp(prefix="git_vault_scan_")
        self.addCleanup(shutil.rmtree, workspace, True)
        repo = self._make_git_repo(parent=workspace)
        missing_repo = os.path.join(workspace, "non_existent_dir_9999")
        status, scan_data = self._post("/api/repos/scan", {
            "scan_path": workspace,
            "depth": 2,
            "only_mine": True
        }, timeout=30)
        self.assertEqual(status, 200)
        self.assertIn("repos", scan_data)
        self.assertIn("stats", scan_data)
        self.assertTrue(scan_data["stats"]["my_repos_count"] >= 1)

        # 2. 手动添加仓库 API (测试不存在路径的错误拦截)
        status, add_err = self._post("/api/repos/manual-add", {
            "path": missing_repo,
            "alias": "Fake"
        })
        self.assertEqual(status, 200)
        self.assertFalse(add_err["success"])
        self.assertIn("路径不存在", add_err["error"])

        # 3. 手动添加真实仓库
        repo_target = repo
        status, add_ok = self._post("/api/repos/manual-add", {
            "path": repo_target,
            "alias": "Git-Vault Core"
        })
        self.assertEqual(status, 200)
        self.assertTrue(add_ok["success"])
        self.assertEqual(add_ok["repo"]["added_by"], "manual")

        # 4. 忽略/移出仓库 API
        status, ign_res = self._post("/api/repos/ignore", {"path": repo_target})
        self.assertEqual(status, 200)
        self.assertTrue(ign_res["success"])

        # 5. 解除忽略
        status, unign_res = self._post("/api/repos/unignore", {"path": repo_target})
        self.assertEqual(status, 200)
        self.assertTrue(unign_res["success"])

        # 6. 双模健康检查验证
        status, health_data = self._get("/api/health-check")
        self.assertEqual(status, 200)
        self.assertIn("platforms", health_data)
        self.assertIn("gitee", health_data["platforms"])
        # 凭据取决于本机 vault，公开测试只校验结构，不断言 authenticated
        self.assertIn("status", health_data["platforms"]["gitee"])

        # 7. 验证 60 秒内存安全防抖缓存生效
        status2, cached_health = self._get("/api/health-check")
        self.assertEqual(status2, 200)
        self.assertTrue(cached_health.get("cached", False))

        # 8. 验证 ?force=true 强制重新握手穿透缓存
        status3, fresh_health = self._get("/api/health-check?force=true")
        self.assertEqual(status3, 200)
        self.assertFalse(fresh_health.get("cached", True))

        # 9. 测试仓库远程源与账号一键迁移 (从 <owner> 迁移至 <owner>)
        temp_mig_repo = tempfile.mkdtemp(prefix="migrate_test_")
        try:
            subprocess.run(["git", "init", temp_mig_repo], check=True, capture_output=True)
            subprocess.run(["git", "remote", "add", "origin", "https://github.com/<owner>/test-proj.git"], cwd=temp_mig_repo, check=True, capture_output=True)
            status, mig_res = self._post("/api/repo/migrate-owner", {
                "repo_path": temp_mig_repo,
                "new_user": "<owner>"
            })
            self.assertEqual(status, 200)
            self.assertTrue(mig_res["success"])
            self.assertEqual(mig_res["new_user"], "<owner>")
            rem_chk = subprocess.run(["git", "remote", "get-url", "origin"], cwd=temp_mig_repo, capture_output=True, text=True)
            self.assertIn("<owner>", rem_chk.stdout)
        finally:
            shutil.rmtree(temp_mig_repo, ignore_errors=True)

    def test_repo_compliance_audit_and_remediation_api(self):
        import tempfile
        import subprocess
        import shutil

        temp_dir = tempfile.mkdtemp(prefix="git_audit_api_test_")
        try:
            # 1. 初始化临时 Git 仓库
            subprocess.run(["git", "init", temp_dir], check=True, capture_output=True)
            # 写入未忽略的敏感配置与证书
            env_file = os.path.join(temp_dir, ".env")
            with open(env_file, "w", encoding="utf-8") as f:
                f.write("OPENAI_API_KEY=" + "sk-" + "proj-test1234567890abcdef\n")
            
            key_file = os.path.join(temp_dir, "server.pem")
            with open(key_file, "w", encoding="utf-8") as f:
                f.write("-----BEGIN " + "PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASC\n-----END " + "PRIVATE KEY-----\n")

            # 2. 发起 API 安全体检
            status, audit_res = self._post("/api/compliance/repo-audit", {"repo_path": temp_dir})
            self.assertEqual(status, 200)
            self.assertTrue(audit_res["success"])
            self.assertIn("score", audit_res)
            self.assertIn("status", audit_res)
            self.assertNotEqual(audit_res["status"], "SAFE")
            self.assertTrue(audit_res["summary"]["total_violations"] >= 2)
            self.assertTrue(audit_res["summary"]["remediations_available"] >= 1)

            # 3. 发起 API 一键脱敏 (注入 .gitignore)
            remediations = audit_res["remediations"]
            patterns = []
            for r in remediations:
                patterns.extend(r.get("patterns", []))

            status, rem_res = self._post("/api/compliance/remediate-gitignore", {
                "repo_path": temp_dir,
                "patterns": patterns
            })
            self.assertEqual(status, 200)
            self.assertTrue(rem_res["success"])
            self.assertTrue(any(".env" in p for p in rem_res["added_patterns"]))

            # 4. 再次体检，验证脱敏生效
            status, reaudit_res = self._post("/api/compliance/repo-audit", {"repo_path": temp_dir})
            self.assertEqual(status, 200)
            self.assertEqual(reaudit_res["summary"]["remediations_available"], 0)
            self.assertEqual(reaudit_res["score"], 100)
            self.assertEqual(reaudit_res["status"], "SAFE")
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_locate_folder_and_batch_migrate_api(self):
        # 1. Test locate-folder API (hint path, no machine-specific workspace root)
        holder = tempfile.mkdtemp(prefix="git_vault_locate_")
        self.addCleanup(shutil.rmtree, holder, True)
        repo = self._make_git_repo(parent=holder)
        folder_name = os.path.basename(repo)
        status, res = self._post("/api/system/locate-folder", {
            "folder_name": folder_name,
            "hints": [holder]
        })
        self.assertEqual(status, 200)
        self.assertTrue(res["success"])
        self.assertTrue(folder_name in res["path"].lower())

        # 2. Test locate-folder with non-existent folder
        status, not_found = self._post("/api/system/locate-folder", {
            "folder_name": "totally_non_existent_folder_xyz_123"
        })
        self.assertEqual(status, 200)
        self.assertFalse(not_found["success"])

        # 3. Test batch migration API
        status, mig_res = self._post("/api/repos/migrate-all-to-511", {
            "new_user": "<owner>"
        }, timeout=30)
        self.assertEqual(status, 200)
        self.assertTrue(mig_res["success"])
        self.assertIn("total_migrated", mig_res)

        # 4. Test sync audit logs API
        status, audit_res = self._get("/api/sync/audit-logs")
        self.assertEqual(status, 200)
        self.assertTrue(audit_res["success"])
        self.assertIn("logs", audit_res)

    def test_repo_detail_and_sync_stream_api(self):
        vault_repo = self._make_git_repo()
        # 1. Test /api/repo/detail
        status, detail = self._get(f"/api/repo/detail?path={urllib.parse.quote(vault_repo)}")
        self.assertEqual(status, 200)
        self.assertTrue(detail.get("success"))
        self.assertEqual(detail.get("name"), os.path.basename(vault_repo))
        self.assertIn("branch", detail)
        self.assertIn("commits", detail)
        self.assertIn("remote_cards", detail)
        self.assertTrue(len(detail.get("commits", [])) > 0)

        # 2. Test /api/sync-stream against a local bare remote (offline, no credentials)
        remote = tempfile.mkdtemp(prefix="git_vault_remote_")
        self.addCleanup(shutil.rmtree, remote, True)
        subprocess.run(["git", "init", "--bare", "-q", remote], check=True, capture_output=True)
        subprocess.run(["git", "-C", vault_repo, "remote", "add", "origin", remote], check=True, capture_output=True)
        url = f"http://127.0.0.1:{TEST_PORT}/api/sync-stream?repo_path={urllib.parse.quote(vault_repo)}&target_platform=gitee"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=30) as resp:
            self.assertEqual(resp.status, 200)
            stream_content = resp.read().decode("utf-8")
            self.assertIn("data:", stream_content)
            self.assertIn("complete", stream_content)

    def test_static_html_served(self):
        url = f"http://127.0.0.1:{TEST_PORT}/index.html"
        with urllib.request.urlopen(url, timeout=5) as resp:
            self.assertEqual(resp.status, 200)
            content = resp.read().decode("utf-8")
            self.assertIn("Git-Vault Enterprise &amp; Agent Guard", content)
            self.assertIn("tab-security", content)
            self.assertIn("tab-stars", content)
            self.assertIn("starCategoryChips", content)
            self.assertIn("starContainer", content)
            self.assertIn("btnToggleStarRestoreMode", content)
            self.assertIn("starRestoreActiveBar", content)

    def test_stars_vault_and_export_api(self):
        # 1. GET /api/stars/vault
        status, data = self._get("/api/stars/vault")
        self.assertEqual(status, 200)
        self.assertTrue(data["success"])
        self.assertIn("lists", data)
        self.assertIn("repositories", data)
        self.assertIn("stats", data)
        self.assertTrue(len(data["lists"]) >= 8)

        # 2. Filter by list
        status, filtered = self._get("/api/stars/vault?list_name=SKILL")
        self.assertEqual(status, 200)
        self.assertTrue(all("SKILL" in r.get("lists", []) for r in filtered["repositories"]))

        # 3. GET /api/stars/export-markdown
        url = f"http://127.0.0.1:{TEST_PORT}/api/stars/export-markdown"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=10) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("text/markdown", resp.headers.get("Content-Type", ""))
            body = resp.read().decode("utf-8")
            self.assertIn("Git-Vault Star", body)

    @patch("server.star_vault_engine.enrich_repo_meta_rest")
    def test_stars_manual_import_and_crud_api(self, mock_enrich):
        mock_enrich.return_value = {
            "full_name": "test-mock-owner/test-mock-repo",
            "owner": "test-mock-owner",
            "name": "test-mock-repo",
            "description": "Mock repo for testing",
            "primary_language": "Python",
            "language": "Python",
            "language_color": "#3572A5",
            "stargazers_count": 42,
            "node_id": "mock_node_id_123",
            "html_url": "https://github.com/test-mock-owner/test-mock-repo",
            "found": True
        }
        # 1. Manual import
        status, res = self._post("/api/stars/manual-import", {
            "list_name": "agent tool",
            "repos": ["test-mock-owner/test-mock-repo"]
        })
        self.assertEqual(status, 200)
        self.assertTrue(res["success"])
        self.assertEqual(res["imported_count"], 1)

        # 2. Create custom list
        status, list_res = self._post("/api/stars/create-list", {
            "name": "IntegrationTestList",
            "description": "Integration test created list"
        })
        self.assertEqual(status, 200)
        self.assertTrue(list_res["success"])

        # 3. Delete repo from vault
        status, del_res = self._post("/api/stars/delete-repo", {
            "full_name": "test-mock-owner/test-mock-repo"
        })
        self.assertEqual(status, 200)
        self.assertTrue(del_res["success"])

    def test_stars_restore_stream_api(self):
        # Test restore-stream in dry_run mode with 0 pacing delay
        url = f"http://127.0.0.1:{TEST_PORT}/api/stars/restore-stream?dry_run=true&pacing_delay=0&repos=ConardLi/garden-skills&recreate_lists=false"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=15) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("text/event-stream", resp.headers.get("Content-Type", ""))
            content = resp.read().decode("utf-8")
            self.assertIn("data:", content)
            self.assertIn("start", content)
            self.assertIn("complete", content)

    @patch("server.star_vault_engine.sync_stars_vault_repo")
    @patch("server.star_vault_engine.query_github_star_lists")
    @patch("server.star_vault_engine.fetch_flat_stars")
    @patch("server.star_vault_engine.star_repository")
    def test_stars_push_cloud_and_fetch_cloud_api(self, mock_star_repo, mock_fetch_flat, mock_gql, mock_sync):
        mock_sync.return_value = {
            "success": True,
            "committed": True,
            "commit_hash": "mock1234",
            "sync_details": {"results": []}
        }
        mock_star_repo.return_value = {"success": True, "status": 204, "status_code": 204, "message": "Starred"}
        # 1. POST /api/stars/push-cloud
        status, push_res = self._post("/api/stars/push-cloud", {
            "branch": "main"
        })
        self.assertEqual(status, 200)
        self.assertTrue(push_res.get("success"))

        # 2. POST /api/stars/fetch-cloud error branch
        mock_gql.return_value = {"success": False, "error": "Bad credentials"}
        status, fetch_err = self._post("/api/stars/fetch-cloud", {
            "token": "invalid_test_token"
        })
        self.assertEqual(status, 502)
        self.assertFalse(fetch_err.get("success"))

        # 3. POST /api/stars/fetch-cloud success branch
        mock_gql.return_value = {
            "success": True,
            "lists": [{"name": "MockList", "description": "Mock list desc", "repositories": []}],
            "repositories": []
        }
        mock_fetch_flat.return_value = []
        status, fetch_ok = self._post("/api/stars/fetch-cloud", {
            "token": "mock_valid_token"
        })
        self.assertEqual(status, 200)
        self.assertTrue(fetch_ok.get("success"))

        # 4. POST /api/stars/star-repo
        status, star_res = self._post("/api/stars/star-repo", {
            "full_name": "octocat/Hello-World",
            "token": "mock_token"
        })
        self.assertEqual(status, 200)
        self.assertTrue(star_res.get("success"))

    @patch("server.agent_installer.install_antigravity_plugin")
    def test_agent_integration_apis(self, mock_install):
        # 1. GET /api/agent/status
        status, res = self._get("/api/agent/status")
        self.assertEqual(status, 200)
        self.assertIn("plugin_installed", res)
        self.assertIn("tools_count", res)
        self.assertIn("schemas_installed", res)

        # 2. GET /api/agent/dsh-config
        status, dsh_res = self._get("/api/agent/dsh-config")
        self.assertEqual(status, 200)
        self.assertIn("manifest", dsh_res)
        self.assertIn("install_command", dsh_res)
        self.assertTrue(dsh_res["install_command"].startswith("dsh plugin add"))

        # 3. POST /api/agent/install-antigravity
        mock_install.return_value = {
            "success": True,
            "plugin_dir": "<path>/fake/plugin",
            "schemas_generated": 10,
            "mcp_config_updated": True
        }
        status, inst_res = self._post("/api/agent/install-antigravity", {})
        self.assertEqual(status, 200)
        self.assertTrue(inst_res["success"])
        self.assertEqual(inst_res["schemas_generated"], 10)

    def _request_raw(self, method, path, headers=None, payload=None, timeout=30):
        url = f"http://127.0.0.1:{TEST_PORT}{path}"
        req_headers = {"Connection": "close"}
        if headers:
            req_headers.update(headers)
        data_bytes = None
        if payload is not None:
            if isinstance(payload, bytes):
                data_bytes = payload
            else:
                data_bytes = json.dumps(payload).encode("utf-8")
                if "Content-Type" not in req_headers:
                    req_headers["Content-Type"] = "application/json"

        req = urllib.request.Request(url, data=data_bytes, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                raw_body = resp.read().decode("utf-8")
                try:
                    body = json.loads(raw_body)
                except Exception:
                    body = raw_body
                return resp.status, resp_headers, body
        except urllib.error.HTTPError as e:
            resp_headers = {k.lower(): v for k, v in e.headers.items()}
            try:
                body = json.loads(e.read().decode("utf-8"))
            except Exception:
                body = {}
            return e.code, resp_headers, body

    def test_cors_trusted_origin_allowed(self):
        # 1. Loopback origin on GET
        status, headers, body = self._request_raw(
            "GET",
            "/api/panic-button",
            headers={"Origin": "http://127.0.0.1:8765"}
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("access-control-allow-origin"), "http://127.0.0.1:8765")
        self.assertIn("origin", headers.get("vary", "").lower())

        # 2. Localhost origin on POST
        status, headers, body = self._request_raw(
            "POST",
            "/api/panic-button",
            headers={"Origin": "http://localhost:8765"},
            payload={"locked": False}
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("access-control-allow-origin"), "http://localhost:8765")

        # 3. Localhost origin on OPTIONS preflight
        status, headers, body = self._request_raw(
            "OPTIONS",
            "/api/panic-button",
            headers={"Origin": "http://localhost:3000"}
        )
        self.assertEqual(status, 204)
        self.assertEqual(headers.get("access-control-allow-origin"), "http://localhost:3000")
        self.assertIn("POST", headers.get("access-control-allow-methods", ""))

    def test_cors_no_origin_header_allowed(self):
        # Requests without Origin header (cURL, Python scripts, Antigravity background tasks) work normally
        status, headers, body = self._request_raw("GET", "/api/status")
        self.assertEqual(status, 200)
        self.assertNotIn("access-control-allow-origin", headers)
        self.assertIn("identity", body)

        status, headers, body = self._request_raw("POST", "/api/panic-button", payload={"locked": False})
        self.assertEqual(status, 200)
        self.assertNotIn("access-control-allow-origin", headers)
        self.assertFalse(body["locked"])

    def test_multiple_host_and_origin_headers_rejected(self):
        # Multiple Host headers must be rejected with 400 Bad Request (RFC 7230 §5.4)
        import http.client
        conn = http.client.HTTPConnection("127.0.0.1", TEST_PORT)
        conn.putrequest("GET", "/api/status")
        conn.putheader("Host", f"127.0.0.1:{TEST_PORT}")
        conn.putheader("Host", "evil.com")
        conn.endheaders()
        resp = conn.getresponse()
        self.assertEqual(resp.status, 400)
        conn.close()

        # Multiple Origin headers on state-modifying requests must be rejected with 403 Forbidden
        conn = http.client.HTTPConnection("127.0.0.1", TEST_PORT)
        conn.putrequest("POST", "/api/panic-button", skip_host=True)
        conn.putheader("Host", f"127.0.0.1:{TEST_PORT}")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Origin", f"http://127.0.0.1:{TEST_PORT}")
        conn.putheader("Origin", "https://evil.com")
        payload = b'{"locked": false}'
        conn.putheader("Content-Length", str(len(payload)))
        conn.endheaders()
        conn.send(payload)
        resp = conn.getresponse()
        self.assertEqual(resp.status, 403)
        conn.close()

    def test_dns_rebinding_host_header_validation(self):
        # 1. Untrusted external Host header is rejected with 403 Forbidden
        status, headers, body = self._request_raw(
            "GET",
            "/api/status",
            headers={"Host": "evil.com:8765"}
        )
        self.assertEqual(status, 403)
        self.assertFalse(body.get("success", True))

        # 2. Subdomain spoofing Host header is rejected with 403 Forbidden
        status, headers, body = self._request_raw(
            "GET",
            "/api/status",
            headers={"Host": "localhost.evil.com"}
        )
        self.assertEqual(status, 403)

        # 3. IP spoofing Host header is rejected with 403 Forbidden
        status, headers, body = self._request_raw(
            "POST",
            "/api/panic-button",
            headers={"Host": "127.0.0.1.attacker.com"},
            payload={"locked": True}
        )
        self.assertEqual(status, 403)

        # 4. Host header with internal whitespace smuggling is rejected with 403 Forbidden
        status, headers, body = self._request_raw(
            "GET",
            "/api/status",
            headers={"Host": "localhost :8765"}
        )
        self.assertEqual(status, 403)

        # 5. Host header with out-of-range port is rejected with 403 Forbidden
        status, headers, body = self._request_raw(
            "GET",
            "/api/status",
            headers={"Host": "localhost:999999"}
        )
        self.assertEqual(status, 403)

        # 6. Trailing dot FQDN Host header (localhost.) is accepted
        status, headers, body = self._request_raw(
            "GET",
            "/api/status",
            headers={"Host": f"localhost.:{TEST_PORT}"}
        )
        self.assertEqual(status, 200)

    def test_cors_untrusted_origin_rejected_and_denied(self):
        # 1. State-modifying POST with untrusted origin is rejected with 403 Forbidden
        status, headers, body = self._request_raw(
            "POST",
            "/api/panic-button",
            headers={"Origin": "https://evil.com"},
            payload={"locked": True}
        )
        self.assertEqual(status, 403)
        self.assertNotIn("access-control-allow-origin", headers)
        self.assertFalse(body.get("success", True))

        # 2. Preflight OPTIONS with untrusted origin is rejected with 403 Forbidden
        status, headers, body = self._request_raw(
            "OPTIONS",
            "/api/panic-button",
            headers={"Origin": "https://evil.com"}
        )
        self.assertEqual(status, 403)
        self.assertNotIn("access-control-allow-origin", headers)

        # 3. DELETE with untrusted origin is rejected with 403 Forbidden
        status, headers, body = self._request_raw(
            "DELETE",
            "/api/panic-button",
            headers={"Origin": "https://evil.com"}
        )
        self.assertEqual(status, 403)
        self.assertNotIn("access-control-allow-origin", headers)

        # 4. GET with untrusted origin does NOT receive CORS allow headers (browser SOP protects client)
        status, headers, body = self._request_raw(
            "GET",
            "/api/status",
            headers={"Origin": "https://evil.com"}
        )
        self.assertEqual(status, 200)
        self.assertNotIn("access-control-allow-origin", headers)

        # 5. POST with userinfo spoofing in Origin is rejected with 403 Forbidden
        status, headers, body = self._request_raw(
            "POST",
            "/api/panic-button",
            headers={"Origin": f"http://attacker@127.0.0.1:{TEST_PORT}"},
            payload={"locked": True}
        )
        self.assertEqual(status, 403)
        self.assertNotIn("access-control-allow-origin", headers)

        # 6. POST with path in Origin is rejected with 403 Forbidden
        status, headers, body = self._request_raw(
            "POST",
            "/api/panic-button",
            headers={"Origin": f"http://127.0.0.1:{TEST_PORT}/api/secret"},
            payload={"locked": True}
        )
        self.assertEqual(status, 403)
        self.assertNotIn("access-control-allow-origin", headers)

    def test_loopback_helpers_unit(self):
        # Unit tests for is_trusted_host and is_trusted_origin helpers
        self.assertTrue(server.is_trusted_host("127.0.0.1:8765"))
        self.assertTrue(server.is_trusted_host("127.0.0.1"))
        self.assertTrue(server.is_trusted_host("localhost:8765"))
        self.assertTrue(server.is_trusted_host("localhost"))
        self.assertTrue(server.is_trusted_host("localhost.:8765"))
        self.assertTrue(server.is_trusted_host("localhost."))
        self.assertTrue(server.is_trusted_host("[::1]:8765"))
        self.assertTrue(server.is_trusted_host("[::1]"))
        self.assertTrue(server.is_trusted_host("::1"))
        self.assertTrue(server.is_trusted_host("[0:0:0:0:0:0:0:1]:8765"))
        self.assertFalse(server.is_trusted_host("evil.com:8765"))
        self.assertFalse(server.is_trusted_host("localhost.evil.com"))
        self.assertFalse(server.is_trusted_host("192.168.1.100:8765"))
        self.assertFalse(server.is_trusted_host("localhost :8765"))
        self.assertFalse(server.is_trusted_host("localhost\t:8765"))
        self.assertFalse(server.is_trusted_host("localhost:0"))
        self.assertFalse(server.is_trusted_host("localhost:65536"))
        self.assertFalse(server.is_trusted_host("localhost:999999"))
        self.assertFalse(server.is_trusted_host(""))

        self.assertTrue(server.is_trusted_origin("http://127.0.0.1:8765"))
        self.assertTrue(server.is_trusted_origin("http://localhost:8765"))
        self.assertTrue(server.is_trusted_origin("http://localhost.:8765"))
        self.assertTrue(server.is_trusted_origin("http://localhost:3000"))
        self.assertTrue(server.is_trusted_origin("http://[::1]:8765"))
        self.assertTrue(server.is_trusted_origin("https://localhost:8765"))
        self.assertFalse(server.is_trusted_origin("https://evil.com"))
        self.assertFalse(server.is_trusted_origin("http://evil.com:8765"))
        self.assertFalse(server.is_trusted_origin("http://localhost.evil.com"))
        self.assertFalse(server.is_trusted_origin("null"))
        self.assertFalse(server.is_trusted_origin(""))
        self.assertFalse(server.is_trusted_origin("javascript:alert(1)"))
        self.assertFalse(server.is_trusted_origin("http://attacker@127.0.0.1:8765"))
        self.assertFalse(server.is_trusted_origin("http://user:pass@localhost:8765"))
        self.assertFalse(server.is_trusted_origin("http://127.0.0.1:8765/api/status"))
        self.assertFalse(server.is_trusted_origin("http://127.0.0.1:8765?x=1"))
        self.assertFalse(server.is_trusted_origin("http://127.0.0.1:8765#hash"))
        self.assertFalse(server.is_trusted_origin("http://127.0.0.1:abc"))
        self.assertFalse(server.is_trusted_origin("http://127.0.0.1:0"))
        self.assertFalse(server.is_trusted_origin("http://127.0.0.1:65536"))
        self.assertFalse(server.is_trusted_origin("http://127.0.0.1:999999"))
        self.assertFalse(server.is_trusted_origin("http://127.0.0.1:8765, https://evil.com"))


if __name__ == "__main__":
    unittest.main()

