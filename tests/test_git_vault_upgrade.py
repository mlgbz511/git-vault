# tests/test_git_vault_upgrade.py
# Antigravity Git-Vault Upgrade Verification Test Suite
import os
import sys
import tempfile
import unittest
import json
import copy
import shutil
import subprocess

# Setup import path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core import (
    compliance_guard,
    credential_vault,
    secret_proxy,
    network_router,
    git_engine,
    mcp_server
)

class TestGitVaultUpgrade(unittest.TestCase):

    def setUp(self):
        # Ensure panic button is off before each test
        compliance_guard.set_panic_button(False)

    def tearDown(self):
        compliance_guard.set_panic_button(False)

    # --- 1. Compliance Guard Tests ---
    def test_secret_leak_scanner(self):
        # Test AWS Key
        aws_text = "const key = '" + "AK" + "IA1234567890ABCDEF';"
        res = compliance_guard.scan_text_for_secrets(aws_text, "test")
        self.assertTrue(any(v["rule_id"] == "aws_access_key" for v in res), "Should detect AWS key")

        # Test GitHub PAT
        gh_pat = "token: ghp_" + "123456789012345678901234567890123456"
        res = compliance_guard.scan_text_for_secrets(gh_pat, "test")
        self.assertTrue(any(v["rule_id"] == "github_pat_classic" for v in res), "Should detect GitHub PAT")

        # Test OpenAI Key
        openai_key = "export OPENAI_API_KEY=" + "sk-" + "proj-1234567890123456789012345678901234567890"
        res = compliance_guard.scan_text_for_secrets(openai_key, "test")
        self.assertTrue(any(v["rule_id"] == "openai_api_key" for v in res), "Should detect OpenAI key")

        # Test Private Key
        rsa_key = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA..."
        res = compliance_guard.scan_text_for_secrets(rsa_key, "test")
        self.assertTrue(any(v["rule_id"] == "private_key" for v in res), "Should detect Private key")

        # Test Safe String
        safe_text = "def hello(): print('Hello World!')"
        res = compliance_guard.scan_text_for_secrets(safe_text, "test")
        self.assertEqual(len(res), 0, "Safe code should have no violations")

    def test_diff_secret_scanner(self):
        diff_text = """diff --git a/config.py b/config.py
index 123..456 100644
--- a/config.py
+++ b/config.py
@@ -1,3 +1,4 @@
 import os
+SECRET_PAT = "ghp_""" + "abcdefghijklmnopqrstuvwxyz1234567890" + '''"
 def run(): pass
'''
        violations = compliance_guard.scan_diff_for_secrets(diff_text)
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0]["file"], "config.py")
        self.assertEqual(violations[0]["line_number"], 2)

    def test_file_size_limits(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a 51MB file
            dummy_51mb = os.path.join(tmpdir, "big_data.bin")
            with open(dummy_51mb, "wb") as f:
                f.seek(51 * 1024 * 1024 - 1)
                f.write(b"\0")

            violations = compliance_guard.check_file_sizes(tmpdir)
            # Must block for Gitee (>50MB) and warn for GitHub (>50MB)
            gitee_blocks = [v for v in violations if v.get("platform") == "gitee" and v.get("severity") == "BLOCK"]
            self.assertTrue(len(gitee_blocks) >= 1, "Must block Gitee for >50MB file")

    def test_contraband_tools_detection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a contraband file name
            v2_file = os.path.join(tmpdir, "v2ray.exe")
            with open(v2_file, "w") as f:
                f.write("binary content")

            violations = compliance_guard.scan_contraband_tools(tmpdir)
            self.assertTrue(any(v["type"] == "CONTRABAND_TOOL" for v in violations), "Must flag contraband filename")

    def test_panic_button_lock(self):
        # 1. Initially disabled
        compliance_guard.set_panic_button(False)
        can_write, _ = compliance_guard.check_write_permission()
        self.assertTrue(can_write)

        # 2. Enable panic button
        compliance_guard.set_panic_button(True)
        self.assertTrue(compliance_guard.is_panic_button_active())
        can_write, msg = compliance_guard.check_write_permission()
        self.assertFalse(can_write)
        self.assertIn("PANIC_BUTTON", msg)

        # 3. Disable again
        compliance_guard.set_panic_button(False)
        can_write, _ = compliance_guard.check_write_permission()
        self.assertTrue(can_write)

    def test_co_authored_by_formatting(self):
        # 1. Message without co-author
        msg = "feat: initial commit"
        formatted = compliance_guard.format_commit_message(msg, "GV_AGY_Gemini-2.5-Pro", "<bot-email>")
        self.assertIn("Co-authored-by: GV_AGY_Gemini-2.5-Pro <<bot-email>>", formatted)

        # 2. Message already with co-author
        already = "feat: update\n\nCo-authored-by: Another Agent <agent@test.com>"
        res = compliance_guard.format_commit_message(already)
        self.assertEqual(res, already, "Should not duplicate co-authored-by")

    # --- 2. Credential Vault Non-Git Tests ---
    def test_non_git_secret_dpapi(self):
        svc = "test_cf_service"
        test_val = "cf_secret_key_value_999888"
        
        # Save encrypted
        save_res = credential_vault.update_non_git_secret(svc, test_val, "cdn", "Test CDN Token")
        self.assertTrue(save_res["success"])

        # Decrypt in memory
        plain = credential_vault.get_non_git_secret_plain(svc)
        self.assertEqual(plain, test_val)

        # Masked view
        masked = credential_vault.get_non_git_secrets_masked()
        self.assertIn(svc, masked)
        self.assertTrue(masked[svc]["has_secret"])
        self.assertNotIn(test_val, masked[svc]["masked"], "Masked string must not contain plain secret")

        # Cleanup
        del_res = credential_vault.delete_non_git_secret(svc)
        self.assertTrue(del_res["success"])
        self.assertNotIn(svc, credential_vault.get_non_git_secrets_masked())

    # --- 3. Secret Proxy Tests ---
    def test_secret_proxy_sanitization(self):
        plain_secret = "my_super_secret_token_abcdef"
        data = {
            "message": f"Response containing {plain_secret} in body",
            "authorization": f"Bearer {plain_secret}",
            "nested": {
                "token": plain_secret,
                "safe_field": 12345
            }
        }
        sanitized = secret_proxy.sanitize_response(data, plain_secret)
        self.assertNotIn(plain_secret, json.dumps(sanitized))
        self.assertEqual(sanitized["authorization"], "<REDACTED>")
        self.assertEqual(sanitized["nested"]["token"], "<REDACTED>")
        self.assertEqual(sanitized["nested"]["safe_field"], 12345)

    def test_secret_proxy_unconfigured_service(self):
        # Calling an unconfigured service must safely fail with 401 without crashing
        res = secret_proxy.execute_proxy_request("unconfigured_svc_xyz", "endpoint/test")
        self.assertFalse(res["success"])
        self.assertEqual(res["status_code"], 401)

    # --- 4. Network Router Tests ---
    def test_network_router_gitee_lock(self):
        # Attempt to set Gitee to proxy mode must be blocked
        res = network_router.update_platform_route("gitee", "proxy")
        self.assertFalse(res["success"], "Gitee must reject proxy mode")
        self.assertIn("LOCKED", res["error"])

        # Gitee extra git args must always be direct
        gitee_args = network_router.get_git_extra_args("https://gitee.com/user/repo.git")
        self.assertEqual(gitee_args, ["-c", "http.proxy="])

    def test_network_router_github_args(self):
        # Set GitHub to proxy
        network_router.update_platform_route("github", "proxy", proxy_url="http://127.0.0.1:8888")
        gh_args = network_router.get_git_extra_args("https://github.com/org/repo.git")
        self.assertEqual(gh_args, ["-c", "http.proxy=http://127.0.0.1:8888"])

        # Reset to direct
        network_router.update_platform_route("github", "direct")
        gh_args_direct = network_router.get_git_extra_args("https://github.com/org/repo.git")
        self.assertEqual(gh_args_direct, ["-c", "http.proxy="])

    # --- 5. MCP Server Tests ---
    def test_mcp_initialize_and_tools_list(self):
        init_res = mcp_server.handle_json_rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        self.assertEqual(init_res["result"]["serverInfo"]["name"], "git-vault-mcp")

        tools_res = mcp_server.handle_json_rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        tools = tools_res["result"]["tools"]
        tool_names = [t["name"] for t in tools]
        expected_tools = [
            "vault_list_repos",
            "vault_get_diff",
            "vault_commit_push",
            "vault_create_repo",
            "vault_proxy_api",
            "vault_get_audit_log"
        ]
        for exp in expected_tools:
            self.assertIn(exp, tool_names, f"MCP must provide {exp}")

    def test_mcp_panic_button_blocks_commit_push(self):
        # Enable panic button
        compliance_guard.set_panic_button(True)
        repo = tempfile.mkdtemp(prefix="git_vault_panic_")
        self.addCleanup(shutil.rmtree, repo, True)
        subprocess.run(["git", "init", "-q", repo], check=True, capture_output=True)

        call_req = {
            "jsonrpc": "2.0",
            "id": 10,
            "method": "tools/call",
            "params": {
                "name": "vault_commit_push",
                "arguments": {
                    "repo_path": repo,
                    "message": "test commit"
                }
            }
        }
        call_res = mcp_server.handle_json_rpc(call_req)
        self.assertTrue(call_res["result"]["isError"], "Must report error when panic button is active")
        content_text = call_res["result"]["content"][0]["text"]
        self.assertIn("PANIC_BUTTON", content_text)

        # Audit log must record BLOCKED
        audit_logs = mcp_server.get_audit_logs(limit=5)
        self.assertTrue(any(l["status"] == "BLOCKED" for l in audit_logs), "Must record BLOCKED in audit log")

    def test_git_engine_diff_and_commits(self):
        repo = tempfile.mkdtemp(prefix="git_vault_engine_")
        self.addCleanup(shutil.rmtree, repo, True)
        env = dict(os.environ, GIT_AUTHOR_NAME="git-vault test", GIT_AUTHOR_EMAIL="test@example.invalid",
                   GIT_COMMITTER_NAME="git-vault test", GIT_COMMITTER_EMAIL="test@example.invalid")
        subprocess.run(["git", "init", "-q", repo], check=True, capture_output=True)
        with open(os.path.join(repo, "a.txt"), "w", encoding="utf-8") as f:
            f.write("one\n")
        subprocess.run(["git", "-C", repo, "add", "a.txt"], check=True, capture_output=True, env=env)
        subprocess.run(["git", "-C", repo, "commit", "-q", "-m", "init"], check=True, capture_output=True, env=env)
        with open(os.path.join(repo, "a.txt"), "a", encoding="utf-8") as f:
            f.write("two\n")
        diff_res = git_engine.get_repo_diff(repo)
        self.assertTrue(diff_res["success"])
        self.assertIn("files", diff_res)

        commits_res = git_engine.get_repo_commits(repo, count=5)
        self.assertTrue(commits_res["success"])
        self.assertTrue(len(commits_res["commits"]) > 0)

    # --- 6. Edge Case & Deep Verification Tests ---
    def test_compliance_guard_self_scan_not_blocked(self):
        """Verify compliance_guard does not false-positive on Git-Vault itself."""
        vault_repo = BASE_DIR
        if not os.path.exists(os.path.join(BASE_DIR, ".git")):
            self.skipTest("self-scan needs a git checkout")
        contraband = compliance_guard.scan_contraband_tools(vault_repo)
        self.assertEqual(len(contraband), 0, f"Git-Vault should not flag itself: {contraband}")

        audit = compliance_guard.audit_pre_commit(vault_repo)
        self.assertFalse(audit.get("blocked", False), f"Audit pre-commit must not block Git-Vault itself: {audit}")

    def test_mcp_handle_json_rpc_with_null_arguments(self):
        """Verify MCP server gracefully handles 'arguments': None without crashing."""
        call_req = {
            "jsonrpc": "2.0",
            "id": 101,
            "method": "tools/call",
            "params": {
                "name": "vault_list_repos",
                "arguments": None
            }
        }
        res = mcp_server.handle_json_rpc(call_req)
        self.assertEqual(res["jsonrpc"], "2.0")
        self.assertEqual(res["id"], 101)
        self.assertFalse(res["result"]["isError"])

    def test_network_router_github_hosts_mode(self):
        """Verify network_router correctly injects curloptResolve when mode is 'hosts'."""
        orig_routes = network_router.load_network_routes()
        try:
            network_router.update_platform_route("github", "hosts", hosts_ip="20.205.243.166")
            args = network_router.get_git_extra_args("https://github.com/octocat/Hello-World.git")
            self.assertIn("-c", args)
            self.assertTrue(any("http.curloptResolve=github.com:443:20.205.243.166" in a for a in args))
            self.assertTrue(any("http.proxy=" in a for a in args))
        finally:
            # 100% Guaranteed atomic restoration of user's original network routes!
            network_router.save_network_routes(orig_routes)

    def test_credential_vault_no_plaintext_leak_and_empty_token_preservation(self):
        """Verify /api/vault tokens do not contain plaintext and empty save preserves token."""
        orig_vault = copy.deepcopy(credential_vault.load_raw_vault())
        try:
            test_plat = "github"
            test_tok = "ghp_" + "testsecrettoken1234567890abcdef"

            # 1. Update token
            credential_vault.update_token(test_plat, test_tok, "testuser", "never")

            # 2. Inspect masked view: must NOT have plaintext value
            masked_data = credential_vault.get_tokens_masked()
            gl_info = masked_data["tokens"][test_plat]
            self.assertTrue(gl_info["has_token"])
            self.assertNotIn("value", gl_info, "Masked tokens must NEVER contain plaintext 'value' field!")
            self.assertNotIn(test_tok, gl_info["masked"])

            # 3. User updates username or expiry with empty token: existing token must NOT be cleared!
            credential_vault.update_token(test_plat, "", "testuser_updated", "30d")
            raw_after = credential_vault.load_raw_vault()
            self.assertIn(test_plat, raw_after.get("encrypted_tokens", {}), "Empty token must NOT clear existing encrypted token!")
            plain_after = credential_vault.dpapi_decrypt(raw_after["encrypted_tokens"][test_plat])
            self.assertEqual(plain_after, test_tok, "Token value must be preserved!")

            # 4. Explicit clear_token must delete it
            credential_vault.update_token(test_plat, "", clear_token=True)
            raw_cleared = credential_vault.load_raw_vault()
            self.assertNotIn(test_plat, raw_cleared.get("encrypted_tokens", {}), "Explicit clear_token must delete token!")
        finally:
            # 100% Guaranteed atomic restoration of user's original vault configuration!
            credential_vault.save_raw_vault(orig_vault)

    def test_secret_proxy_endpoint_prefix_handling(self):
        """Verify execute_proxy_request handles redundant prefixes cleanly."""
        # Cloudflare with leading /client/v4/
        res1 = secret_proxy.execute_proxy_request("cloudflare", "/client/v4/zones")
        # Should fail with 401 (if no token) or network response, but NOT 400 invalid URL
        self.assertNotEqual(res1.get("status_code"), 400)

if __name__ == "__main__":
    unittest.main()
