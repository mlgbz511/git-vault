# tests/test_secret_prefixes.py
# T6 验收：漏检 token 前缀（T1 credential_types + T3 compliance_guard / git_credential_helper）
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core import compliance_guard, credential_types, credential_vault
from core import git_credential_helper as helper

FAKE_TOKENS = {
    "github_app_user_token": "ghu_" + "x" * 36,
    "github_app_installation_token": "ghs_" + "x" * 36,
    "github_oauth_refresh_token": "ghr_" + "x" * 36,
    "gitlab_pat": "glpat-" + "y" * 20,
}
RULE_TO_TYPE = {
    "github_app_user_token": "app_user_token",
    "github_app_installation_token": "app_installation_token",
    "github_oauth_refresh_token": "oauth_refresh_token",
    "gitlab_pat": "pat_gitlab",
}
FAKE_PAT = "ghp_" + "z" * 36


class TestSecretPrefixes(unittest.TestCase):
    def test_all_four_prefixes_blocked(self):
        for rule_id, token in FAKE_TOKENS.items():
            with self.subTest(rule_id=rule_id):
                hits = [v for v in compliance_guard.scan_text_for_secrets("token = " + token, "unit") if v["rule_id"] == rule_id]
                self.assertTrue(hits, "未命中: " + rule_id)
                self.assertEqual(hits[0]["severity"], "BLOCK")

    def test_glued_or_truncated_does_not_hit(self):
        for rule_id, token in FAKE_TOKENS.items():
            with self.subTest(rule_id=rule_id):
                glued = "prefix" + token
                hits = [v for v in compliance_guard.scan_text_for_secrets(glued, "unit") if v["rule_id"] == rule_id]
                self.assertFalse(hits, "粘连串不应命中: " + rule_id)
                shortened = token[:-1]
                hits2 = [v for v in compliance_guard.scan_text_for_secrets(shortened, "unit") if v["rule_id"] == rule_id]
                self.assertFalse(hits2, "截短串不应命中: " + rule_id)

    def test_rules_come_from_single_source(self):
        patterns = {r["id"]: r["pattern"] for r in compliance_guard.SECRET_PATTERNS}
        compiled = credential_types.prefix_patterns()
        for rule_id, type_id in RULE_TO_TYPE.items():
            with self.subTest(rule_id=rule_id):
                self.assertEqual(patterns[rule_id], credential_types.KEY_TYPES[type_id]["prefix_regex"])
                self.assertIsNotNone(compiled[type_id].search(FAKE_TOKENS[rule_id]))

    def test_existing_prefixes_still_blocked(self):
        hits = [v for v in compliance_guard.scan_text_for_secrets("k=" + FAKE_PAT, "unit") if v["rule_id"] == "github_pat_classic"]
        self.assertTrue(hits)


class TestHelperChannels(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.vault_path = os.path.join(self._tmp.name, "vault.json")
        patcher = mock.patch.object(credential_vault, "VAULT_CONFIG_FILE", self.vault_path)
        patcher.start()
        self.addCleanup(patcher.stop)
        with open(self.vault_path, "w", encoding="utf-8") as fp:
            json.dump({"accounts": []}, fp)

    def _run(self, payload):
        out = io.StringIO()
        with mock.patch.object(sys, "argv", ["helper", "get"]), \
             mock.patch.object(sys, "stdin", io.StringIO(payload)), \
             mock.patch.object(sys, "stdout", out):
            rc = helper.main()
        return rc, out.getvalue()

    def test_https_channel_returns_token_via_stdout(self):
        credential_vault.add_or_update_account(platform="github", token=FAKE_PAT, account_id="acc_h1", key_type="pat_classic")
        rc, out = self._run("host=github.com" + chr(10) + chr(10))
        self.assertEqual(rc, 0)
        self.assertIn("password=" + FAKE_PAT, out)

    def test_ssh_channel_never_emits_pat(self):
        credential_vault.add_or_update_account(platform="github", token=FAKE_PAT, account_id="acc_h2", key_type="pat_classic")
        rc, out = self._run("protocol=ssh" + chr(10) + "host=github.com" + chr(10) + chr(10))
        self.assertEqual(rc, 0)
        self.assertEqual(out.strip(), "")


if __name__ == "__main__":
    unittest.main()
