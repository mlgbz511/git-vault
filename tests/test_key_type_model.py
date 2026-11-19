# tests/test_key_type_model.py
# T6 验收：凭据模型扩维（T2 core/credential_vault.py）
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core import credential_vault as cv

ROTATION_KEYS = {"rotate_after_days", "rotated_at", "last_verified_at"}
SCOPE_KEYS = {"owner", "repos", "permissions", "environment"}
FAKE_GH = "ghp_" + "a" * 36
FAKE_SSH = "ssh-fake-key-material-0123456789"


class VaultTestBase(unittest.TestCase):
    """所有用例在临时目录里跑，绝不碰真实 config/vault.json。"""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.vault_path = os.path.join(self._tmp.name, "vault.json")
        patcher = mock.patch.object(cv, "VAULT_CONFIG_FILE", self.vault_path)
        patcher.start()
        self.addCleanup(patcher.stop)
        self._write_raw({"accounts": [], "repo_account_bindings": {}, "non_git_secrets": {}, "encryption": "Windows-DPAPI"})

    def _write_raw(self, data):
        with open(self.vault_path, "w", encoding="utf-8") as fp:
            json.dump(data, fp, ensure_ascii=False)

    def _raw(self):
        with open(self.vault_path, "r", encoding="utf-8") as fp:
            return json.load(fp)


class TestMigration(VaultTestBase):
    def test_legacy_upgrade_adds_key_type_scope_rotation(self):
        cipher = cv.dpapi_encrypt("gitee_legacy_token_9999")
        self._write_raw({
            "saved_accounts": {"gitee_user": "old_user"},
            "encrypted_tokens": {"gitee": cipher},
            "token_metadata": {"gitee": {"username": "old_user", "expires_at": "never"}},
            "accounts": [],
        })
        raw = cv.load_raw_vault()
        self.assertEqual(len(raw["accounts"]), 1)
        acc = raw["accounts"][0]
        self.assertEqual(acc["key_type"], "pat_classic")
        self.assertEqual(set(acc["scope"]), SCOPE_KEYS)
        self.assertEqual(set(acc["rotation"]), ROTATION_KEYS)
        self.assertNotIn("last_rotated", acc)

    def test_migration_is_idempotent(self):
        cipher = cv.dpapi_encrypt("fake-gitee-token-0001")
        self._write_raw({"encrypted_tokens": {"gitee": cipher}, "accounts": []})
        first = cv.load_raw_vault()["accounts"]
        second = cv.load_raw_vault()["accounts"]
        self.assertEqual(json.dumps(first, sort_keys=True), json.dumps(second, sort_keys=True))


class TestAccountModel(VaultTestBase):
    def test_add_account_persists_new_fields(self):
        res = cv.add_or_update_account(
            platform="github",
            token=FAKE_GH,
            username="fake_user",
            alias="假账号",
            expires_at="2030-01-01",
            account_id="acc_fake_1",
            key_type="ssh_user_key",
            scope={"owner": "me", "repos": ["demo"], "permissions": {"git": "write"}, "environment": "dev"},
        )
        self.assertTrue(res["success"])
        self.assertEqual(res["key_type"], "ssh_user_key")
        acc = self._raw()["accounts"][0]
        self.assertEqual(acc["key_type"], "ssh_user_key")
        self.assertEqual(acc["scope"]["repos"], ["demo"])
        self.assertEqual(set(acc["rotation"]), ROTATION_KEYS)

    def test_illegal_or_platform_domain_type_rejected(self):
        bad = cv.add_or_update_account(platform="github", token=FAKE_GH, key_type="no_such_type")
        self.assertFalse(bad["success"])
        platform_only = cv.add_or_update_account(platform="github", token=FAKE_GH, key_type="ci_secret")
        self.assertFalse(platform_only["success"])

    def test_get_plain_token_by_key_type_and_default_fallback(self):
        cv.add_or_update_account(platform="github", token=FAKE_GH, account_id="acc_pat", key_type="pat_classic")
        cv.add_or_update_account(platform="github", token=FAKE_SSH, account_id="acc_ssh", key_type="ssh_user_key")
        self.assertEqual(cv.get_plain_token("github", key_type="ssh_user_key"), FAKE_SSH)
        self.assertEqual(cv.get_plain_token("github"), FAKE_GH)

    def test_tokens_masked_iterates_accounts_not_hardcoded_platforms(self):
        cv.add_or_update_account(platform="bitbucket", token=FAKE_GH, account_id="acc_bb", key_type="pat_classic")
        out = cv.get_tokens_masked()
        self.assertIn("bitbucket", out["tokens"])
        entry = out["tokens"]["bitbucket"]
        self.assertEqual(entry["key_type"], "pat_classic")
        self.assertEqual(set(entry["rotation"]), ROTATION_KEYS)
        self.assertTrue(entry["has_token"])
        self.assertTrue(entry["masked"].startswith("ghp_"))
        self.assertIn("…", entry["masked"])

    def test_mask_never_leaks_token_or_tail(self):
        cv.add_or_update_account(platform="github", token=FAKE_GH, account_id="acc_mask", key_type="pat_classic")
        acc = cv.list_accounts_masked(platform="github")[0]
        for field in ("key_type", "scope", "masked", "expiry_info", "rotation"):
            self.assertIn(field, acc)
        self.assertTrue(acc["masked"].startswith("ghp_"))
        self.assertNotIn(FAKE_GH, acc["masked"])
        self.assertNotIn(FAKE_GH[-4:], acc["masked"])
        self.assertNotIn("****", acc["masked"])

    def test_update_token_keeps_existing_key_type(self):
        cv.add_or_update_account(platform="github", token=FAKE_SSH, account_id="acc_upd", key_type="ssh_user_key")
        res = cv.update_token("github", "rotated-fake-token-abcdef123456")
        self.assertTrue(res["success"])
        acc = self._raw()["accounts"][0]
        self.assertEqual(acc["key_type"], "ssh_user_key")
        self.assertTrue(acc["rotation"]["rotated_at"])


class TestSecretModel(VaultTestBase):
    def test_non_git_secret_has_same_shape(self):
        res = cv.update_non_git_secret("demo_service", "fake-secret-value-123456", key_type="generic_secret", expires_at="2030-01-01")
        self.assertTrue(res["success"])
        entry = self._raw()["non_git_secrets"]["demo_service"]
        self.assertEqual(entry["key_type"], "generic_secret")
        self.assertEqual(entry["expires_at"], "2030-01-01")
        self.assertEqual(set(entry["rotation"]), ROTATION_KEYS)
        masked = cv.get_non_git_secrets_masked()["demo_service"]
        self.assertNotIn("fake-secret-value-123456", json.dumps(masked, ensure_ascii=False))

    def test_list_all_secrets_plain_is_internal(self):
        cv.add_or_update_account(platform="github", token=FAKE_GH, account_id="acc_plain", key_type="pat_classic")
        cv.update_non_git_secret("demo_service", "fake-secret-value-123456")
        plain = cv.list_all_secrets_plain()
        self.assertEqual(plain["accounts"][0]["plain_token"], FAKE_GH)
        self.assertEqual(plain["non_git"]["demo_service"]["plain"], "fake-secret-value-123456")
        masked_view = cv.get_tokens_masked()
        self.assertNotIn(FAKE_GH, json.dumps(masked_view, ensure_ascii=False, default=str))


if __name__ == "__main__":
    unittest.main()
