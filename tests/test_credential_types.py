# tests/test_credential_types.py
# T6 验收：密钥类型单一事实源（T1 core/credential_types.py）
import os
import re
import sys
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core import credential_types as ct

REQUIRED_IDS = {
    "pat_classic", "pat_fine", "ssh_user_key", "deploy_key", "app_private_key",
    "app_installation_token", "oauth_user_token", "gh_cli_token", "ci_secret",
    "generic_secret",
}
FIELDS = (
    "id", "label_zh", "label_en", "prefix_regex", "can_push", "storage_domain",
    "default_scope", "docs_url", "rotation_hint", "expires_hint",
)
SCOPE_KEYS = {"owner", "repos", "permissions", "environment"}


class TestCredentialTypes(unittest.TestCase):
    def test_required_types_present(self):
        missing = REQUIRED_IDS - set(ct.KEY_TYPES)
        self.assertFalse(missing, "KEY_TYPES 缺少类型: %s" % sorted(missing))
        self.assertGreaterEqual(len(ct.KEY_TYPES), 10)

    def test_field_completeness_and_id_consistency(self):
        for key, entry in ct.KEY_TYPES.items():
            with self.subTest(key=key):
                self.assertEqual(entry["id"], key)
                for field in FIELDS:
                    self.assertIn(field, entry)
                self.assertIn(entry["storage_domain"], ("client", "platform"))
                self.assertEqual(set(entry["default_scope"]), SCOPE_KEYS)
                self.assertIsInstance(entry["can_push"], bool)

    def test_prefix_regex_compilable(self):
        for key, entry in ct.KEY_TYPES.items():
            if entry["prefix_regex"]:
                with self.subTest(key=key):
                    re.compile(entry["prefix_regex"])

    def test_parse_is_strict_and_normalize_falls_back(self):
        self.assertEqual(ct.parse_key_type("ghs"), "app_installation_token")
        self.assertEqual(ct.parse_key_type(" GHS "), "app_installation_token")
        self.assertEqual(ct.parse_key_type("glpat"), "pat_gitlab")
        self.assertIsNone(ct.parse_key_type("no_such_type"))
        self.assertIsNone(ct.parse_key_type(None))
        self.assertEqual(ct.normalize_key_type("no_such_type"), "generic_secret")

    def test_push_capability_and_storage_domain(self):
        self.assertTrue(ct.is_push_capable("pat_classic"))
        self.assertFalse(ct.is_push_capable("ci_secret"))
        self.assertFalse(ct.is_push_capable("no_such_type"))
        self.assertTrue(ct.platform_storable("pat_classic"))
        self.assertFalse(ct.platform_storable("ci_secret"))
        self.assertFalse(ct.platform_storable("no_such_type"))

    def test_default_scope_is_deep_copy(self):
        first = ct.default_scope("pat_fine")
        second = ct.default_scope("pat_fine")
        first["repos"].append("polluted")
        first["permissions"]["contents"] = "read"
        self.assertEqual(second["repos"], [])
        self.assertEqual(second["permissions"], ct.KEY_TYPES["pat_fine"]["default_scope"]["permissions"])

    def test_prefix_patterns_and_registered_platforms(self):
        patterns = ct.prefix_patterns()
        expected = {k for k, v in ct.KEY_TYPES.items() if v["prefix_regex"]}
        self.assertEqual(set(patterns), expected)
        self.assertNotIn("ssh_user_key", patterns)
        self.assertEqual(set(ct.registered_platforms()), {"github", "gitee", "gitlab"})


if __name__ == "__main__":
    unittest.main()
