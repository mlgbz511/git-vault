# -*- coding: utf-8 -*-
import sys, os, unittest
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.redaction import redact, redact_text, sanitize_remotes, REDACTED

FAKE_TOKEN = "a" * 32
FAKE_GH = "ghp_" + "b" * 36
FAKE_URL = f"https://oauth2:{FAKE_TOKEN}@gitee.com/o/r.git"

class RedactionTests(unittest.TestCase):
    def assert_clean(self, text):
        self.assertNotIn(FAKE_TOKEN, text)
        self.assertNotIn(FAKE_GH, text)
        self.assertRegex(text.replace("***@", "@"), r"@")

    def test_url_userinfo(self):
        out = redact_text(FAKE_URL)
        self.assertNotIn(FAKE_TOKEN, out)
        self.assertIn("***@", out)

    def test_sensitive_keys(self):
        out = redact({"token": FAKE_TOKEN, "password": "pw1234567", "ok": "visible"})
        self.assertEqual(out["token"], "<REDACTED>")
        self.assertEqual(out["password"], "<REDACTED>")
        self.assertEqual(out["ok"], "visible")

    def test_nested(self):
        out = redact({"a": [{"remotes": {"push_urls": [FAKE_URL]}}], "text": FAKE_GH})
        s = str(out)
        self.assertNotIn(FAKE_TOKEN, s)
        self.assertNotIn(FAKE_GH, s)

    def test_authorization_header(self):
        out = redact_text("Authorization: Bearer " + "c" * 40)
        self.assertNotIn("c" * 40, out)
        self.assertIn("REDACTED", out)

    def test_private_key_block(self):
        block = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEfake\n-----END " + "RSA PRIVATE KEY-----"
        self.assertNotIn("MIIEfake", redact_text(block))

    def test_sanitize_remotes(self):
        out = sanitize_remotes({"fetch_url": FAKE_URL, "push_urls": [FAKE_URL, "git@github.com:o/r.git"]})
        self.assertNotIn(FAKE_TOKEN, str(out))
        self.assertIn("git@github.com:o/r.git", out["push_urls"])


class SensitiveContainerTests(unittest.TestCase):
    """回归：敏感键名不得吃掉结构化容器（git-vault 控制台凭据表格崩溃根因）。

    旧实现把 credentials 这类「已脱敏的账号列表」整值替换成 "<REDACTED>" 字符串，
    前端 data.credentials || data.accounts 兜底因此失效并对字符串调用 forEach。
    """

    ACCOUNTS = [
        {"id": "a" * 24, "platform": "github", "username": "octo",
         "masked": "ghp_…(40)", "has_token": True, "is_default": True,
         "expires_at": "2027-01-01T00:00:00"},
        {"id": "b" * 24, "platform": "gitee", "username": "<owner>",
         "masked": "(未设置)", "has_token": False, "is_default": False},
    ]

    def test_sensitive_key_holding_list_survives(self):
        out = redact({"credentials": self.ACCOUNTS})
        self.assertIsInstance(out["credentials"], list)
        self.assertEqual(len(out["credentials"]), 2)
        self.assertEqual(out["credentials"][0]["platform"], "github")
        self.assertEqual(out["credentials"][0]["masked"], "ghp_…(40)")

    def test_sensitive_key_holding_dict_survives(self):
        out = redact({"credentials": {"github": {"masked": "ghp_…(40)", "has_token": True}}})
        self.assertIsInstance(out["credentials"], dict)
        self.assertEqual(out["credentials"]["github"]["masked"], "ghp_…(40)")

    def test_scalar_secret_under_sensitive_key_still_redacted(self):
        for key in ("credentials", "token", "password", "authorization", "secret"):
            out = redact({key: "x" * 40})
            self.assertEqual(out[key], REDACTED, key)

    def test_fail_closed_random_secret_inside_container(self):
        # 无固定前缀的高熵随机密钥混在容器里，仍必须被抹掉
        random_key = "Zk3" + "Q" * 18 + "7mP" + "x" * 17 + "9"
        out = redact({"credentials": [{"name": "svc", "value": random_key}]})
        self.assertNotIn(random_key, str(out))
        self.assertEqual(out["credentials"][0]["value"], REDACTED)

    def test_fail_closed_prefixed_secret_inside_container(self):
        out = redact({"credentials": [{"note": "token: " + FAKE_GH}]})
        self.assertNotIn(FAKE_GH, str(out))

    def test_url_userinfo_inside_container_still_masked(self):
        out = redact({"credentials": [{"remote": FAKE_URL}]})
        self.assertNotIn(FAKE_TOKEN, str(out))
        self.assertIn("***@", str(out))

    def test_bool_under_sensitive_key_preserved(self):
        self.assertEqual(redact({"credentials": True})["credentials"], True)

if __name__ == "__main__":
    unittest.main()
