# -*- coding: utf-8 -*-
import sys, os, unittest, base64, tempfile, subprocess
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.secret_proxy import resolve_proxy_target, sanitize_response
from core import compliance_guard

FAKE = "a" * 32

class ProxyGuardTests(unittest.TestCase):
    def test_relative_allowed(self):
        url, err = resolve_proxy_target("github", "repos/o/r")
        self.assertIsNone(err); self.assertTrue(url.startswith("https://api.github.com/"))

    def test_absolute_same_host_allowed(self):
        url, err = resolve_proxy_target("github", "https://api.github.com/repos/o/r")
        self.assertIsNone(err)

    def test_loopback_blocked(self):
        _, err = resolve_proxy_target("github", "http://127.0.0.1:8765/api/status")
        self.assertIsNotNone(err)
        self.assertEqual(err[0], 400)

    def test_other_host_blocked(self):
        _, err = resolve_proxy_target("github", "https://evil.example.com/x")
        self.assertIsNotNone(err)

    def test_userinfo_url_blocked(self):
        _, err = resolve_proxy_target("github", f"https://api.github.com@{'x'*0}evil.example.com/x")
        self.assertIsNotNone(err)

    def test_unknown_service_blocked(self):
        _, err = resolve_proxy_target("custom", "https://evil.example.com/x")
        self.assertIsNotNone(err)

    def test_base64_echo_blocked(self):
        fake = "ghp_" + "b" * 36
        enc = base64.b64encode(fake.encode()).decode()
        out = str(sanitize_response({"echo": enc}, "t"))
        self.assertNotIn(fake, out); self.assertNotIn(enc, out)

class GitConfigScanTests(unittest.TestCase):
    def test_detects_userinfo(self):
        d = tempfile.mkdtemp()
        subprocess.run(["git", "init", "-q"], cwd=d)
        cfg = os.path.join(d, ".git", "config")
        with open(cfg, "a", encoding="utf-8") as f:
            f.write('[remote "origin"]\n\turl = https://oauth2:%s@gitee.com/o/r.git\n' % FAKE)
        findings = compliance_guard.scan_git_config_credentials(d)
        self.assertEqual(len(findings), 1)
        self.assertNotIn(FAKE, str(findings))

if __name__ == "__main__":
    unittest.main()
