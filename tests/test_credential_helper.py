# -*- coding: utf-8 -*-
import os, sys, unittest
from unittest.mock import patch

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core import git_engine

FAKE = "ghp_" + "FAKE_TOKEN_FOR_ARGV_TEST_1234567890"

class PushArgvTests(unittest.TestCase):
    def test_token_never_in_argv(self):
        captured = {}
        def fake_run_git(args, cwd=None, timeout=20):
            captured["args"] = list(args)
            return {"success": True, "returncode": 0, "stdout": "", "stderr": ""}
        with patch.object(git_engine, "run_git", side_effect=fake_run_git), \
             patch.object(git_engine.network_router, "get_git_extra_args", return_value=[]), \
             patch("core.credential_vault.get_plain_token", return_value=FAKE):
            git_engine._execute_single_push(r"<path>\nonexistent", "main", "git@github.com:o/r.git", "r")
        cmd = " ".join(captured["args"])
        self.assertNotIn(FAKE, cmd)
        self.assertIn("https://github.com/o/r.git", cmd)
        self.assertIn("credential.helper=!python", cmd)

if __name__ == "__main__":
    unittest.main()
