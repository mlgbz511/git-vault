# tests/test_repo_archive.py
# Verification Test Suite for Git-Vault In-App Repository Archive Feature

import os
import sys
import unittest
import json
import copy

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core import git_engine

class TestRepoArchive(unittest.TestCase):

    def setUp(self):
        # Snapshot current managed_repos config
        self.orig_cfg = copy.deepcopy(git_engine.load_managed_repos_config())
        self.test_repo_path = os.path.normpath(os.path.abspath("<vault-root>\\_test_archive_sandbox_repo_"))

    def tearDown(self):
        # 100% Atomic restoration of user's original managed_repos config
        git_engine.save_managed_repos_config(self.orig_cfg)
        git_engine.invalidate_repos_cache()

    def test_archive_and_unarchive_flow(self):
        """Verify archive_repo sets archive metadata and unarchive_repo restores active state."""
        # 1. Archive test repository
        res_archive = git_engine.archive_repo(self.test_repo_path, reason="Completed milestone v1.0")
        self.assertTrue(res_archive.get("success"))
        self.assertTrue(res_archive.get("is_archived"))
        self.assertTrue(bool(res_archive.get("archived_at")))

        # Check persisted config
        cfg = git_engine.load_managed_repos_config()
        match = next((r for r in cfg.get("managed_repos", []) if os.path.normpath(r.get("path", "")).lower() == self.test_repo_path.lower()), None)
        self.assertIsNotNone(match, "Archived repository must exist in managed_repos")
        self.assertTrue(match.get("is_archived"))
        self.assertEqual(match.get("archive_reason"), "Completed milestone v1.0")
        self.assertTrue(bool(match.get("archived_at")))

        # 2. Unarchive repository
        res_unarchive = git_engine.unarchive_repo(self.test_repo_path)
        self.assertTrue(res_unarchive.get("success"))
        self.assertFalse(res_unarchive.get("is_archived"))

        # Check persisted config after unarchive
        cfg_after = git_engine.load_managed_repos_config()
        match_after = next((r for r in cfg_after.get("managed_repos", []) if os.path.normpath(r.get("path", "")).lower() == self.test_repo_path.lower()), None)
        self.assertIsNotNone(match_after)
        self.assertFalse(match_after.get("is_archived"))
        self.assertNotIn("archived_at", match_after)
        self.assertNotIn("archive_reason", match_after)

    def test_fast_loader_counts_and_attributes(self):
        """Verify get_managed_repositories_fast includes active_count, archived_count, and flags."""
        res = git_engine.get_managed_repositories_fast(force_refresh=True)
        stats = res.get("stats", {})
        self.assertIn("active_count", stats)
        self.assertIn("archived_count", stats)
        self.assertEqual(stats["active_count"] + stats["archived_count"], len(res.get("repos", [])))

        for repo in res.get("repos", []):
            self.assertIn("is_archived", repo)
            self.assertIsInstance(repo["is_archived"], bool)

if __name__ == "__main__":
    unittest.main()
