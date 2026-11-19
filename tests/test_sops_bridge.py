# tests/test_sops_bridge.py
# T6 验收：SOPS + age 跨机密文层（T4 core/sops_bridge.py）
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core import credential_vault

try:
    from core import sops_bridge
except ImportError:  # T4 未落地时显式 SKIP，不静默通过
    sops_bridge = None

FAKE_TOKEN = "ghs_" + "q" * 36
AGE_KEY = "AGE-SECRET-KEY-FAKE-0123456789"


class SopsTestBase(unittest.TestCase):
    def setUp(self):
        if sops_bridge is None:
            self.skipTest("core/sops_bridge.py 未落地（T4 依赖）")
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.vault_path = os.path.join(self._tmp.name, "vault.json")
        patcher = mock.patch.object(credential_vault, "VAULT_CONFIG_FILE", self.vault_path)
        patcher.start()
        self.addCleanup(patcher.stop)
        with open(self.vault_path, "w", encoding="utf-8") as fp:
            json.dump({"accounts": []}, fp)
        credential_vault.add_or_update_account(platform="github", token=FAKE_TOKEN, account_id="acc_sops", key_type="pat_classic")
        self.target = os.path.join(self._tmp.name, "secrets.enc.yaml")

    def _patch_which(self, value="sops"):
        try:
            patcher = mock.patch.object(sops_bridge.shutil, "which", return_value=value)
        except AttributeError:
            patcher = mock.patch("shutil.which", return_value=value)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _patch_age_key(self):
        """真实行为要求存在 age 私钥，否则 T4 直接返回 AGE_KEY_MISSING；测试给假私钥。"""
        if hasattr(sops_bridge, "_load_age_key"):
            patcher = mock.patch.object(sops_bridge, "_load_age_key", return_value=AGE_KEY)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _patch_run(self, returncode, stdout=b"", stderr=b""):
        captured = {}

        def fake_run(cmd, *args, **kwargs):
            captured["cmd"] = list(cmd)
            captured["kwargs"] = kwargs
            return subprocess.CompletedProcess(cmd, returncode, stdout, stderr)

        if not hasattr(sops_bridge, "subprocess"):
            self.skipTest("sops_bridge 未通过 subprocess 调用外部二进制")
        proxy = mock.MagicMock()
        proxy.run = fake_run
        patcher = mock.patch.object(sops_bridge, "subprocess", proxy)
        patcher.start()
        self.addCleanup(patcher.stop)
        return captured


class TestSopsMissing(SopsTestBase):
    def test_missing_sops_reports_code_and_writes_nothing(self):
        if shutil.which("sops"):
            self.skipTest("本机装有 sops，缺失分支不可复现")
        res = sops_bridge.export_to_file(self.target)
        self.assertFalse(res["success"])
        self.assertIn("SOPS_NOT_INSTALLED", res.get("error") or "")
        self.assertFalse(os.path.exists(self.target))

    def test_sops_available_never_raises(self):
        # 契约：返回 dict（含 available/error/install_hint），不是 bool
        info = sops_bridge.sops_available()
        self.assertIsInstance(info, dict)
        self.assertIn("available", info)
        self.assertIsInstance(info["available"], bool)
        fake_dir = self._tmp.name
        with open(os.path.join(fake_dir, "sops.exe"), "wb") as fp:
            fp.write(b"")
        with mock.patch.dict(os.environ, {"PATH": fake_dir + os.pathsep + os.environ.get("PATH", "")}):
            info2 = sops_bridge.sops_available()
            self.assertIsInstance(info2, dict)
            self.assertIsInstance(info2["available"], bool)


class TestSopsInvocation(SopsTestBase):
    def setUp(self):
        super().setUp()
        self._patch_age_key()

    def test_argv_has_no_private_key_and_stderr_redacted(self):
        self._patch_which()
        captured = self._patch_run(1, b"", ("bad key " + FAKE_TOKEN).encode())
        with mock.patch.object(sops_bridge, "sops_available", return_value={"available": True, "sops": "sops", "age": "", "sops_version": "fake", "error": "", "install_hint": ""}):
            os.environ["SOPS_AGE_KEY"] = AGE_KEY
            try:
                res = sops_bridge.export_to_file(self.target)
            finally:
                os.environ.pop("SOPS_AGE_KEY", None)
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("error"), "SOPS_FAILED")
        joined = " ".join(str(x) for x in (captured.get("cmd") or []))
        self.assertNotIn(AGE_KEY, joined)
        self.assertNotIn(FAKE_TOKEN, json.dumps(res, ensure_ascii=False, default=str))

    def test_import_dry_run_does_not_leak_plaintext(self):
        self._patch_which()
        with open(self.target, "w", encoding="utf-8") as fp:
            fp.write("ENC" + chr(10))
        # T4 真实契约：sops --output-type json 解出 dict；accounts 是 {id: {platform,key_type,secret}}
        body = json.dumps({
            "schema_version": 1,
            "accounts": {"acc_sops": {"platform": "github", "key_type": "pat_classic", "secret": FAKE_TOKEN}},
            "non_git": {},
        })
        self._patch_run(0, body.encode(), b"")
        with mock.patch.object(sops_bridge, "sops_available", return_value={"available": True, "sops": "sops", "age": "", "sops_version": "fake", "error": "", "install_hint": ""}):
            res = sops_bridge.import_from_file(self.target, dry_run=True)
        self.assertTrue(res.get("success"), res.get("error"))
        self.assertIn("added", res)
        self.assertNotIn(FAKE_TOKEN, json.dumps(res, ensure_ascii=False, default=str))

    def test_diff_reports_no_values(self):
        self._patch_which()
        with open(self.target, "w", encoding="utf-8") as fp:
            fp.write("ENC" + chr(10))
        body = json.dumps({
            "schema_version": 1,
            "accounts": {"acc_sops": {"platform": "github", "key_type": "pat_classic", "secret": FAKE_TOKEN}},
            "non_git": {},
        })
        self._patch_run(0, body.encode(), b"")
        with mock.patch.object(sops_bridge, "sops_available", return_value={"available": True, "sops": "sops", "age": "", "sops_version": "fake", "error": "", "install_hint": ""}):
            res = sops_bridge.diff_with_vault(self.target)
        self.assertIn("has_changes", res)
        self.assertNotIn(FAKE_TOKEN, json.dumps(res, ensure_ascii=False, default=str))

    def test_roundtrip_skips_without_real_sops(self):
        if not (sops_bridge.sops_available() or {}).get("available"):
            print("SKIP test_roundtrip: 本机无 sops/age")
            self.skipTest("本机无 sops/age")
        res = sops_bridge.export_to_file(self.target)
        self.assertTrue(res["success"], res.get("error"))
        with open(self.target, "r", encoding="utf-8") as fp:
            ciphertext = fp.read()
        self.assertNotIn(FAKE_TOKEN, ciphertext)
        imported = sops_bridge.import_from_file(self.target)
        self.assertTrue(imported["success"], imported.get("error"))


if __name__ == "__main__":
    unittest.main()
