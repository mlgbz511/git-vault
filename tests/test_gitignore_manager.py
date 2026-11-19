# tests/test_gitignore_manager.py
# Antigravity Git-Vault - Global .gitignore Architecture Verification
import os
import sys
import unittest
import subprocess

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core import gitignore_manager, compliance_guard

class TestGitignoreManager(unittest.TestCase):
    def setUp(self):
        # 记录测试前的全局 excludesfile
        self.orig_excludes = gitignore_manager.get_current_global_excludesfile()
        self.test_custom_file = os.path.join(BASE_DIR, "config", "test_gitignore_temp")

    def tearDown(self):
        # 恢复初始配置
        if self.orig_excludes:
            subprocess.run(["git", "config", "--global", "core.excludesfile", self.orig_excludes], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            gitignore_manager.clear_global_gitignore()

        if os.path.exists(self.test_custom_file):
            try:
                os.remove(self.test_custom_file)
            except Exception:
                pass

    def test_presets_structure(self):
        presets = gitignore_manager.get_presets_meta()
        self.assertGreaterEqual(len(presets), 3)
        ids = [p["id"] for p in presets]
        self.assertIn("strict", ids)
        self.assertIn("general", ids)
        self.assertIn("minimal", ids)
        for p in presets:
            self.assertTrue(p.get("immutable", False), f"Official preset {p['id']} must be immutable")

    def test_custom_template_lifecycle(self):
        # 1. 尝试覆盖官方预设应当被拒绝
        err_res = gitignore_manager.save_custom_template("strict", "篡改", "*.exe")
        self.assertFalse(err_res["success"])
        self.assertIn("官方只读预设", err_res["error"])

        # 2. 保存合法自定义模板
        save_res = gitignore_manager.save_custom_template("my_vue_rule", "Vue 项目模板", "dist/\n*.log\n")
        self.assertTrue(save_res["success"])

        # 3. 读取并验证
        templates = gitignore_manager.load_custom_templates()
        self.assertIn("my_vue_rule", templates)
        self.assertEqual(templates["my_vue_rule"]["name"], "Vue 项目模板")
        self.assertFalse(templates["my_vue_rule"]["immutable"])

        # 4. 应用自定义模板到全局
        apply_res = gitignore_manager.apply_global_gitignore(preset_id="my_vue_rule", target_path=self.test_custom_file)
        self.assertTrue(apply_res["success"])
        with open(self.test_custom_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("dist/", content)

        # 5. 删除测试自定义模板
        del_res = gitignore_manager.delete_custom_template("my_vue_rule")
        self.assertTrue(del_res["success"])
        self.assertNotIn("my_vue_rule", gitignore_manager.load_custom_templates())

        # 6. 删除官方预设应当被拒绝
        del_strict = gitignore_manager.delete_custom_template("strict")
        self.assertFalse(del_strict["success"])

    def test_apply_strict_preset(self):
        res = gitignore_manager.apply_global_gitignore(preset_id="strict", target_path=self.test_custom_file)
        self.assertTrue(res["success"])
        self.assertTrue(os.path.exists(self.test_custom_file))
        
        with open(self.test_custom_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("*.exe", content)
        self.assertIn("*.zip", content)
        self.assertIn("*.dll", content)
        self.assertIn("node_modules/", content)

        # 验证 git config
        current = gitignore_manager.get_current_global_excludesfile()
        self.assertEqual(current.replace("\\", "/"), self.test_custom_file.replace("\\", "/"))

    def test_apply_custom_content(self):
        custom_rule = "*.mytestcustom\n/mybuild/"
        res = gitignore_manager.apply_global_gitignore(preset_id="custom", custom_content=custom_rule, target_path=self.test_custom_file)
        self.assertTrue(res["success"])
        with open(self.test_custom_file, "r", encoding="utf-8") as f:
            content = f.read()
        self.assertIn("*.mytestcustom", content)

    def test_status_query(self):
        status = gitignore_manager.get_global_gitignore_status()
        self.assertIn("is_configured", status)
        self.assertIn("presets", status)
        self.assertIn("current_preset", status)

    def test_binary_pollution_guard(self):
        fake_diff = "diff --git a/app.exe b/app.exe\nnew file mode 100644\n--- /dev/null\n+++ b/app.exe\n@@ -0,0 +1 @@\n+binarycontent"
        violations = compliance_guard.scan_diff_for_secrets(fake_diff)
        types = [v.get("type") for v in violations]
        self.assertIn("BINARY_POLLUTION", types)

if __name__ == "__main__":
    unittest.main()
