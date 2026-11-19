# tests/test_multi_account_vault.py
# Antigravity Git-Vault - Multi-Account Entity & Repository Binding Verification
import os
import sys
import unittest

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from core import credential_vault

TOKEN_PERSONAL = "ghp_" + "personal_token_12345678"
TOKEN_WORK = "ghp_" + "company_token_87654321"

class TestMultiAccountVault(unittest.TestCase):
    def setUp(self):
        # 备份原始 vault.json 并为测试隔离清空
        self.raw_backup = credential_vault.load_raw_vault()
        credential_vault.save_raw_vault({"accounts": [], "repo_bindings": {}, "tokens": {}, "non_git_secrets": {}})

    def tearDown(self):
        # 还原 vault.json
        credential_vault.save_raw_vault(self.raw_backup)

    def test_multi_account_lifecycle(self):
        # 1. 为 github 添加第一个账号 (应自动设为默认)
        res1 = credential_vault.add_or_update_account(
            platform="github",
            token=TOKEN_PERSONAL,
            username="user_personal",
            alias="个人主号",
            expires_at="never",
            is_default=False, # 虽然传 False，但首个账号应被自动提升为默认
            account_id="acc_gh_test_1"
        )
        self.assertTrue(res1["success"])
        self.assertTrue(res1["is_default"])

        # 2. 为同一个 github 添加第二个账号 (企业工作号)
        res2 = credential_vault.add_or_update_account(
            platform="github",
            token=TOKEN_WORK,
            username="user_work",
            alias="公司企业工作号",
            expires_at="2027-12-31",
            is_default=False,
            account_id="acc_gh_test_2"
        )
        self.assertTrue(res2["success"])
        self.assertFalse(res2["is_default"])

        # 3. 验证默认获取明文 Token 得到第一个账号
        default_token = credential_vault.get_plain_token("github")
        self.assertEqual(default_token, TOKEN_PERSONAL)

        # 4. 切换默认账号为企业工作号
        set_res = credential_vault.set_default_account("acc_gh_test_2")
        self.assertTrue(set_res["success"])
        new_default_token = credential_vault.get_plain_token("github")
        self.assertEqual(new_default_token, TOKEN_WORK)

        # 5. 测试仓库级独立绑定 (即使全局默认是工作号，指定仓库绑定个人号依然优先命中)
        fake_repo = "<vault-root>\\projects\\open_source_app"
        bind_res = credential_vault.bind_repo_account(fake_repo, "github", "acc_gh_test_1")
        self.assertTrue(bind_res["success"])
        repo_token = credential_vault.get_plain_token("github", repo_path=fake_repo)
        self.assertEqual(repo_token, TOKEN_PERSONAL)

        # 非绑定仓库依然走全局默认
        other_repo_token = credential_vault.get_plain_token("github", repo_path="<vault-root>\\other")
        self.assertEqual(other_repo_token, TOKEN_WORK)

        # 6. 验证脱敏列表
        accounts = credential_vault.list_accounts_masked(platform="github")
        self.assertEqual(len([a for a in accounts if a["id"] in ["acc_gh_test_1", "acc_gh_test_2"]]), 2)
        work_acc = next(a for a in accounts if a["id"] == "acc_gh_test_2")
        self.assertTrue(work_acc["is_default"])
        self.assertEqual(work_acc["alias"], "公司企业工作号")
        # T2 规格变更：掩码改为「前缀段+长度」如 ghp_…(27)，不再输出 ****；
        # 实质约束不变：token 尾 4 位严禁出现在掩码里。
        self.assertTrue(work_acc["masked"].startswith("ghp_"))
        self.assertNotIn("4321", work_acc["masked"])

        # 7. 删除当前默认账号，验证系统自动将剩余同平台账号设为默认
        del_res = credential_vault.delete_account("acc_gh_test_2")
        self.assertTrue(del_res["success"])
        recovered_token = credential_vault.get_plain_token("github")
        self.assertEqual(recovered_token, TOKEN_PERSONAL)

        # 8. 清理解绑
        unbind_res = credential_vault.bind_repo_account(fake_repo, "github", "")
        self.assertTrue(unbind_res["success"])
        credential_vault.delete_account("acc_gh_test_1")

    def test_legacy_data_migration(self):
        # 构造纯旧版 vault 数据
        legacy_cipher = credential_vault.dpapi_encrypt("gitee_mock_secret_9999")
        legacy_data = {
            "saved_accounts": {"gitee_user": "old_user"},
            "encrypted_tokens": {"gitee": legacy_cipher},
            "token_metadata": {"gitee": {"username": "old_user", "expires_at": "never"}},
            "accounts": []
        }
        migrated = credential_vault.migrate_legacy_tokens(legacy_data)
        self.assertTrue(migrated)
        self.assertEqual(len(legacy_data["accounts"]), 1)
        acc = legacy_data["accounts"][0]
        self.assertEqual(acc["platform"], "gitee")
        self.assertEqual(acc["username"], "old_user")
        self.assertTrue(acc["is_default"])
        plain = credential_vault.dpapi_decrypt(acc["encrypted_token"])
        self.assertEqual(plain, "gitee_mock_secret_9999")

    def test_universal_secrets_management(self):
        # 1. 保存 AI 大模型密钥
        res = credential_vault.save_generic_secret(
            service="deepseek",
            secret="sk-" + "dsk-test-secret-key-12345678",
            env_var="DEEPSEEK_API_KEY",
            category="ai",
            alias="DeepSeek-V3 生产主Key",
            description="用于 Agent 代码自动补全"
        )
        self.assertTrue(res["success"])

        # 2. 保存云平台密钥
        res2 = credential_vault.save_generic_secret(
            service="cloudflare",
            secret="cf-token-secure-12345678",
            env_var="CLOUDFLARE_API_TOKEN",
            category="cloud",
            alias="Cloudflare 全局治理 Token",
            description="用于 DNS 解析与边缘缓存清理"
        )
        self.assertTrue(res2["success"])

        # 3. 按分类查询列表
        ai_secrets = credential_vault.list_all_secrets_masked(category="ai")
        self.assertTrue(any(s["service"] == "deepseek" for s in ai_secrets))
        ds_secret = next(s for s in ai_secrets if s["service"] == "deepseek")
        self.assertEqual(ds_secret["env_var"], "DEEPSEEK_API_KEY")
        self.assertEqual(ds_secret["alias"], "DeepSeek-V3 生产主Key")
        self.assertTrue(ds_secret["has_secret"])

        # 4. 解密验证
        plain_ds = credential_vault.get_non_git_secret_plain("deepseek")
        self.assertEqual(plain_ds, "sk-dsk-test-secret-key-12345678")

        # 5. 删除测试
        del_res = credential_vault.delete_non_git_secret("deepseek")
        self.assertTrue(del_res["success"])
        self.assertEqual(credential_vault.get_non_git_secret_plain("deepseek"), "")

if __name__ == "__main__":
    unittest.main()
