# Git-Vault Plugin for DSH (DeepSeek Harness)

本插件为 DSH 提供完整的 Git-Vault MCP 2.0 工具套件，支持在 DeepSeek 编程智能体环境中执行安全代码提交、合规自愈与 Star 资产检索。

## 安装方式

### 方式 1：通过 DSH CLI 一键添加
在终端中执行：
```bash
dsh plugin add <vault-root>\tools\git-vault\extensions\dsh
```

### 方式 2：在 DSH 桌面端安装
1. 打开 DSH 界面；
2. 进入 **设置 (Settings)** -> **插件 (Plugins)** -> **从本地文件夹添加**；
3. 选择 `<vault-root>\tools\git-vault\extensions\dsh` 目录即可。

## 工具能力清单

- `vault_list_repos`: 工作区仓库深度探针
- `vault_get_diff`: 工作区代码安全差分读取
- `vault_commit_push`: 受控提交与 GitHub/Gitee/GitLab 三云并发推送
- `vault_audit_compliance`: 主动合规与密钥防泄漏扫描
- `vault_remediate_gitignore`: .gitignore 自动自愈与解除缓存跟踪
- `vault_check_panic`: 查询全局只读急停锁状态
- `vault_search_stars`: 私有 Star 容灾库精准检索
- `vault_query_lists`: 8 大分类 Lists 统计获取
- `vault_star_repo`: 云端点星与分类绑定
- `vault_proxy_api`: 零明文特权 API 代理调用
