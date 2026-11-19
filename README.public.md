# git-vault

Windows 本地凭据网关：用 DPAPI 加密保存多平台 Git/API 令牌，为 Agent 提供受控的
commit / push / 外部 API 代理，并带 MCP（stdio + SSE）接入。

本仓库是公开脱敏版本，不含任何真实配置、凭据或日志数据。

---

## 能力

- 多平台多路同步：一次提交，按配置推送到 GitHub / Gitee / GitLab。
- 令牌保险箱：PAT 与非 Git 密钥仅以密文落盘（Windows DPAPI，CurrentUser 作用域）。
- 零明文 API 代理：Agent 调用外部服务时由网关解密并注入凭据，响应与日志脱敏。
- 全局只读锁（Panic Button）：一键阻断所有 Agent 的 commit / push，只保留只读能力。
- 合规熔断：单文件体积上限、敏感凭据扫描（AWS / GitHub / GitLab / OpenAI / 私钥）、
  翻墙类源码静态阻断、自然人身份与 `Co-authored-by` 署名装配。
- 分平台网络路由：GitHub 可选代理或 hosts，Gitee 默认境内直连。
- MCP 服务端：stdio 与 SSE 两种接入方式，内置受控工具与审计流水。
- Web 控制台：暗色工程界面，默认 `http://127.0.0.1:8765`。

---

## 平台限定：Windows + DPAPI

- 密文由 Windows DPAPI 生成，**只能在同一台 Windows 主机、同一用户账户下解密**。
- 拷贝 `config/vault.json` 到另一台机器或另一个用户账户后无法解密；
  Linux / macOS 上只能读取代码与非加密配置，令牌相关功能不可用。
- 跨机迁移：在目标机重新录入令牌，不要搬移 DPAPI 密文。

---

## 零明文说明

- 磁盘上只有 DPAPI 密文；明文只出现在进程内存中，用完即弃。
- Agent 永远拿不到令牌明文：代理层解密、发起请求、返回前按规则脱敏。
- 需要新 token 时在平台侧生成后直接写入网关，不经过对话、日志或提交历史。

---

## 快速开始

```bash
# 1. 生成单文件部署包
python scripts/package.py

# 2. 运行（首次运行会在 dist/ 旁解出 .vault-runtime，配置与日志写在该目录）
python dist/vault.pyz

# 或直接从源码运行
python server.py
```

浏览器打开 `http://127.0.0.1:8765`。

首次使用配置：

```bash
copy config\vault.example.json config\vault.json
copy config\managed_repos.example.json config\managed_repos.json
copy config\git_profiles.example.json config\git_profiles.json
copy config\network_routes.example.json config\network_routes.json
```

示例文件里的 `<owner>`、`<bot-account>`、`127.0.0.1:11455`、`%USERPROFILE%` 均为
占位符，按本机情况替换。

---

## MCP 配置片段

stdio（Agent 侧直接拉起 MCP 进程）：

```json
{
  "mcpServers": {
    "git-vault": {
      "command": "python",
      "args": ["<REPO>/core/mcp_server.py"]
    }
  }
}
```

HTTP SSE（网关已在运行时）：

```json
{
  "mcpServers": {
    "git-vault": {
      "url": "http://127.0.0.1:8765/mcp/sse"
    }
  }
}
```

---

## 不包含任何 config / logs 数据

发布包明确不包含：

- `config/vault.json`、`config/managed_repos.json`、`config/git_profiles.json`、
  `config/network_routes.json`、`config/starred_vault.json`、`config/runtime_state.json`、
  `config/sync_*.json` 及任何 `*.bak*` 备份；
- `logs/` 下的服务日志与审计流水；
- 真实账号名、邮箱、仓库路径与绝对路径。

只提供 `config/*.example.json` 占位示例。

---

## 许可

MIT，见 [LICENSE](LICENSE)。
