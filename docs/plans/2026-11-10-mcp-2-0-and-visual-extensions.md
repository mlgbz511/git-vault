# Git-Vault MCP 2.0 & 可视化扩展中心实施计划 (Implementation Plan)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 构建 Git-Vault MCP 2.0 企业级受控网关，扩充为 10 大标准工具群与只读 Resources，并提供面向 Antigravity 原生 Plugin 扩展与 DSH (DeepSeek Harness) 的可视化接入体系与 Web 端一键安装中枢。

**Architecture:** 
1. `core/mcp_server.py` 全面升级，新增合规主动自愈 (`vault_audit_compliance`, `vault_remediate_gitignore`, `vault_check_panic`)、Star 资产容灾检索 (`vault_search_stars`, `vault_query_lists`, `vault_star_repo`)，支持 `vault://` Resources 协议并对 Stdio 执行纯净流重定向；
2. 构建 Antigravity 原生扩展包 (`~/.gemini/config/plugins/git-vault/`) 与工具 Schema (`~/.gemini/antigravity/mcp/git-vault/`)；
3. 构建 DSH 插件包 (`tools/git-vault/extensions/dsh/dsh.plugin.json`)；
4. 在 Web 控制台开发 `[ Agent 接入中心 ]` 弹窗与后端 API (`/api/agent/status`, `/api/agent/install-antigravity`) 实现零手工配置一键就绪。

**Tech Stack:** Python 3.10+, JSON-RPC 2.0, Model Context Protocol (MCP 2024-11-05), Server-Sent Events (SSE), HTML5/CSS3 (GitHub Primer Dark / Claude Design System), Windows DPAPI.

**Spec:** [`%USERPROFILE%/.gemini/antigravity/brain/cb563e4b-2086-4026-bd52-1668ae4d2c03/plan_mcp_server_2_0_design.md`](file:///%USERPROFILE%/.gemini/antigravity/brain/cb563e4b-2086-4026-bd52-1668ae4d2c03/plan_mcp_server_2_0_design.md)

---

## Global Constraints

- 严禁在代码、提交信息、日志或交互界面中使用任何修饰性 Emoji 表情字符；
- Stdio 管道必须实现绝对纯净流：所有非 JSON-RPC 输出、print 及底层异常必须强行重定向至 `sys.stderr`；
- 所有密码与 Token 绝不以明文形式返回给 Agent，严格执行零明文（Zero-Plaintext）脱敏规则；
- 所有已有的 61 项自动化测试必须持续 100% 通过，不引入回归缺陷；
- Antigravity 插件配置必须兼容本地现有 `%USERPROFILE%\.gemini\config\mcp_config.json` 与 `%USERPROFILE%\.gemini\antigravity\mcp\` 规范。

---

## Review Focus

1. **Stdio JSON 管道污染检测**：若底层子模块执行 `print()`，是否会导致 `run_stdio_server()` 抛出 JSON 解析错误？测试需重定向标准输出并验证。
2. **Panic 状态穿透防护**：当系统处于急停只读状态时，`vault_commit_push` 和 `vault_create_repo` 是否能物理阻断并返回标准 `isError: true`？
3. **Star 资产中文字符搜索**：`vault_search_stars` 对中文描述（如“前沿模型”、“免费”）及大小写无关分类名（如 `SKILL`, `skill`）是否能稳定召回？
4. **Antigravity 一键安装原子性**：若用户重复点击“一键安装到 Antigravity”，是否会产生覆盖冲突或写坏既有的 `mcp_config.json`？
5. **合规自愈后 Git 状态收敛**：`vault_remediate_gitignore` 写入规则后，是否能自动调用 `git rm --cached` 将已追踪的受污染文件安全剥离？

---

## Tasks

### Task 1: 重构 `core/mcp_server.py` 核心工具集与 Resources 协议 (TDD)

**Files:**
- Modify: `tools/git-vault/core/mcp_server.py`
- Test: `tools/git-vault/tests/test_mcp_server_v2.py`

- [ ] **Step 1.1**: 编写测试用例 `tests/test_mcp_server_v2.py`，断言 `tools/list` 包含全部 10 个工具名称，并断言 `resources/list` 与 `resources/read` 能够获取 `vault://stars/index.md`。
- [ ] **Step 1.2**: 运行测试确认因工具缺失而失败（Red 阶段）。
- [ ] **Step 1.3**: 在 `core/mcp_server.py` 中实现新增的工具处理器：
  - `tool_vault_audit_compliance(args)`：调用 `compliance_guard.scan_repository` 返回合规明细；
  - `tool_vault_remediate_gitignore(args)`：调用 `gitignore_manager` 自动写入 `.gitignore` 并执行缓存移除；
  - `tool_vault_check_panic(args)`：返回当前急停锁状态与拦截说明；
  - `tool_vault_search_stars(args)`：调用 `star_vault_engine.query_vault` 实现多条件搜索；
  - `tool_vault_query_lists(args)`：返回 8 个 Lists 分类统计；
  - `tool_vault_star_repo(args)`：支持为仓库点星并归入本地和云端 Lists。
- [ ] **Step 1.4**: 实现 MCP Resources 协议处理器：`resources/list` 和 `resources/read`，支持 `vault://stars/index.md`、`vault://stars/catalog.json`、`vault://system/health`。
- [ ] **Step 1.5**: 实现 Stdio 输出纯净流保护（`SafeStdioWriter`），拦截外部 `print` 并定向至 `sys.stderr`。
- [ ] **Step 1.6**: 运行 `test_mcp_server_v2.py` 确保全部用例通过（Green 阶段）。
- [ ] **Step 1.7**: 提交变更：`git commit -m "feat(mcp): upgrade mcp server to 2.0 with 10 tools and resources support"`。

---

### Task 2: 构建 Antigravity 原生 Plugin 扩展包与 Schema 一键生成器

**Files:**
- Create: `tools/git-vault/core/agent_installer.py`
- Create: `tools/git-vault/extensions/antigravity/plugin.json`
- Create: `tools/git-vault/extensions/antigravity/mcp_config.json`
- Create: `tools/git-vault/extensions/antigravity/skills/git-vault-workflow/SKILL.md`
- Test: `tools/git-vault/tests/test_agent_installer.py`

- [ ] **Step 2.1**: 编写测试用例 `tests/test_agent_installer.py`，断言安装器能够正确检测 Antigravity 环境并在指定目标生成插件与 10 个工具的 JSON Schema 文件。
- [ ] **Step 2.2**: 编写模板文件 `tools/git-vault/extensions/antigravity/plugin.json` 与 `SKILL.md`。
- [ ] **Step 2.3**: 编写 `core/agent_installer.py`，实现：
  - `check_antigravity_status()`：探测 `~/.gemini/config/plugins/git-vault` 与 `mcp_config.json`；
  - `install_antigravity_plugin()`：自动复制插件包并安全合并配置，生成 `~/.gemini/antigravity/mcp/git-vault/` 下的 10 个 tool schema (`.json`) 与 `instructions.md`；
  - `check_dsh_status()` 与 `generate_dsh_manifest()`。
- [ ] **Step 2.4**: 运行测试确保安装器生成的文件格式和 JSON 均有效。
- [ ] **Step 2.5**: 提交变更：`git commit -m "feat(extensions): implement antigravity plugin bundle and schema auto-installer"`。

---

### Task 3: 构建 DSH (DeepSeek Harness) 插件包

**Files:**
- Create: `tools/git-vault/extensions/dsh/dsh.plugin.json`
- Create: `tools/git-vault/extensions/dsh/README.md`

- [ ] **Step 3.1**: 按照 DSH 社区规范（参照 `Ebony-Vinyl/dsh-our-free-model`）编写 `dsh.plugin.json`，声明工具提供者与 `http://127.0.0.1:8765/mcp/sse` 连接端点。
- [ ] **Step 3.2**: 编写 `README.md`，提供一行指令安装说明（`dsh plugin add ...`）与离线测试方案。
- [ ] **Step 3.3**: 提交变更：`git commit -m "feat(extensions): add dsh plugin bundle for deepseek harness"`。

---

### Task 4: 服务端 API 接入与 Web 控制台【Agent 接入中心】前端开发

**Files:**
- Modify: `tools/git-vault/server.py`
- Modify: `tools/git-vault/web/index.html`
- Test: `tools/git-vault/tests/test_server_api.py`

- [ ] **Step 4.1**: 在 `server.py` 中注册新端点：
  - `GET /api/agent/status`：返回 Antigravity 和 DSH 插件的安装与连通状态；
  - `POST /api/agent/install-antigravity`：触发本地一键安装到 Antigravity 扩展目录；
  - `GET /api/agent/dsh-config`：返回 DSH 一键安装配置指令。
- [ ] **Step 4.2**: 运行测试 `test_server_api.py` 验证新 API 端点。
- [ ] **Step 4.3**: 在 `web/index.html` 顶部导航栏增加 `[ Agent 接入 ]` 按钮（带芯片图标）；
- [ ] **Step 4.4**: 在 `web/index.html` 实现 `agentHubModal` 弹窗界面：
  - **Antigravity 卡片**：动态展示当前安装状态，提供 `[ 一键安装至 Antigravity 扩展 ]` 按钮，安装后展示绿灯状态；
  - **DSH 卡片**：展示 DSH 插件说明与 `[ 复制 dsh plugin 指令 ]` 按钮；
  - **Cursor / VS Code 卡片**：提供标准配置 JSON 一键复制；
- [ ] **Step 4.5**: 编写前端 JavaScript 处理函数 `openAgentHubModal()`, `installAntigravityPlugin()`, `copyDshCommand()`。
- [ ] **Step 4.6**: 提交变更：`git commit -m "feat(ui): add visual ai agent integration hub modal in web console"`。

---

### Task 5: 真实环境一键安装部署与全量回归验证

**Files:**
- All modified files across `tools/git-vault`

- [ ] **Step 5.1**: 运行全量自动化测试（包含全部历史 61 项用例与新增用例）：
  `python -m unittest discover -s tests -v`
- [ ] **Step 5.2**: 执行一次真实的一键安装，将 Git-Vault 扩展正式挂载至用户本机的 `%USERPROFILE%\.gemini\config\plugins\git-vault\` 与 `%USERPROFILE%\.gemini\antigravity\mcp\git-vault\`。
- [ ] **Step 5.3**: 重启后台脱壳守护服务（PID 切换验证）。
- [ ] **Step 5.4**: 提交最终变更并向用户做完整交付汇报。
