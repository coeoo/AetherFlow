# 全局协作约束

## 提交信息语言

- 本仓库中的所有 Git commit message 必须使用简体中文。
- 提交标题必须使用简体中文，禁止使用纯英文标题，例如 `fix bug`、`update`、`refactor`。
- 如果提交包含正文，正文也必须使用简体中文，至少说明：
  - 修改了什么
  - 为什么这么改
  - 验证了什么

## 本地大模型配置

- 本项目本地大模型配置统一放在仓库根目录 `.env.local`。
- `.env.local` 已被 `.gitignore` 忽略，禁止提交真实密钥。
- 可提交的模板是 `.env.example`，只能使用占位符，不得写入真实 Token。
- 需要的核心变量：
  - `LLM_BASE_URL`
  - `LLM_API_KEY`
  - `LLM_DEFAULT_MODEL`
- 可选调优变量：
  - `LLM_TIMEOUT_SECONDS`
  - `LLM_WALL_CLOCK_TIMEOUT_SECONDS`
  - `LLM_RETRY_ATTEMPTS`
  - `LLM_REASONING_EFFORT`
- Candidate Judge 开关：
  - `AETHERFLOW_CVE_CANDIDATE_JUDGE_ENABLED=false` 为默认基线行为
  - 只有需要验证候选判断 Agent 时才显式设为 `true`
- 检查配置是否加载时，必须通过 `app.config.load_settings()` 的结果判断，
  只输出 `set/missing`，不得打印 `LLM_API_KEY` 的真实值。
- 禁止把真实 API Key 写入源码、文档、日志、测试快照、commit message 或
  `AGENTS.md`。
