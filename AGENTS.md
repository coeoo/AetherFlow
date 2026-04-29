# AetherFlow 协作约束与索引

本文件只承载仓库级协作约束、当前稳定真相和常用入口索引。

## 1. 文档边界

- `AGENTS.md`：仓库级协作规则、验证约束、事实入口索引。
- `.trellis/workflow.md`：Trellis 工作流、阶段推进、任务流转、agent 路由真相；执行流程以它为准，不在这里重复展开。
- `docs/design/README.md`：长期实现设计索引；模块边界、入口、状态字段、降级和测试映射放到 `docs/design/`，不写进本文件。
- `docs/03-系统架构/架构设计.md`：平台运行形态和全局架构真相。

如果某条内容更像“怎么实现模块”而不是“如何协作与验证”，应写到 `docs/design/` 或对应设计文档，不应继续堆到 `AGENTS.md`。

## 2. 当前仓库真相

- 前端稳定主路由包括 `/`、`/patch`、`/announcements`、`/deliveries`、`/system/tasks`、`/system/health`。
- `/patch` 是当前真实的 CVE / Patch 工作台入口；相关详情页路由是 `/patch/runs/:runId`。
- 系统当前运行角色是 `API / Worker / Scheduler`。
- `Scheduler` 当前是最小职责实现：保留 entrypoint，写入 heartbeat，并处理已到期投递记录；不要把它描述成已完成的通用调度平台。

## 3. 稳定协作规则

### 3.1 提交信息

- 本仓库所有 Git commit message 必须使用简体中文。
- 提交标题禁止使用 `fix bug`、`update`、`refactor` 这类空泛英文标题。
- 如果提交包含正文，至少说明：改了什么、为什么这么改、验证了什么。

### 3.2 本地模型与配置

- 本地模型配置统一放在仓库根目录 `.env.local`。
- `.env.local` 必须保持忽略，不得提交真实密钥；可提交模板是 `.env.example`。
- 当前核心 LLM 配置键：
  - `LLM_BASE_URL`
  - `LLM_API_KEY`
  - `LLM_DEFAULT_MODEL`
- 当前常用调优键：
  - `LLM_TIMEOUT_SECONDS`
  - `LLM_WALL_CLOCK_TIMEOUT_SECONDS`
  - `LLM_RETRY_ATTEMPTS`
  - `LLM_REASONING_EFFORT`
- Candidate Judge 默认保持关闭：
  - `AETHERFLOW_CVE_CANDIDATE_JUDGE_ENABLED=false`
  - 只有在明确验证 Candidate Judge 时才显式打开
- 检查配置是否加载时，以 `app.config.load_settings()` 的结果为准；只输出 `set/missing`，不要打印真实 `LLM_API_KEY`。

### 3.3 运行产物与提交边界

- `backend/results/` 是运行证据目录，用于 acceptance、baseline、compare 和真实样本结果留档。
- `backend/results/` 默认不提交；汇报时记录报告路径和关键摘要即可。
- 基线夹具、测试夹具等可版本化内容，应放在测试夹具目录，不要混放进 `backend/results/`。

### 3.4 测试与验证约定

- 涉及数据库的测试，优先显式传入 `TEST_DATABASE_URL`，不要隐式依赖 shell 残留环境。
- 常规测试和轻量脚本默认带外层超时，优先使用 `timeout 60s`。
- 若是真实浏览器 acceptance 或明显超过 60 秒的链路，应在任务上下文里单独说明原因和超时值，不要静默放大。

## 4. 常用事实入口

- 工作流与任务阶段：`.trellis/workflow.md`
- 当前 task 需求与上下文：`.trellis/tasks/<task>/prd.md`、`implement.jsonl`、`check.jsonl`
- 平台/场景架构：`docs/03-系统架构/架构设计.md`
- 长期实现设计索引：`docs/design/README.md`
- 前端路由真相：`frontend/src/app/router.tsx`
- 本地配置加载：`backend/app/config.py`
- 运行角色中的 Scheduler 最小职责：`backend/app/scheduler/runtime.py`
- 默认测试入口与超时约定：`Makefile`
- 运行产物忽略规则：`.gitignore`

## 5. 使用原则

- 优先依据当前代码、当前 task 文档和上述入口核对事实，不要把临时会话策略写成本仓库长期规则。
- 需要长期保留的实现细节，补到 `docs/design/`；需要阶段性执行安排，补到 task / plan 文档；不要继续扩写本文件。
