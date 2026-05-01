# Backend 质量约定

> 测试规模、运行边界、提交质量、敏感配置。

---

## 1. 测试规模与覆盖

- 当前 49 个测试文件 / 464 用例（`backend/tests/`）
- 关键测试类型：
  - `test_*.py` — 单元/集成测试
  - `test_acceptance_*.py` — 真实样本端到端（如 `test_acceptance_browser_agent.py`）
  - `test_*_schema_contract.py` — Schema 兼容契约
  - `test_*_regressions.py` — 回归基线（如 `test_cve_regressions.py`）
- 来自 `docs/06-开发规范/代码规范.md` §7：
  - 新功能先写设计 → 再写测试 → 再写实现
  - 长任务测试覆盖**成功 / 失败 / 重试 / 超时**四类路径
  - 场景测试必须覆盖**手动入口**与**自动入口**差异

---

## 2. 测试运行约定

参考 `Makefile` 与 `AGENTS.md` §3.4：

- **常规命令**：`make backend-test`（带 `timeout 60s` 与 `TEST_DATABASE_URL`）
- **针对性测试**：`./.venv/bin/python -m pytest backend/tests/test_<module>.py -v`
- **DB 测试前置**：`make pg-up`（启动 docker postgres）
- **超时**：默认 `timeout 60s`；超过 60s 的真实浏览器 acceptance 必须在任务上下文显式说明原因和超时值，**不要静默放大**
- **TEST_DATABASE_URL 必传**：`backend/tests/conftest.py::test_database_url` 缺失会 `pytest.skip`，不要让 CI 误判通过

---

## 3. 运行产物边界

来自 `AGENTS.md` §3.3：

- `backend/results/` 是运行证据目录（acceptance、baseline、compare、真实样本结果留档）
- **默认 git 忽略**，不提交
- 汇报时只记录报告路径和关键摘要
- **可版本化**的基线夹具、测试夹具放 `backend/tests/fixtures/`，**不要**混进 `backend/results/`

---

## 4. 敏感配置规则

来自 `AGENTS.md` §3.2：

- 本地模型配置统一放仓库根 `.env.local`（已 gitignore，模板是 `.env.example`）
- 核心 LLM 配置键：`LLM_BASE_URL` / `LLM_API_KEY` / `LLM_DEFAULT_MODEL`
- 调优键：`LLM_TIMEOUT_SECONDS` / `LLM_WALL_CLOCK_TIMEOUT_SECONDS` / `LLM_RETRY_ATTEMPTS` / `LLM_REASONING_EFFORT`
- **Candidate Judge 默认关闭**：`AETHERFLOW_CVE_CANDIDATE_JUDGE_ENABLED=false`
- **检查配置**：以 `app.config.load_settings()` 结果为准；**只输出 `set/missing`**，**不要**打印 `LLM_API_KEY` 真实值

---

## 5. 提交质量

来自 `AGENTS.md` §3.1 + `docs/06-开发规范/Git规范.md`：

- 提交信息**必须使用简体中文**
- **禁止** `fix bug` / `update` / `refactor` 这类空泛英文标题
- 提交正文至少说明：
  1. **改了什么**
  2. **为什么这么改**（连接到设计文档/任务/ADR）
  3. **验证了什么**（测试命令 + 通过的测试名）
- 不使用 `--no-verify` / `--no-gpg-sign` 跳过 hook，除非用户明确要求
- 提交前必须 `git diff --cached --stat` 验证范围

---

## 6. 代码质量原则

- **可测试性 > 可读性 > 一致性 > 简洁性 > 可逆转性**
- SOLID + YAGNI + DRY，但不为消除少量合理重复引入复杂层级
- **精准修改**：每行变更都应能追溯到当前用户目标、必要验证或本次改动造成的清理；不要借机改格式 / 改命名 / 重排代码
- 只清理本次改动造成的孤儿代码；预先存在的 dead code 在汇报中指出，不主动删

---

## 7. 禁止

- **不要在 `backend/results/` 写测试夹具**——它默认不提交，CI 会丢失
- **不要把 LLM_API_KEY 真实值打进日志或提交**
- **不要静默吞 PostgreSQL 连接错误**——测试 fixture 已 skip，业务代码必须冒泡
- **不要为兼容旧结构保留无意义 legacy 代码**（`代码规范.md` §1）
- **不要让单个 run 失败把 worker 主循环挂掉**——节点错误由 runtime 翻译成 `stop_reason`
- **不要在 commit 中夹带 `.trellis/` 治理改动到业务 commit**——治理改动单独提交（杂项类标题）

---

## 8. Code Review 关注点

资深 reviewer 视角：

- 边界条件（空列表、None、超长输入）
- 错误路径是否清晰（catch/raise/log 三件套齐全）
- 是否引入回归（跑相邻模块的测试）
- 测试覆盖了**失败/超时/重试**路径，不只是 happy path
- 跨场景分层是否被破坏（CVE 语义出现在 platform/）
