# 2026-04-27 Session022 - CVE Candidate Judge 默认关闭接口

状态: ✅ 已完成

## 做了什么

- 基于 Phase 1 baseline 通过结论，进入 CVE Agent Boundary Refactor Phase 2 Task 2.1。
- 先做 readiness review，确认 Task 2.1 只引入 Candidate Judge 接口，默认关闭，不接入 `agent_decide_node`。
- 按 TDD 增加 feature flag 与 Candidate Judge schema 测试，并先确认 RED。
- 新增 Candidate Judge 独立决策模块和 prompt：
  - `backend/app/cve/decisions/candidate_judge.py`
  - `backend/app/cve/prompts/candidate_judge.md`
- 在 `Settings` 中新增 `cve_candidate_judge_enabled`，由 `AETHERFLOW_CVE_CANDIDATE_JUDGE_ENABLED` 控制，默认 `False`。
- 更新边界重构计划和 AI 使用说明，记录 Task 2.1 的验证结果与下一步。

## 本次更新的文档

- `docs/superpowers/plans/2026-04-25-cve-agent-boundary-refactor.md`
  - 标记 Task 2.1 的 feature flag 测试、schema 测试、接口实现和测试验证已完成。
  - 记录目标测试与补充回归结果。
- `docs/09-AI开发日志/README_AI使用说明.md`
  - 更新到 v1.10。
  - 明确 Candidate Judge 默认关闭接口已落地，下一步是 Phase 2 Task 2.2。
- `docs/09-AI开发日志/日志/2026-04-27_Session022_CVE_CandidateJudge默认关闭接口.md`
  - 新增本次开发日志。

## 本次更新的代码

- `backend/app/config.py`
  - 新增 `cve_candidate_judge_enabled` 配置项。
  - 从 `AETHERFLOW_CVE_CANDIDATE_JUDGE_ENABLED` 读取，默认关闭。
- `backend/app/cve/decisions/candidate_judge.py`
  - 新增 `CandidateJudgeContext`。
  - 新增 `CandidateJudgeResult` 和 `to_dict()` schema 输出。
  - 新增 `build_candidate_judge_context()`。
  - 新增 `call_candidate_judge()`，按 OpenAI 兼容 JSON object 方式调用 LLM。
- `backend/app/cve/prompts/candidate_judge.md`
  - 新增 Candidate Judge 系统提示词，约束返回固定 JSON object。
- `backend/tests/test_cve_agent_decisions.py`
  - 增加默认关闭、环境变量开启、schema 字段和结构化响应解析测试。

## 关键决策

- Task 2.1 不修改 `agent_nodes.py`，不接入主链，避免影响 Phase 1 行为。
- Candidate Judge 的接口先保持最小：只定义 context、result schema、prompt 和显式调用函数。
- feature flag 默认关闭；真正影响候选排序/过滤的接入留到 Task 2.2。
- `backend/results/` 仍是运行产物，本次不提交。

## 验证结果

RED:

```text
ImportError: cannot import name 'candidate_judge' from 'app.cve.decisions'
```

GREEN:

```bash
timeout 60s ./.venv/bin/python -m pytest \
  backend/tests/test_cve_agent_decisions.py \
  backend/tests/test_phase2_schema_contract.py \
  -q
```

结果：

```text
20 passed in 0.71s
```

计划要求的决策测试：

```bash
timeout 60s ./.venv/bin/python -m pytest backend/tests/test_cve_agent_decisions.py -q
```

结果：

```text
12 passed in 0.18s
```

补充回归：

```bash
timeout 60s ./.venv/bin/python -m pytest \
  backend/tests/test_cve_agent_graph.py \
  backend/tests/test_browser_agent_llm.py \
  -q
```

结果：

```text
45 passed, 35 skipped in 5.82s
```

Diff 检查：

```bash
git diff --check
```

结果：通过。

## 下次计划

1. 进入 Phase 2 Task 2.2：在 feature flag 下接入 Candidate Judge。
2. 接入前先做重点 review，确认候选下载前排序/过滤不会改变默认关闭行为。
3. flag on 后复跑 baseline candidate，并与 Phase 1 baseline 对比。

## 遗留风险

- Candidate Judge 目前只是接口和 prompt，尚未接入主链，不能改善候选过滤质量。
- Task 2.2 会影响候选下载前决策边界，需要比 Task 2.1 更严格的 review 与 baseline 对比。
- `backend/results/` 中仍有本地验收产物，默认不提交。
