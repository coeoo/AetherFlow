# 2026-04-28 Session023 - CVE Candidate Judge 主链接入

状态: ✅ 已完成

## 做了什么

- 基于 `CVE Agent Boundary Refactor` Phase 2 Task 2.2，按 TDD 将
  Candidate Judge 接入候选下载前决策。
- Candidate Judge 仍由 `AETHERFLOW_CVE_CANDIDATE_JUDGE_ENABLED` 控制，
  默认关闭时保持原有候选下载行为。
- flag 开启且下一步为 `try_candidate_download` 时：
  - 对当前直接候选调用 Candidate Judge。
  - 只保留 `verdict=accept` 且 `candidate_key` 与候选 canonical key 匹配的候选。
  - 全部拒绝时停止搜索，并写入 `candidate_judge_rejected_all`。
  - 调用异常时降级保留原下载决策，不让主链失败。
- Candidate Judge 结果会额外记录 `candidate_judge` 搜索决策，保留输入候选、
  结构化输出、接受 key 和拒绝原因，便于后续 baseline 对比归因。

## 本次更新的代码

- `.env.example`
  - 新增可提交的本地配置模板，只包含占位符，不包含真实密钥。
- `AGENTS.md`
  - 补充本地大模型配置约定：真实值放 `.env.local`，模板放 `.env.example`，
    检查配置必须通过 `load_settings()`，不得打印真实 API Key。
- `docs/07-部署运维/环境配置.md`
  - 补充 Candidate Judge 开关与 LLM 配置检查约束。
- `backend/app/cve/decisions/candidate_judge.py`
  - 新增 `CandidateJudgeSelection`。
  - 新增 `select_candidate_keys_with_judge()`。
  - 增强 provider 非 JSON 响应诊断，记录状态码、content-type 和截断 body 预览，
    不记录密钥。
- `backend/app/cve/agent_nodes.py`
  - 在 `try_candidate_download` 决策落地前接入 Candidate Judge。
  - 保持 feature flag 默认关闭和异常降级。
  - 写入 `candidate_judge` 搜索决策记录。
- `backend/tests/test_cve_agent_decisions.py`
  - 新增 selection helper 的 accept/reject 单元测试。
  - 新增 provider 非 JSON 响应诊断测试，确保错误信息不泄漏 API Key。
- `backend/tests/test_cve_agent_graph.py`
  - 新增 flag on 接受高可信 commit patch 的图节点测试。
  - 新增 flag on 拒绝 CVSS 噪声候选的图节点测试。
  - 新增 Candidate Judge 决策记录断言。
- `docs/superpowers/plans/2026-04-25-cve-agent-boundary-refactor.md`
  - 回写 Task 2.2 的 RED/GREEN 证据和 baseline 未执行原因。

## 验证结果

RED:

```text
timeout 60s ./.venv/bin/python -m pytest backend/tests/test_cve_agent_graph.py -q

2 failed, 28 passed, 35 skipped in 0.46s
```

失败原因：

- `app.cve.agent_nodes.candidate_judge_decisions` 尚不存在。
- 追加 evidence 约束后，缺少 `candidate_judge` 决策记录。

GREEN:

```bash
timeout 60s ./.venv/bin/python -m pytest backend/tests/test_cve_agent_graph.py -q
```

结果：

```text
30 passed, 35 skipped in 0.32s
```

计划要求的组合回归：

```bash
timeout 60s ./.venv/bin/python -m pytest \
  backend/tests/test_cve_agent_graph.py \
  backend/tests/test_browser_agent_integration.py \
  -q
```

结果：

```text
30 passed, 40 skipped in 0.33s
```

补充决策与 LLM 客户端回归：

```bash
timeout 60s ./.venv/bin/python -m pytest \
  backend/tests/test_cve_agent_decisions.py \
  backend/tests/test_browser_agent_llm.py \
  -q
```

结果：

```text
30 passed in 3.28s
```

## Baseline 对比

本轮继续执行了 flag off / flag on mock candidate report。

说明：

- `--all` 在 180 秒外层保护内超时，原因是两个真实浏览器场景串行运行时，
  第二个场景尚未完成即被 timeout 终止。
- 改为按单 CVE 分开运行。
- 复核后确认：shell 进程环境变量没有直接设置 LLM 配置，但应用通过 `.env.local`
  和 `load_settings()` 可以加载 `LLM_BASE_URL` / `LLM_API_KEY` / `LLM_DEFAULT_MODEL`。
- flag on 触发了 Candidate Judge 真实调用；失败原因是 provider 返回体不是合法 JSON，
  主链按设计降级保留原候选决策。

报告路径：

- flag off `CVE-2022-2509`:
  `backend/results/candidate-cve-agent-boundary-refactor-phase2-flag-off-mock-cve-2022-2509/acceptance_report.json`
- flag on `CVE-2022-2509`:
  `backend/results/candidate-cve-agent-boundary-refactor-phase2-flag-on-mock-cve-2022-2509/acceptance_report.json`
- flag off `CVE-2024-3094`:
  `backend/results/candidate-cve-agent-boundary-refactor-phase2-flag-off-mock-cve-2024-3094/acceptance_report.json`
- flag on `CVE-2024-3094`:
  `backend/results/candidate-cve-agent-boundary-refactor-phase2-flag-on-mock-cve-2024-3094/acceptance_report.json`

对比结论：

- `CVE-2022-2509`: `patch_quality_degraded=false`,
  `high_value_path_regressed=false`。差异仅来自 GitLab Cloudflare token
  导致 navigation path 字符串变化。
- `CVE-2024-3094`: `patch_quality_degraded=false`,
  `high_value_path_regressed=false`。差异为 final patch URL 顺序变化，patch
  类型仍为 `github_commit_patch`。

## 遗留风险

- Candidate Judge prompt 目前只通过结构化响应、fake judge 测试和 provider 非 JSON
  响应时的降级路径验证；尚未在真实 LLM 返回合法 JSON 时验证“正常 judge
  接受/拒绝”的收益。
- 如果 Candidate Judge 在真实样本中过度拒绝候选，可能降低 patch 找到率；必须通过
  baseline 对比观察 `patch_found`、`false positive`、LLM 调用次数、duration 和
  patch quality。
- 当前工作区存在与本轮无关的历史计划文件删除状态，未处理、未回滚。

## 下次计划

1. 如需验证 Candidate Judge 的真实收益，配置真实 LLM 后复跑 flag on candidate report。
2. 对比真实 Judge 正常响应时的 `patch_found`、false positive、duration 和
   patch quality。
3. 若真实 Judge 无退化，再进入 Phase 3 evaluation-driven iteration。
