# 2026-04-28 Session024 - CVE Candidate Judge 收口验证准备

状态: ✅ 已完成

## 做了什么

- 复核当前仓库阶段，确认 CVE Agent Boundary Refactor 已处于 Phase 2 收口验证点：
  - Phase 1 已通过 mock candidate baseline。
  - Phase 2 Task 2.1 已完成 Candidate Judge 默认关闭接口。
  - Phase 2 Task 2.2 已在 feature flag 下接入主链。
- 同步 AI 接手说明，避免后续会话误判为“Candidate Judge 尚未接入主链”。
- 按安全约束检查本地 LLM 配置加载状态，只输出 `set/missing`，未打印真实 API Key。
- 在真实 LLM 配置存在的前提下，单独复跑 `CVE-2022-2509` flag on candidate report，
  先复现 Candidate Judge provider 非 JSON 响应，再修正本地 `LLM_BASE_URL` 并验证
  `candidate_judge` 决策正常写入。

## 本次更新的文档

- `docs/09-AI开发日志/README_AI使用说明.md` — 更新 CVE Patch Agent 接手要点，明确 Task 2.2 已完成，下一步是真实 Judge 收口验证。
- `docs/09-AI开发日志/日志/2026-04-28_Session024_CVE_CandidateJudge收口验证准备.md` — 记录本次阶段口径同步和下一步验证边界。

## 本次更新的代码

- 无。

## 关键决策

- 当前不直接进入 Phase 3；先完成 Phase 2 收口验证。
- Candidate Judge 真实收益判断必须基于 flag on candidate report，而不是只看 fake judge 单测或 provider 非 JSON 降级路径。
- `backend/results/` 仍作为运行证据目录，默认不提交。

## 问题与处理

- 问题：`docs/09-AI开发日志/README_AI使用说明.md` 仍停留在 Task 2.1，写着 Candidate Judge 尚未接入主链。
- 处理：将接手口径更新为 Task 2.2 已完成，并把下一步收敛到真实 LLM 下的 flag on 收口验证。
- 问题：第一次运行 acceptance 时缺少 `DATABASE_URL/AETHERFLOW_DATABASE_URL`。
- 处理：按计划文档要求显式传入 `--database-url postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_baseline_20260425`，不依赖 shell 环境变量。
- 问题：`CVE-2022-2509` flag on 运行虽然 `PASS`，但 Candidate Judge provider 返回 `text/html` 非 JSON。
- 处理：脱敏检查发现 `LLM_BASE_URL` path 为 `/`，而代码会拼接 `/chat/completions`；
  按 `.env.example` 的 OpenAI-compatible base URL 约定，将本地 `LLM_BASE_URL` 修正为
  `/v1` base URL，并保留备份 `.env.local.bak.20260428155100`。

## 本次验证

配置加载检查：

```text
LLM_BASE_URL=set
LLM_API_KEY=set
LLM_DEFAULT_MODEL=set
LLM_TIMEOUT_SECONDS=set
LLM_WALL_CLOCK_TIMEOUT_SECONDS=set
LLM_RETRY_ATTEMPTS=set
LLM_REASONING_EFFORT=set
AETHERFLOW_CVE_CANDIDATE_JUDGE_ENABLED=false
```

第一次真实 Judge flag on 单场景：

```bash
AETHERFLOW_CVE_CANDIDATE_JUDGE_ENABLED=true PYTHONPATH=backend timeout 180s ./.venv/bin/python -m scripts.acceptance_browser_agent \
  --cve CVE-2022-2509 \
  --profile rule-fallback-only \
  --mock-mode llm-timeout-forced \
  --database-url postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_baseline_20260425 \
  --results-dir backend/results/candidate-cve-agent-boundary-refactor-phase2-realjudge-flag-on-cve-2022-2509
```

结果：

```text
status=succeeded
acceptance_verdict=PASS
patch_found=true
stop_reason=patches_downloaded
duration_seconds=23.5
selected_patch_types=["gitlab_commit_patch"]
patch_failure_kinds=[]
```

对比历史 flag off report：

```text
patch_quality_degraded=false
high_value_path_regressed=false
navigation_path_changed=true
final_patch_urls.changed=false
```

但本次不能视为 Candidate Judge 正常收益验证通过，原因是：

```text
candidate_judge_provider_non_json_response: status=200, content_type=text/html; charset=utf-8
```

数据库 search decision 复核结果：该 run 只记录了 `rule_fallback` 决策，没有正常写入
`candidate_judge` 决策。

修复后脱敏配置检查：

```text
LLM_BASE_URL=set
scheme=https
host_kind=remote
path=/v1
path_has_v1=true
model=set
key=set
```

修复后最小 Candidate Judge 真实调用：

```text
candidate_key_matches=true
verdict=accept
confidence_type=float
reason_summary=set
rejection_reason=empty
```

修复后 `CVE-2022-2509` flag on 单场景：

```bash
AETHERFLOW_CVE_CANDIDATE_JUDGE_ENABLED=true PYTHONPATH=backend timeout 180s ./.venv/bin/python -m scripts.acceptance_browser_agent \
  --cve CVE-2022-2509 \
  --profile rule-fallback-only \
  --mock-mode llm-timeout-forced \
  --database-url postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_baseline_20260425 \
  --results-dir backend/results/candidate-cve-agent-boundary-refactor-phase2-realjudge-fixed-flag-on-cve-2022-2509
```

结果：

```text
status=succeeded
acceptance_verdict=PASS
patch_found=true
stop_reason=patches_downloaded
duration_seconds=21.02
selected_patch_types=["gitlab_commit_patch"]
patch_failure_kinds=[]
```

数据库 search decision 复核结果：

```text
decision_type=candidate_judge
validated=true
selected_candidate_keys=["https://gitlab.com/gnutls/gnutls/-/commit/ce37f9eb265dbe9b6d597f5767449e8ee95848e2"]
result_count=1
verdicts=["accept"]
```

对比历史 flag off report：

```text
patch_quality_degraded=false
high_value_path_regressed=false
navigation_path_changed=true
final_patch_urls.changed=false
```

修复后 `CVE-2024-3094` flag on 单场景：

```bash
AETHERFLOW_CVE_CANDIDATE_JUDGE_ENABLED=true PYTHONPATH=backend timeout 180s ./.venv/bin/python -m scripts.acceptance_browser_agent \
  --cve CVE-2024-3094 \
  --profile rule-fallback-only \
  --mock-mode llm-timeout-forced \
  --database-url postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_baseline_20260425 \
  --results-dir backend/results/candidate-cve-agent-boundary-refactor-phase2-realjudge-fixed-flag-on-cve-2024-3094
```

结果：

```text
status=succeeded
acceptance_verdict=PASS
patch_found=true
stop_reason=patches_downloaded
duration_seconds=45.99
selected_patch_types=["github_commit_patch"]
patch_failure_kinds=[]
```

数据库 search decision 复核结果：

```text
decision_type=candidate_judge
validated=true
result_count=5
verdicts=["accept", "accept", "accept", "accept", "accept"]
```

对比历史 flag off report：

```text
patch_quality_degraded=false
high_value_path_regressed=false
navigation_path_changed=false
final_patch_urls.changed=true
```

说明：`final_patch_urls.changed=true` 仅为 GitHub commit patch URL 顺序变化，patch type
仍为 `github_commit_patch`，未触发 patch quality 退化。

## 下次计划

1. 进入 Phase 3 evaluation-driven iteration。
2. 首轮目标选择 `non_maintained_or_no_public_patch`，先拆分“系统失败”和“可接受的无公开补丁/非维护范围”验收语义。
3. 每次后续改动必须先填写目标 `failure_category`、影响样本、预期改善、风险、验证命令和回滚方式。
4. 暂不扩大样本规模；若真实样本暴露新 P1 failure category，再按小样本、高代表性的方式补充验收。

## Phase 3 首轮执行结果

- 已完成 `non_maintained_or_no_public_patch` 的最小 acceptance 分类切片；随后已继续拆为
  `no_public_patch` 与 `non_maintained_component`，见下一节。
- 变更范围仅限：
  - `backend/scripts/acceptance_browser_agent.py`
  - `backend/tests/test_acceptance_browser_agent.py`
- 首轮临时语义：
  - `status=failed`
  - `verdict=PASS`
  - `stop_reason=no_patch_candidates`
  - `patch_found=false`
  - 归类为 `failure_category=non_maintained_or_no_public_patch`
- 不改变导航主链、Candidate Judge、patch downloader 或真实验收样本。
- 相关验证：
  - `timeout 60s ./.venv/bin/python -m pytest backend/tests/test_acceptance_browser_agent.py::test_no_patch_candidate_pass_is_classified_as_non_maintained_or_no_public_patch -q`
    - `1 passed`
  - `timeout 60s ./.venv/bin/python -m pytest backend/tests/test_acceptance_browser_agent.py backend/tests/test_cve_agent_graph.py -q`
    - `72 passed, 35 skipped`
- 注：首轮临时测试名已在二次拆分中替换为更细粒度的 no-public-patch 与 WordPress/WPScan/Trac
  样本测试。

## Phase 3 首轮二次拆分结果

- 根据真实样本证据继续拆分 `non_maintained_or_no_public_patch`：
  - `no_public_patch`
  - `non_maintained_component`
- 真实样本依据：
  - `backend/results/live-20cve-deepseek-v4-pro-20260424T1515Z/cve-2025-13820/acceptance_report.json`
    - `status=failed`
    - `verdict=PASS`
    - `stop_reason=stop_search`
    - `patch_found=false`
    - `navigation_path` 包含 `wpscan.com/vulnerability/...` 与 GitHub Advisory
    - 新归类：`failure_category=non_maintained_component`
  - `backend/results/live-20cve-deepseek-v4-pro-20260424T1515Z/cve-2025-14428/acceptance_report.json`
    - `status=failed`
    - `verdict=PASS`
    - `stop_reason=stop_search`
    - `patch_found=false`
    - `navigation_path` 包含 `plugins.trac.wordpress.org/changeset/...` 与 Wordfence 来源
    - 新归类：`failure_category=non_maintained_component`
  - `backend/results/live-retest-CVE-2026-0544-cvss-filter-deepseek-v4-pro/acceptance_report.json`
    - `status=failed`
    - `verdict=PASS`
    - `stop_reason=no_patch_candidates`
    - `patch_found=false`
    - `navigation_path` 只指向 NVD / CVE.org / VulDB 类信息页
    - 新归类：`failure_category=no_public_patch`
- 变更范围仍限于 acceptance 报告分类和对应单元测试；未改浏览器导航、Candidate Judge 或 patch downloader。
- 本轮新增测试先红后绿：
  - `test_wordpress_wpscan_no_patch_pass_is_classified_as_non_maintained_component`
  - `test_wordpress_trac_no_patch_pass_is_classified_as_non_maintained_component`
  - `test_no_patch_candidate_pass_is_classified_as_no_public_patch`

## 遗留风险

- `CVE-2022-2509` 与 `CVE-2024-3094` 已验证真实 Judge 正常返回并写入 `candidate_judge` 决策；后续风险转为 Phase 3 中具体 failure category 的定向迭代风险。
