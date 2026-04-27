# 2026-04-27 Session021 - CVE Agent 边界重构 Phase1 验收收口

状态: ✅ 已完成

## 做了什么

- 接手 CVE Patch Agent Boundary Refactor 后续任务，复核仓库状态、开发服务状态和隔离数据库。
- 通过 `scripts/dev_start.sh` 启动本地开发会话，确认 `infra-postgres-1` 恢复健康，复用隔离库 `aetherflow_baseline_20260425`。
- 复跑 Phase 1 Task 1.6 mock candidate baseline，确认原计划中的 `timeout 60s` 不适合 `acceptance_browser_agent --all`：
  - `--all` 会串行执行两个真实浏览器场景。
  - `llm-timeout-forced` 只强制 LLM 导航调用超时，仍会执行真实页面抓取、规则 fallback、patch 下载、数据库写入和报告生成。
  - 历史 baseline 总耗时为 `57.32s`，距离 60 秒只有极小余量，容易被真实页面加载波动击穿。
- 组织只读代码分析和子代理分析，确认本轮超时不是 Phase 1 引入额外 Agent 循环：
  - `chain_count` 未增加。
  - `search_nodes_count` 未增加。
  - `rule_fallback_count` 未增加。
  - `navigation_path` 未增加。
  - 主要波动来自真实页面加载耗时和串行场景累计。
- 经维护者确认，将 Task 1.6 的 acceptance baseline 外层超时调整为 `180s`，与报告字段 `all_under_3_minutes` 一致。
- 使用 `timeout 180s` 生成正式 candidate report，并完成 baseline/candidate compare。
- 更新边界重构计划、AI 接手说明，并记录本次开发日志。

## 本次更新的文档

- `docs/superpowers/plans/2026-04-25-cve-agent-boundary-refactor.md`
  - 将 Task 1.6 mock candidate baseline 外层超时从 `60s` 调整为 `180s`。
  - 记录 candidate baseline 摘要、compare 结论和回归测试结果。
  - 标记 Task 1.6 已完成，说明 Phase 2 可以进入 Task 2.1。
  - 在 Execution Notes 中补充 acceptance baseline 与普通 pytest 的 timeout 语义差异。
- `docs/09-AI开发日志/README_AI使用说明.md`
  - 更新到 v1.9。
  - 补充 Phase 1 已完成、Phase 2 下一步和 `backend/results/` 不提交约束。
  - 明确真实浏览器 acceptance `--all` 使用 `timeout 180s`，普通 pytest 仍使用 `timeout 60s`。
- `docs/09-AI开发日志/日志/2026-04-27_Session021_CVE_Agent边界重构Phase1验收收口.md`
  - 新增本次开发日志。

## 本次更新的代码

- 无。

## 关键决策

- 不把 `timeout 60s` 机械套用到真实浏览器 acceptance `--all`。
- 对真实浏览器 baseline，使用 `timeout 180s` 作为外层保护，与 `all_under_3_minutes` 验收语义一致。
- 对普通 pytest、轻量脚本和不访问真实浏览器网络链路的验证命令，继续使用 `timeout 60s`。
- 不修改 Phase 1 业务代码；当前证据显示 Phase 1 边界拆分没有引入明显行为退化。
- 不提交 `backend/results/`，只记录 report 路径和关键摘要。

## 问题与处理

- 问题：首次检查时 Postgres 容器停止，宿主机 `127.0.0.1:55432` 连接被拒绝。
  - 处理：经维护者确认后执行 `bash scripts/dev_start.sh`，开发服务和 Postgres 恢复运行。
- 问题：按原计划使用 `timeout 60s` 运行 candidate `--all`，进程被外层 timeout 杀掉，未生成正式 candidate report。
  - 处理：只读分析代码和结果，确认 `--all` 串行执行且报告在所有场景结束后统一写入；经维护者确认后改用 `timeout 180s` 复跑。
- 问题：compare 显示 `patch_url_changed=true`。
  - 处理：确认变化主要是 patch URL 输出顺序变化；两个场景均无 `patch_quality_degraded`，无 `high_value_path_regressed`，最佳 patch 类型和优先级保持不变。

## 验证结果

正式 candidate baseline：

```bash
PYTHONPATH=backend timeout 180s ./.venv/bin/python -m scripts.acceptance_browser_agent \
  --all \
  --mock-mode llm-timeout-forced \
  --profile rule-fallback-only \
  --database-url postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_baseline_20260425 \
  --results-dir backend/results/candidate-cve-agent-boundary-refactor-phase1-mock
```

结果：

```text
scenario_count: 2
execution_outcomes: {"succeeded": 2}
acceptance_verdicts: {"PASS": 2}
failure_categories: {"None": 2}
patch_found_count: 2
chain_completion_rate: 1.0
total_duration_seconds: 58.79
all_under_3_minutes: true
```

baseline/candidate compare：

```bash
PYTHONPATH=backend timeout 60s ./.venv/bin/python -m scripts.acceptance_browser_agent \
  --baseline-report backend/results/baseline-cve-agent-boundary-refactor-mock/acceptance_report.json \
  --candidate-report backend/results/candidate-cve-agent-boundary-refactor-phase1-mock/acceptance_report.json
```

结果摘要：

```text
CVE-2022-2509:
  patch_quality_degraded: false
  high_value_path_regressed: false
  navigation_path_changed: false
  more_rule_fallback: false

CVE-2024-3094:
  patch_quality_degraded: false
  high_value_path_regressed: false
  navigation_path_changed: false
  more_rule_fallback: false
```

组合回归：

```bash
timeout 60s ./.venv/bin/python -m pytest \
  backend/tests/test_cve_agent_graph.py \
  backend/tests/test_cve_agent_policy.py \
  backend/tests/test_browser_agent_integration.py \
  backend/tests/test_acceptance_browser_agent.py \
  backend/tests/test_cve_agent_skills.py \
  backend/tests/test_cve_agent_decisions.py \
  backend/tests/test_cve_agent_evidence.py \
  -q
```

结果：

```text
102 passed, 40 skipped in 0.55s
```

补充模块测试：

```bash
timeout 60s ./.venv/bin/python -m pytest \
  backend/tests/test_cve_agent_search_tools.py \
  backend/tests/test_browser_agent_llm.py \
  -q
```

结果：

```text
27 passed in 3.76s
```

## 下次计划

1. 进入 Phase 2 Task 2.1：引入 Candidate Judge 接口但默认关闭。
2. 继续保持 `agent_nodes.py` facade 兼容入口，不破坏现有 monkeypatch 路径。
3. Candidate Judge 接入前先写 feature flag 和 schema 测试，确保默认关闭时 Phase 1 行为不变。

## 遗留风险

- `backend/results/` 中保留本地验收产物，默认不提交。
- acceptance baseline 仍依赖真实页面和 patch URL，运行时间可能受网络波动影响；后续如需稳定 CI，应考虑 partial report 或更强 mock 层，而不是压低外层 timeout。
