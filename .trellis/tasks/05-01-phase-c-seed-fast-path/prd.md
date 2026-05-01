# Phase C — seed candidate fast path（受控短路）

## Goal

引入受控短路（feature flag 默认关闭）：高置信 seed-derived candidate 在 build_initial_frontier 之后被验证可下载时，跳过 Browser Agent 探索直接 finalize；保留完整 evidence / decision / artifact / source_trace 与详情页解释能力。本任务是 Evidence-First 架构 ADR §阶段 C 的兑现，目标是把 phase-b4 已就绪的 fix_commit 多 host 候选转化为可量化的 duration 节省（CVE-2024-38545 类样本预期 27s → <5s），同时保证 flag=false 与 phase-b4 baseline 完全等价、CVE-2022-2509 类样本不被误短路。

## What I already know

### 维护者批准状态
用户作为维护者在 phase-b4 brainstorm 时已批准跨过 Plan B.5 的 "不新增 validate_seed_candidates / 不引入 fast path flag" 停止条件，本会话连续推进 Phase C。

### phase-b4 已就绪的基础（4 commits）
- `dc48b7a`：candidate_scoring 接管 type-only priority；reference_matcher 委托；KNOWN_PATCH_TYPES 公开常量
- `f0cfedb`：candidate_generator 多 host fix_commit 扩展（GitHub/GitLab/kernel/Bitbucket/Gitee/AOSP）
- `9c68419`：build_initial_frontier 仅在 reference_url evidence 上接管 candidate_generator；fix_commit evidence 派生候选保留在 `state["patch_candidates"]`，**等本任务消费**
- `bd05f30`：标注 candidate_generator reference_url 归一化边界为 Phase C 前置

### phase-b4 已建立的 baseline
- mock-mode (rule-fallback-only profile)：CVE-2022-2509 PASS patches=6；CVE-2024-3094 PASS patches=5
- 真实样本 (dashscope-stable profile)：CVE-2022-2509 PASS dur=81.1s patches=6；CVE-2024-3094 PASS dur=104.5s patches=1
- 报告路径：`backend/results/candidate-cve-evidence-first-phase-b-{mock,live}/`

### Phase C 目标契约（来自 ADR §阶段 C）
- feature flag `AETHERFLOW_CVE_SEED_FAST_PATH_ENABLED=false` 默认关闭
- 新增节点 `validate_seed_candidates_node` 在 build_initial_frontier 之后判断是否短路
- 短路时写完整 evidence / decision / artifact / source_trace（不生成空壳详情页）
- 详情页能解释"为什么没走 Browser Agent"
- flag=false 行为与 Phase B+ 完全一致
- flag=true CVE-2024-38545 类样本短路成功
- flag=true CVE-2022-2509 类样本仍走 Browser Agent
- 短路结果 final_patch_urls 与完整流程一致
- 短路结果保留可解释的 source_traces / decision_history

### 来自 phase-b4 的前置事项（codex review 留尾）
- **Q7**：candidate_generator reference_url 路径补 `normalize_frontier_url` + acceptance 回归保护（phase-b4 实施时反向退化未定位根因）
- **CVE-2024-38545 acceptance scenario 缺失**：`backend/scripts/acceptance_browser_agent.py:_SCENARIOS` 仅含 CVE-2022-2509 / CVE-2024-3094，flag=true 短路成功验证需要先扩 scenario
- **patch_candidates 幽灵候选收口**（codex review #2）：state["patch_candidates"] 由 resolve_seeds_node 写入但无下游消费 — 本任务正是显式消费时机
- **每 evidence 单独调 generator 的临时实现**（codex review #3）：build_initial_frontier 当前为合并 evidence_source_count 每 evidence 单调 generate_candidates，可一并优化

### 关键代码入口
- `backend/app/cve/agent_graph.py`：图拓扑（要加节点 + 条件边）
- `backend/app/cve/agent_nodes.py`：现有节点；新增 `validate_seed_candidates_node`
- `backend/app/cve/agent_state.py`：AgentState 字段（可能要加 fast_path_decision）
- `backend/app/config.py`：feature flag 加载
- `backend/app/cve/decisions/fallback.py:287` `>=90` 高质量阈值（fast path 的 trigger 借鉴）
- `backend/app/cve/detail_service.py`：详情页投影（"为什么没走 Browser Agent" hook）
- `frontend/src/features/cve/types.ts` + `CVERunDetailPage.tsx`（前端解释展示）
- `backend/scripts/acceptance_browser_agent.py:_SCENARIOS`（acceptance 扩 CVE 名单）

## Assumptions (temporary)

1. fast path trigger 的核心信号是 candidate_generator 输出的 PatchCandidate 中 `confidence == "high"` + `patch_type ∈ HIGH_PRIORITY_UPSTREAM_PATCH_TYPES`（github/gitlab/kernel/bitbucket/gitee/aosp commit_patch）。
2. fast path 不绕过 download_and_validate —— 仍跑下载验证（保 patch 真实可达），仅跳过 fetch_next_batch / extract_links_and_candidates / agent_decide 阶段。这能保 final_patch_urls 与完整流程一致，避免空壳详情页。
3. 前置 Q7（normalize-before-match）应在 Phase C 任务内补齐，否则 fast path 的 reference_url evidence 路径不与 baseline 等价。
4. CVE-2024-38545 必须扩到 acceptance scenarios，否则 flag=true 短路成功无法自动回归。
5. patch_candidates 幽灵候选收口可以伴随 validate_seed_candidates_node 的实现自然完成（节点显式消费 state["patch_candidates"]），不需独立 commit。

## Open Questions

（Q1-Q5 均已收敛，见 Decision Log；如实施期出现新边界再补。）

## Decision Log

**Q1 → 选项 A（前置纳入本任务，串行 2 前置 + Phase C 主体）**

- Step 1：补 candidate_generator reference_url 路径 normalize_frontier_url（baseline 等价的真正补丁）+ 完整 acceptance 回归保护（mock-mode + 真实样本双重验证）
- Step 2：扩 acceptance script `_SCENARIOS` 加 CVE-2024-38545（kernel commit；定义验收条件：flag=false 走 Browser Agent / flag=true 短路成功）
- Step 3+：Phase C 主体（feature flag、validate_seed_candidates_node、图改造、详情页解释、双向 acceptance）
- 预估 6-7 个 commits，同一任务内交付

**Q2 → 选项 B（patch_type 白名单 + confidence==high）**

- 短路 trigger 条件（**全部满足**才短路）：
  - `PatchCandidate.patch_type` 在 HIGH_PRIORITY_UPSTREAM_PATCH_TYPES（github_commit_patch / gitlab_commit_patch / kernel_commit_patch / bitbucket_commit_patch / gitee_commit_patch / aosp_commit_patch）
  - `PatchCandidate.confidence == "high"`
- 这正好对应 phase-b4 设计中的"可靠证据"语义：fix_commit evidence 强制 confidence=high；reference_url evidence 仅在 semantic_tag ∈ {"patch", "Patch", "FIX"} 时 confidence=high
- 不接入 candidate_scoring.total 阈值（避免与 fallback.py:287 的 type-only `>=90` 阈值语义冲突，引入新调优变量）
- 不要求 evidence_source_count 多源验证（保留 fix_commit evidence 单源高置信短路路径，CVE-2024-38545 类样本受益）
- 候选来源：consume `state["patch_candidates"]`（resolve_seeds_node 产出）+ `state["direct_candidates"]`（build_initial_frontier reference_url evidence 派生）的并集，按 canonical_key 去重

**Q3 → 选项 B（短路 → download；下载失败时回退到 Browser Agent）**

- LangGraph 流程：
  - flag=false：图拓扑保持不变（`build_initial_frontier → fetch_next_batch → ...`）
  - flag=true 时：`build_initial_frontier → validate_seed_candidates`：
    - **短路 trigger 命中**：`validate_seed_candidates → download_and_validate`；下载成功 → finalize_run；下载失败 → 回退到 fetch_next_batch 走完整 Browser Agent 流程（兜底）
    - **不命中**：`validate_seed_candidates → fetch_next_batch`，行为与 flag=false 等价
- 兜底依赖：download_and_validate 已有"未下载完候选时 next_action=fetch_next_batch"的逻辑（agent_nodes.py:1102-1113）；fast path 失败回退路径与现有 next_action 机制天然兼容
- 这与 ADR §阶段 C "短路时写完整 evidence / decision / artifact / source_trace" 一致；download 失败时 patch artifact 不空壳（对网络/mirror 403 等可恢复失败有兜底，对长尾复杂样本仍可激活 Browser Agent 探索）

**Q4 → 选项 A（summary_json runtime_kind 新表识 + 前端徽章）**

- 后端 `summary_json` 新增字段：
  - `runtime_kind: "patch_agent_fast_path"`（短路时；非短路保持现有 `"patch_agent_graph"`）
  - `fast_path_reason: str`（人类可读说明，如 "高置信 GitHub commit_patch 候选；跳过浏览器探索阶段"）
  - `fast_path_skipped_phases: list[str]`（如 `["fetch_next_batch", "extract_links_and_candidates", "agent_decide"]`）
- `detail_service._is_agent_run` 已识别 `runtime_kind in {"patch_agent", "patch_agent_graph"}`，需扩 `"patch_agent_fast_path"` 视作 Agent run
- 前端 `frontend/src/features/cve/types.ts` `CVERunSummary` 加新字段；`CVERunDetailPage.tsx` 在 verdict hero 区域加 "Fast Path" 徽章 + tooltip 显示 fast_path_reason
- TraceTimeline 组件按 `fast_path_skipped_phases` 显式标注被跳过的阶段（灰色 + "fast path 跳过" 提示）
- 不动 cve_search_decisions 表（短路决策仍由 validate_seed_candidates_node 写一条 `decision_type="fast_path_short_circuit"` 记录到 `cve_search_decisions`，复用现有审计链路）

**Q5 → 选项 A（7 commit 细拆）**

| commit | 标题 | 文件 |
|---|---|---|
| 1 | `重构(cve): candidate_generator reference_url 路径补 normalize-before-match` | candidate_generator.py + test_candidate_generator.py |
| 2 | `测试(cve): acceptance script 扩展 CVE-2024-38545 scenario` | scripts/acceptance_browser_agent.py + tests |
| 3 | `功能(cve): 引入 fast path feature flag 与 validate_seed_candidates 节点实现` | config.py + agent_state.py + agent_nodes.py（新增 validate_seed_candidates_node）+ tests |
| 4 | `功能(cve): LangGraph 加 fast path 条件边与下载失败兜底回退` | agent_graph.py + agent_nodes.py（download_and_validate 调整）+ test_cve_agent_graph.py |
| 5 | `功能(cve): summary_json runtime_kind=patch_agent_fast_path 详情页投影` | finalize_run_node + detail_service.py + test_cve_detail_service.py |
| 6 | `功能(frontend): CVERunDetailPage 加 Fast Path 徽章与 TraceTimeline 跳过表示` | frontend/src/features/cve/types.ts + CVERunDetailPage.tsx + TraceTimeline.tsx + test |
| 7 | `测试(cve): Phase C 双向 acceptance baseline 验证` | docs/superpowers/plans/2026-05-01-cve-evidence-first-phase-c.md + acceptance 报告引用 |

## Requirements

**Step 1（commit 1）**：candidate_generator reference_url 路径补 normalize-before-match
- 在 `generate_candidates` reference_url 分支调 `normalize_frontier_url(ev.url) or ev.url` 再 `match_reference_url`
- 排查 phase-b4 时间窗口内未定位的反向退化根因（dump CVE-2022-2509 受影响的 reference URL 集合 + canonical_key 漂移路径）
- 单元测试加 fragment / 多余空白 / openwall http→https 三类回归
- mock-mode acceptance + 真实样本 acceptance 与 phase-b4 baseline 完全等价
- bd05f30 中的 Q7 边界注释清除

**Step 2（commit 2）**：acceptance script 扩展 CVE-2024-38545 scenario
- `_SCENARIOS` 加 CVE-2024-38545 entry（kernel commit；ADR 性能定位反例）
- `_determine_verdict` 新增 CVE-2024-38545 验收条件：
  - flag=false 时：期望走 Browser Agent（visited_page_roles 含 tracker_page / commit_page）
  - flag=true 时：期望短路（fast_path 信号 + duration 显著降低）
- `--cve` 参数支持 CVE-2024-38545

**Step 3（commit 3）**：feature flag + validate_seed_candidates_node 实现
- `app/config.py` Settings 加 `cve_seed_fast_path_enabled: bool = False`，env var `AETHERFLOW_CVE_SEED_FAST_PATH_ENABLED`
- `app/cve/agent_state.py` AgentState 加 `fast_path_decision: dict | None = None`（写入 fast_path_reason / candidate / skipped_phases）
- 新增 `validate_seed_candidates_node`：
  - 读 settings，flag=false 时 stop_reason=None / next_action=expand_frontier 直接传出
  - flag=true 时遍历 state["direct_candidates"] + state["patch_candidates"]，按 canonical_key 去重，找 trigger 命中候选（patch_type ∈ HIGH_PRIORITY_UPSTREAM_PATCH_TYPES 且 confidence==high）
  - 命中：state["fast_path_decision"] = {"candidate_url", "patch_type", "fast_path_reason", "skipped_phases"}；写 cve_search_decisions 一条 `decision_type="fast_path_short_circuit"` (input=candidate context, output=trigger 命中说明)；next_action="try_candidate_download"；selected_candidate_keys=[命中 candidate canonical_key]
  - 不命中：next_action=expand_frontier，state["fast_path_decision"] = None
- 单元测试：trigger 边界（patch_type 不在白名单 / confidence!=high / direct_candidates 与 patch_candidates 并集去重）

**Step 4（commit 4）**：LangGraph 加 fast path 条件边与下载失败兜底回退
- `agent_graph.py` 修改：`build_initial_frontier → validate_seed_candidates`；`validate_seed_candidates` 用 `_route_after_validate_seed_candidates`：
  - next_action="try_candidate_download" → download_and_validate
  - next_action="expand_frontier" → fetch_next_batch
- `download_and_validate_node` 调整：当 state["fast_path_decision"] 命中且下载成功 → next_action=finalize_run；下载失败 → next_action=fetch_next_batch（兜底回退到 Browser Agent）
- 图测试：flag=false 行为不变；flag=true 短路命中 → download → finalize；flag=true 命中 + 下载失败 → fetch_next_batch；flag=true 不命中 → fetch_next_batch

**Step 5（commit 5）**：summary_json runtime_kind 详情页投影
- `finalize_run_node` 当 state["fast_path_decision"] 非空时：
  - summary_json["runtime_kind"] = "patch_agent_fast_path"
  - summary_json["fast_path_reason"] = state["fast_path_decision"]["fast_path_reason"]
  - summary_json["fast_path_skipped_phases"] = state["fast_path_decision"]["skipped_phases"]
- `detail_service._is_agent_run` 加 "patch_agent_fast_path" 识别
- detail_service get_cve_run_detail 在 summary 中透出 fast_path_reason / fast_path_skipped_phases
- 测试：test_cve_detail_service 加 fast path summary 投影回归

**Step 6（commit 6）**：前端 Fast Path 徽章与 TraceTimeline 跳过表示
- `frontend/src/features/cve/types.ts::CVERunSummary` 加 `runtime_kind` / `fast_path_reason` / `fast_path_skipped_phases` 字段
- `CVERunDetailPage.tsx` verdict hero 区域：`runtime_kind === "patch_agent_fast_path"` 时显示 "Fast Path" 徽章 + tooltip
- `CVETraceTimeline.tsx` 按 fast_path_skipped_phases 标注跳过阶段（灰色 + "fast path 跳过" 提示）
- 前端测试：cve-pages.test.tsx 加 Fast Path 徽章渲染回归

**Step 7（commit 7）**：双向 acceptance baseline 验证
- 跑 mock-mode + flag=false vs phase-b4 baseline → 等价
- 跑 mock-mode + flag=true vs 新建 fast_path baseline → 等价
- 跑真实样本 + flag=false vs phase-b4 live baseline → 等价（CVE-2022-2509 / CVE-2024-3094 / CVE-2024-38545）
- 跑真实样本 + flag=true：CVE-2024-38545 短路成功 + duration 显著降低 + final_patch_urls 与 flag=false 等价；CVE-2022-2509 仍走 Browser Agent
- 收口文档：`docs/superpowers/plans/2026-05-01-cve-evidence-first-phase-c.md`

## Acceptance Criteria

- [ ] **Step 1**：candidate_generator reference_url 路径 normalize-before-match 补齐；mock-mode + 真实样本 acceptance 与 phase-b4 baseline 完全等价
- [ ] **Step 2**：CVE-2024-38545 已扩入 acceptance _SCENARIOS；flag=false / flag=true 验收条件分别定义
- [ ] **Step 3**：feature flag 加载正常；validate_seed_candidates_node trigger 命中边界单元测试 PASS
- [ ] **Step 4**：图测试 flag=false 行为不变；flag=true 短路命中 + 下载成功 → finalize；flag=true 短路命中 + 下载失败 → fetch_next_batch 兜底；flag=true 不命中 → fetch_next_batch
- [ ] **Step 5**：summary_json runtime_kind / fast_path_reason / fast_path_skipped_phases 字段；detail_service 投影；test_cve_detail_service PASS
- [ ] **Step 6**：前端 Fast Path 徽章 + TraceTimeline 跳过表示；frontend test PASS
- [ ] **Step 7**：双向 acceptance baseline 全 PASS：
  - flag=false + mock-mode 与 phase-b4 baseline 等价
  - flag=false + 真实样本 与 phase-b4 live 等价
  - flag=true + CVE-2022-2509 仍走 Browser Agent（visited_page_roles 含 tracker / commit）
  - flag=true + CVE-2024-38545 短路成功（runtime_kind=patch_agent_fast_path + duration 显著低于 baseline + final_patch_urls 等价）
- [ ] `make backend-test` + frontend test 全量回归 PASS

## Definition of Done

- 单元测试 + 图测试 + acceptance（mock-mode + 真实样本双 flag 状态）三层验证全 PASS
- 非本任务 dirty 文件未混入 commit
- 7 个独立中文三段式 commit
- 详情页投影变更同步前端 types.ts + CVERunDetailPage 测试
- Phase C 收口文档 `docs/superpowers/plans/2026-05-01-cve-evidence-first-phase-c.md` 写完

## Requirements (evolving)

- 待 Q1-Q5 收敛后展开。

## Acceptance Criteria (evolving)

- [ ] flag=false 行为与 phase-b4 baseline 完全一致（mock-mode + 真实样本双层 acceptance）
- [ ] flag=true 在 CVE-2024-38545 类样本上短路成功（duration 显著降低；patch 仍下载成功）
- [ ] flag=true 在 CVE-2022-2509 类样本上仍走 Browser Agent（visited_page_roles 包含 tracker / mailing / commit）
- [ ] 短路结果 final_patch_urls 集合与完整流程等价
- [ ] 短路结果保留可解释的 source_traces / decision_history / search_graph
- [ ] 详情页能展示 "为什么没走 Browser Agent" 的解释字段
- [ ] candidate_generator reference_url 路径 normalize-before-match 补齐 + acceptance 回归 PASS
- [ ] CVE-2024-38545 acceptance scenario 已扩入 _SCENARIOS

## Definition of Done

- 单元测试 + 图测试 + acceptance（mock-mode + 真实样本双 flag 状态）三层验证全 PASS
- 非本任务 dirty 文件未混入 commit
- 中文三段式 commit message
- 详情页投影变更同步前端 types.ts + CVERunDetailPage 测试

## Out of Scope (explicit)

- 不修改 patch_downloader 主下载逻辑
- 不改 Candidate Judge 默认关闭策略
- 不接入 candidate_scoring.total（仍用 type-only priority + 高置信白名单作 trigger）
- 不引入新外部依赖
- 不扩到 fix_version / advisory evidence 的 fast path（仅 fix_commit + reference_url 高置信候选）

## Technical Notes

- Phase C 完工后写 `docs/superpowers/plans/2026-05-01-cve-evidence-first-phase-c.md` 收口（参照 phase-b 模板）
- ADR §阶段 D （Browser Agent 精细化 + no_patch_reason 分类）留作后续

## Research References

（待 brainstorm 中按需补充）
