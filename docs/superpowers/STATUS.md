# Superpowers 当前状态

> 本文件是 `docs/superpowers/` 的当前接手入口。开始执行或审查 Superpowers
> 过程资产前，先读本文件，再读 active spec 和 active plan。

## 当前定位

- `docs/` 主文档仍是产品、功能和实现事实的长期入口。
- `docs/superpowers/` 保存阶段性设计、执行计划、评审和治理索引。
- 当 `docs/superpowers/` 与 `docs/` 主文档冲突时，以主文档和当前代码实现为准。

## 当前活跃事项

- Active architecture ADR: `docs/design/adr-evidence-first-patch-engine.md`
- Active execution prompt: `docs/design/codex-prompt-phase-a.md`（Phase A）；Phase B 由 `docs/superpowers/plans/2026-05-01-cve-evidence-first-phase-b.md` 承担；Phase C 由 trellis 任务 `.trellis/tasks/05-01-phase-c-seed-fast-path/` 承担（已 in_progress，Step 1 of 7 已完成）
- Active spec: `docs/superpowers/specs/2026-04-25-cve-agent-boundary-refactor-design.md`（boundary refactor 历史基础，仍有效）
- Active plan: `docs/superpowers/plans/2026-05-01-cve-evidence-first-phase-b.md`（Evidence-First Phase B execution plan；Plan 内 Task B.1/B.2 已合入主线，Task B.3/B.4/B.5 由 trellis 任务 `phase-b4-frontier-full-takeover` 接管完成）
- Superseded plan: `docs/superpowers/plans/2026-04-25-cve-agent-boundary-refactor.md`（Phase 0/1/2 已完成，Phase 3 Task 3.1 首轮迭代完成后被 Evidence-First ADR 接管）
- Active phase: **Evidence-First Phase C Step 1 已完成**（Step 1 of 7：`f84664f` candidate_generator reference_url 路径补 normalize-before-match + `cd50c51` 沉淀 CVE 场景层非显然约定到 `.trellis/spec/backend/cve-conventions.md`；诊断阶段翻转 phase-b4 commit `bd05f30` 当时归因——真因是 `patch_downloader.py:420` 真实网络下载 gitlab/github/kernel 抖动，与 normalize 无关）；**Phase B+ 已完成**（4 commits 合入 main：`dc48b7a` / `f0cfedb` / `9c68419` / `bd05f30`）；Phase C 剩余 Step 2-7 待续（trellis 任务 `.trellis/tasks/05-01-phase-c-seed-fast-path/` in_progress）
- Current next checkpoint: Phase C Step 2 — `backend/scripts/acceptance_browser_agent.py::_SCENARIOS` 扩 CVE-2024-38545 scenario（kernel commit；ADR 性能定位反例）；之后 Step 3+ 做 fast path feature flag + validate_seed_candidates 节点 + 图改造 + 详情页解释 + 双向 acceptance baseline
- Last recorded baseline:
  - mock-mode (rule-fallback-only profile): `backend/results/candidate-cve-evidence-first-phase-b-mock/acceptance_report.json` — CVE-2022-2509 PASS patches=6；CVE-2024-3094 PASS patches=5；与 baseline-cve-agent-boundary-refactor-mock compare `high_value_path_regressed=false / patch_quality_degraded=false`
  - 真实样本 (dashscope-stable profile): `backend/results/candidate-cve-evidence-first-phase-b-live/acceptance_report.json` — CVE-2022-2509 PASS dur=81.1s patches=6；CVE-2024-3094 PASS dur=104.5s patches=1；total 185.6s；chain_completion_rate=1.0

## 当前权威主文档入口

- `docs/00-总设计/`
- `docs/01-产品介绍/`
- `docs/04-功能设计/`
- `docs/13-界面设计/`
- `docs/04-功能设计/M103-CVE数据源与页面探索规则功能设计.md`

## 当前不可提交或需谨慎处理的产物

- `backend/results/`
- `.env.local`
- 真实 API Key、Token、Cookie、私钥
- 真实 LLM 决策日志中可能包含的敏感供应商配置

## 状态规则

- `draft`：草稿，不能直接执行。
- `active`：当前执行入口。
- `completed`：已完成并有验收或收口记录。
- `superseded`：已被后续文档替代，不能作为当前实现依据。
- `archived`：历史保留，仅用于追溯。

## 已知 superseded 资产

- `docs/superpowers/specs/2026-04-20-cve-patch-agent-graph-design.md`
  - Superseded by: `docs/superpowers/specs/2026-04-21-cve-browser-agent-design.md`
  - 原因：httpx / 混合式 Patch Agent 方案已被浏览器驱动型 Browser Agent 方案替代。

## 接手顺序

1. 读 `docs/superpowers/STATUS.md`。
2. 读 active spec。
3. 读 active plan 的当前 phase 和最近完成的 task。
4. 核对 `git status --short --branch` 和相关 diff。
5. 检查 `docs/superpowers/REVIEW_CHECKLIST.md`，先审查 plan 是否仍然可执行。
6. 执行前确认不可提交产物和验证命令。

## 更新规则

- active spec / active plan 变化时，必须更新本文件。
- 阶段完成时，必须更新 `Last recorded baseline` 或说明未验证原因。
- 新增关键架构决策时，必须同步更新 `docs/superpowers/DECISIONS.md`。
- 完成阶段性验收时，优先写入 `docs/superpowers/reviews/`，再更新本文件。
