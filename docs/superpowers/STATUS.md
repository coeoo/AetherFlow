# Superpowers 当前状态

> 本文件是 `docs/superpowers/` 的当前接手入口。开始执行或审查 Superpowers
> 过程资产前，先读本文件，再读 active spec 和 active plan。

## 当前定位

- `docs/` 主文档仍是产品、功能和实现事实的长期入口。
- `docs/superpowers/` 保存阶段性设计、执行计划、评审和治理索引。
- 当 `docs/superpowers/` 与 `docs/` 主文档冲突时，以主文档和当前代码实现为准。

## 当前活跃事项

- Active architecture ADR: `docs/design/adr-evidence-first-patch-engine.md`
- Active execution prompt: `docs/design/codex-prompt-phase-a.md`
- Active spec: `docs/superpowers/specs/2026-04-25-cve-agent-boundary-refactor-design.md`
- Active plan: `docs/superpowers/plans/2026-04-25-cve-agent-boundary-refactor.md`
- Active phase: CVE Evidence-First Phase A pre-implementation
- Current next checkpoint: 按 active ADR 与阶段 A prompt 执行 seed evidence 基础层改造，保持 `LangGraph` 主链、`agent_nodes.py` 兼容面、`source_type="cve_seed_resolve"`、`run.phase` / `stop_reason` 与当前 acceptance 行为不变。
- Last recorded baseline: mock candidate baseline PASS，见 active plan 的 Task 2.2 Step 5。Evidence-First ADR 已采纳为当前架构方向，但阶段 A 代码尚未开始，暂无新的实现后 baseline。

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
