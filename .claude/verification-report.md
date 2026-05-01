---
name: 计划审查报告 — boundary-refactor plan
description: 对 docs/superpowers/plans/2026-04-25-cve-agent-boundary-refactor.md 的收敛审查
created_at: 2026-05-01
reviewer: Claude Code（独立判断）+ Codex（客观对照，session 019de154-733e-7911-8deb-af5bd0979ed9）
---

# 计划审查报告：CVE Agent Boundary Refactor Implementation Plan

## 1. 审查对象

- 主文件：`docs/superpowers/plans/2026-04-25-cve-agent-boundary-refactor.md`（1188 行，2026-04-29 17:11 最后更新）
- 关联文件：
  - `docs/superpowers/STATUS.md`（superpowers 当前状态入口）
  - `docs/design/adr-evidence-first-patch-engine.md`（active ADR，2026-04-29）
  - `docs/design/codex-prompt-phase-a.md`（Evidence-First 阶段 A 执行指令）
- 当前代码事实：5 项已修改 + 2 个未跟踪文件（candidate_scoring.py / test_candidate_scoring.py）
- 最近 15 次 git 提交（含 `b046bb2` "接入Evidence-First富化管道并修复阶段A偏差"）

## 2. 综合评分（0-100）

| 维度 | 我的评分 | Codex 评分 | 一致性 |
| --- | ---: | ---: | --- |
| 清晰度 | 70 | 68 | 高 |
| 一致性 | 48 | 52 | 高 |
| 可执行性 | 55 | 58 | 高 |
| **综合** | **58** | **61** | **±3 高度一致** |

两位审查者独立得出"应当 supersede（被新计划替代）"的相同结论。

## 3. 核心问题（按严重度排序）

### P0 — plan 状态与代码事实严重错位（**必须立即收敛**）

| 来源 | 声称 | 代码事实 |
| --- | --- | --- |
| plan 头部 | `Status: active`，`Current phase: Phase 3 Evaluation Driven Iteration` | Phase 3 Task 3.1 已完成首轮，无 Task 3.2 模板 |
| `STATUS.md` | `Active phase: CVE Evidence-First Phase A pre-implementation` | commit `b046bb2` 已经在 4-29 17:31 接入 Phase A 富化管道并自我标注"修复阶段A偏差" |
| 当前 dirty worktree | 应处于"Phase A pre-implementation" | 实际正在做 Phase B（评分模块、host 扩展、PatchCandidate 合入 frontier） |

三处真相互不一致。**STATUS.md 自身也是过时的**——这是 codex 没有强调但同样关键的发现。

### P1 — 大量已落地 commit 步骤未勾选（plan 进度状态污染）

git log 已存在以下提交，但 plan 中对应 step 仍标 `- [ ]`：

| Commit | Plan 位置 |
| --- | --- |
| `86c030a` 测试(cve): 固定浏览器Agent基线分类 | Task 0.1 Step 6 |
| `813d0be` 重构(cve): 抽取Agent证据记录入口 | Task 1.1 Step 7 |
| `b92c11c` 重构(cve): 抽取Agent搜索工具 | Task 1.2a Step 6 |
| `5f09f49` 重构(cve): 抽取Agent搜索策略 | Task 1.2b Step 6 |
| `a64e9f2` 重构(cve): 抽取Agent回退决策 | Task 1.3 Step 7 |
| `1dd3fef` 重构(cve): 收敛Agent节点兼容入口 | Task 1.4 Step 5 |
| `ec4b2f0` 重构(cve): 抽取Agent导航决策边界 | Task 1.5 Step 7 |
| `5eec3cd` 功能(cve): 增加候选判断Agent接口 | Task 2.1 Step 5 |

**注意**：Task 0.1 Step 6 的 plan 期望 commit message 是「测试(cve): 固定浏览器Agent**基线失败分类**」，git log 是「测试(cve): 固定浏览器Agent**基线分类**」（少了"失败"两字）— 文字不严格一致但语义对应，应记入勾选范围。

### P2 — 当前 dirty worktree 缺乏正式的 Phase B plan 承载

未提交改动属于 ADR Phase B 范畴：

| 改动 | 归属 |
| --- | --- |
| `candidate_scoring.py`（179 行多维评分） | Phase B（codex-prompt-phase-a:339 明确说"复杂评分留给阶段 B"） |
| `reference_matcher.py` 扩展（Bitbucket/Gitee/AOSP/Bugzilla） | Phase B（candidate generation 扩展） |
| `agent_nodes.py` 将 PatchCandidate 合并入 direct_candidates | Phase B（候选进入主链时机调整） |

旧 plan 没有 Phase B 任务，新 plan 没有创建。**这些改动正在"无 plan 状态"下推进**。这是当前最大的执行风险。

### P3 — Phase 3 缺失 plan-level 完成定义

Phase 3 是开放式迭代框架（每轮选一个 baseline failure_category）。当前已经有 `no_public_patch` / `non_maintained_component` 类样本被识别为"非系统缺陷"，但 plan 没有定义"何时停止扩主链"的阈值，存在范围漂移风险。

## 4. 与 Codex 的判断对比

### 4.1 一致结论
- supersede 旧 plan（替代而非简单归档）
- 修正 plan 头部状态行
- 勾选已对应 git log 的 8 个 commit step
- 当前 dirty 改动归属 Phase B
- 旧 plan 的 Phase 0/1/2 仍是有效历史基础

### 4.2 我对 Codex 的补充和质疑

**质疑 1：Codex 第 7 条说"dirty code 越过 codex-prompt-phase-a.md 硬边界"** — 这个判断**部分错误**。
- commit `b046bb2` 自己写明"回退了提前执行阶段B的第二轮循环"，说明当时确实越界并被纠正。
- 但当前 dirty 改动是**主动重启 Phase B**，不是误闯。问题不是"越界"，而是 **"Phase B 启动了但没有 plan 文档"**。

**补充 1：STATUS.md 自身也过时** — Codex 只指出 plan 与 STATUS.md 不一致，但**STATUS.md 本身也是错的**。它说 "Phase A pre-implementation"，但 commit `b046bb2` 已经把 Phase A 主体合入。STATUS.md 必须同步更新为 "Phase A 主体已完成；Phase B 启动但缺执行 plan"。

**补充 2：supersede 的执行顺序必须明确** — Codex 已建议"先创建新 plan 再切 STATUS.md 指针"，我进一步明确顺序：
1. 不能在没有 Phase B plan 的情况下直接把旧 plan 标 superseded — 否则会产生"无任何 active plan"空窗
2. 应当：① 先由 ADR 派生 Phase B execution plan → ② STATUS.md 切换 Active plan → ③ 旧 plan 标 superseded → ④ 同步勾选已落地的 step

## 5. 收敛建议（按优先级）

### 立即可做（仅文档治理，零代码风险）
1. **修正 plan 头部状态行**（Status / Current phase / Next checkpoint）
2. **勾选 8 个已落地的 commit step**（Task 0.1 Step 6 等，详见上表）
3. **修正 STATUS.md 的 Active phase**：从 "Phase A pre-implementation" 改为 "Phase A 主体已完成（commit b046bb2），Phase B 启动但缺 execution plan"

### 短期需要（决定 Phase B 走向）
4. **派生 Phase B execution plan**（基于 ADR + codex-prompt-phase-a 的 Phase B 描述），承载当前 dirty 工作：
   - candidate_scoring.py 的接入点（替换 reference_matcher.CANDIDATE_PRIORITY 字典的策略）
   - reference_matcher host 扩展的回归测试覆盖（Bitbucket/Gitee/AOSP/Bugzilla 新规则当前缺单测）
   - PatchCandidate 合入 direct_candidates 的语义验收（必须明确"高置信短路 vs 完整证据保留"边界）
5. **STATUS.md 切换 Active plan 指向新计划**

### 旧 plan 收敛动作
6. **将旧 plan 标记为 superseded by 新 Phase B plan**，保留 Phase 0/1/2 历史基础不动
7. **明确 Phase 3 的终止条件**：将开放式迭代框架的 stop 规则写进新 plan（例如"连续一次 failure_category 刷新无系统缺陷则停止扩主链"）

## 6. 潜在风险

1. **行为边界风险**：当前 dirty 中 `agent_nodes.py` 把 `PatchCandidate` 合入 `direct_candidates` 改变了候选进入主链的时机，**必须** 在新 plan 中明确这是 acceptance 行为变更还是仅观测增强。
2. **CANDIDATE_PRIORITY 双源风险**：`candidate_scoring.py` 声称替代 `reference_matcher.CANDIDATE_PRIORITY`，但当前主链仍使用旧字典 — 接入前是"两处真相"，接入后必须确认 acceptance baseline 不退化。
3. **Bitbucket/Gitee/AOSP 正则未回归**：grep 显示 `test_reference_matcher.py` 没有新增对应用例，新 host 走的是哪条 acceptance 路径未知。
4. **AOSP 正则可疑**：`_AOSP_GITILES_COMMIT_RE = r"^/plugins/gitiles/[^/]+/[+]/\+/log/([0-9a-f]{40})$"` 路径片段 `/[+]/\+/log/` 写法异常，正常 gitiles 不应包含 `/log/` 后缀。
5. **Bugzilla host 未限定**：`_BUGZILLA_ATTACHMENT_RE` 只匹配 path 与 query，未限定 hostname，会误匹配任意域名的 `/attachment.cgi?id=N`。

## 7. 最终建议

**对当前 plan：supersede（由 Phase B execution plan 替代并归档）**

**对当前会话的下一步行动**（按用户决策粒度排序）：
- A. 仅做文档治理（修 plan 头部 + 勾选 8 个 step + 修 STATUS.md）— 零风险，立即可做
- B. A + 派生 Phase B execution plan 骨架（基于 ADR）— 中等工作量，明确下一阶段方向
- C. A + B + 立即处理 dirty worktree（补 reference_matcher 单测、确认 candidate_scoring 接入点）— 完整收敛

## 8. 参考的客观对照证据

- Codex 独立审查 session：`019de154-733e-7911-8deb-af5bd0979ed9`
- Codex 综合评分 61，三维度 68/52/58，判定 supersede
- Codex 给出的最小 patch 已覆盖 plan 头部 + 8 个 commit step 复选框
- 双方独立结论高度一致；分歧仅在 codex 第 7 条对"硬边界"的措辞上，已在 §4.2 修正

---

## 9. 本会话已落地的收敛动作（2026-05-01）

按用户选择的 C 档"完整收敛"执行，按 A → B → C 顺序：

### A 部分：文档治理（零代码风险）

- **A1** ✅ 修正 `boundary-refactor plan` 头部 — Status: superseded；引用新 Phase B plan；标注 Phase 0/1/2 历史基础有效
- **A2** ✅ 勾选 8 个已落地的 commit step（Task 0.1.6 / 1.1.7 / 1.2a.6 / 1.2b.6 / 1.3.7 / 1.4.5 / 1.5.7 / 2.1.5）
- **A3** ✅ 修正 STATUS.md — Active phase 改为"Phase B in-progress"；Active plan 切换到新 Phase B plan；Last baseline 注明需 Phase B 收口前重做

### B 部分：派生 Phase B execution plan

- **B1** ✅ 创建 `docs/superpowers/plans/2026-05-01-cve-evidence-first-phase-b.md`（523 行）
  - Codex 给出 unified diff 原型（session `019de154`）
  - 我重写为生产级文档，关键改进：① 头部明确 Phase A 起点 commit `b046bb2` ② Commit Strategy 整合到每个 Task Step ③ 简化 Task B.5 为收口检查清单 ④ 显式列出非 Phase B 的 dirty 文件归属
  - 包含 5 个 Task：B.1 reference_matcher 新 host 测试 / B.2 AOSP+Bugzilla 正则修正 / B.3 candidate_scoring 接入 / B.4 PatchCandidate 合入 direct_candidates 验收 / B.5 Phase B 收口
- **B2** ✅ STATUS.md Active plan 指针已在 A3 中切换

### C 部分：处理 dirty 工作区

- **C1+C2** ✅ 修正 `reference_matcher.py` 缺陷 + 补 15 个新测试用例
  - Codex 出 unified diff 原型（同 session）
  - 我重写改进：① AOSP 应用层加贪婪守卫 `parsed.path.count("/+/") == 1` ② AOSP 用 `aosp_match.group(1)` 替代 `rsplit` ③ Bugzilla 应用层先校验 hostname+path 再 parse_qs ④ 新增 1 条贪婪守卫反例测试
  - **修正点**：
    - `_AOSP_GITILES_COMMIT_RE` 从 `^/plugins/gitiles/[^/]+/[+]/\+/log/([0-9a-f]{40})$`（错误前缀+错误片段+严格 40 hex）改为 `^/(.+)/\+/([0-9a-f]{7,40})$`
    - `_BUGZILLA_HOSTS` allowlist 引入：`bugzilla.redhat.com / bugzilla.suse.com / bugzilla.kernel.org / bugzilla.mozilla.org / bugzilla.gnome.org / bugs.gentoo.org`
    - Bugzilla 应用层从 `parsed.path + "?" + parsed.query` 拼接匹配改为 hostname+path+parse_qs 标准化
  - **测试覆盖（15 个新用例）**：
    - Bitbucket commit / commits 复数路径 / pull request / 非 commit 路径反例
    - Gitee commit / 非 commit 路径反例
    - AOSP gitiles commit / log 反例 / refs branch 反例 / 非 AOSP host 反例 / 双 `/+/` 反例
    - Bugzilla redhat / suse 正例 / 任意域名反例 / 缺 id 参数反例
    - 评分排序（bitbucket commit > pull / aosp commit < kernel commit）
  - Codex review 结论：**通过但需关注**（Bugzilla allowlist 保守可后续扩；多 id 行为宽松可后续收紧；netloc 端口边界 — 均非阻塞）
  - 验证：`pytest backend/tests/test_reference_matcher.py -q` → 35 passed
  - 扩展回归：`reference_matcher / cve_agent_graph / seed_resolver / seed_resolver_enriched / candidate_generator / patch_evidence / candidate_scoring` 共 7 个测试文件 → 105 passed, 40 skipped, 无回归
- **C3** ✅ candidate_scoring 接入决策已在 Phase B Task B.3 中定义
  - **决策**：本会话**不实际接入主链**（避免 acceptance baseline 行为变化）
  - **理由**：candidate_scoring 接入会改变候选优先级评分，可能影响 patch URL 选择顺序；按 Phase B plan 要求，接入必须复跑 acceptance baseline 验证 — 这超出本会话能力（需 postgres + 真实 LLM 环境）
  - **后续路径**：用户按 Phase B plan Task B.3 顺序执行：写测试 RED → 接入 → GREEN → 跑 acceptance compare → 提交

## 10. 当前工作区状态（落地后）

### 已修改文件

| 文件 | 来源 | 状态 |
| --- | --- | --- |
| `docs/superpowers/plans/2026-04-25-cve-agent-boundary-refactor.md` | 本会话 A1+A2 | 头部 supersede 标记 + 8 个 step 勾选 |
| `docs/superpowers/STATUS.md` | 本会话 A3 | Active plan 切换 + Active phase 修正 |
| `docs/superpowers/plans/2026-05-01-cve-evidence-first-phase-b.md` | 本会话 B1 新建 | 523 行 Phase B execution plan |
| `backend/app/cve/reference_matcher.py` | 本会话 C1+C2 + 之前 dirty | AOSP/Bugzilla 修正 + 4 类新 host（dirty 部分由 Phase B Task B.1 commit） |
| `backend/tests/test_reference_matcher.py` | 本会话 C1+C2 | 新增 15 个测试用例 |
| `.claude/verification-report.md` | 本会话 | 审查报告 |
| 之前已 dirty 的文件 | 之前 | 未动（agent_frontier_skill / agent_nodes / candidate_scoring / test_candidate_scoring / test_cve_agent_graph） |

### 提交建议（按 Phase B plan Commit Strategy 分批）

本会话**不主动 commit**，由用户按 Phase B plan 决定提交节奏。建议分批：

1. **文档治理 commit**（本会话 A+B 产物）：
   - `docs/superpowers/STATUS.md`
   - `docs/superpowers/plans/2026-04-25-cve-agent-boundary-refactor.md`
   - `docs/superpowers/plans/2026-05-01-cve-evidence-first-phase-b.md`
   - `.claude/verification-report.md`
   - 建议 message：`文档(cve): 收敛boundary-refactor计划，派生Phase B execution plan`
2. **Phase B Task B.1 commit**：
   - `backend/app/cve/reference_matcher.py`（仅 host 扩展部分，不含本会话的 AOSP/Bugzilla 修正）
   - `backend/app/cve/agent_frontier_skill.py`
   - `backend/tests/test_reference_matcher.py`（仅 Bitbucket/Gitee 正例）
   - 建议 message：`测试(cve): 覆盖Phase B新增候选来源匹配`
3. **Phase B Task B.2 commit**：
   - `backend/app/cve/reference_matcher.py`（本会话的 AOSP 守卫 + Bugzilla allowlist）
   - `backend/tests/test_reference_matcher.py`（本会话的 AOSP/Bugzilla 边界用例）
   - 建议 message：`修复(cve): 收敛AOSP与Bugzilla候选匹配边界`

注意：步骤 2 与 3 涉及同一文件的不同部分，分批 commit 需要 `git add -p` 选择性 staging，或先 stash 后 cherry-pick。如不便分批，可合并为一个 commit 但 message 需说明两类改动。

### 不属于 Phase B 的 dirty 文件（保留待用户处理）

- `backend/app/cve/candidate_scoring.py` — Phase B Task B.3 接入时一并 commit
- `backend/tests/test_candidate_scoring.py` — 同上
- `backend/app/cve/agent_nodes.py` — Phase B Task B.4 接入时一并 commit
- `backend/tests/test_cve_agent_graph.py` — 同上

## 11. 收敛完成度自评

| 检查项 | 状态 |
| --- | --- |
| 旧 plan 状态行已修正 | ✅ |
| 旧 plan 已勾选 step 与 git log 对齐 | ✅ |
| STATUS.md 状态路由已更新 | ✅ |
| 新 Phase B plan 已创建并被 STATUS.md 引用 | ✅ |
| dirty worktree 已有 plan 承载 | ✅ |
| reference_matcher 4 类新 host 有单测覆盖 | ✅（15 个新用例）|
| AOSP 正则缺陷已修复 | ✅（5 个边界测试通过）|
| Bugzilla hostname allowlist 已收紧 | ✅（4 个边界测试通过）|
| candidate_scoring 接入决策已记录 | ✅（Phase B Task B.3 等待执行）|
| 扩展回归测试无破坏 | ✅（105 passed, 40 skipped）|
| acceptance baseline 复跑 | ⚪ 不在本会话范围（Phase B Task B.4 需 postgres 环境）|

**综合**：本会话完整收敛了"plan 状态错位"和"dirty 工作区缺 plan 承载"的 P0/P1 风险，并修复了 reference_matcher 的两处明确缺陷（AOSP 正则 + Bugzilla hostname）。candidate_scoring 主链接入与 acceptance 验证按 Phase B plan 留给后续执行。
