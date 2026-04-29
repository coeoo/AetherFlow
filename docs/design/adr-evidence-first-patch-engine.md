# ADR: Evidence-First Patch Acquisition Engine

> 状态：active
> 日期：2026-04-29
> 决策者：项目负责人
> 关联文档：cve-patch-acquisition-strategy-report.md

---

## 决策

AetherFlow 的 CVE Patch 获取能力从 Browser-Agent-first 架构演进为 Evidence-first、Candidate-driven、Agent-fallback 的分层补丁获取引擎。

Browser Agent 继续保留且持续增强，但不再承担所有 CVE 的默认主路径。结构化数据提取、证据归一化、候选生成、确定性下载验证和可解释评分成为主干。Agent 专注处理长尾复杂样本的深度探索。

---

## 背景

当前系统的 LangGraph 图对所有 CVE 都走完整的 Browser Agent 流程：

```
resolve_seeds -> build_initial_frontier -> fetch_next_batch -> extract_links_and_candidates
-> agent_decide -> download_and_validate -> finalize_run
```

这个架构方向正确，但存在一个结构性问题：对"确定性场景"和"不确定场景"的处理成本没有分层。

实测数据显示：
- CVE-2024-38545（内核 CVE）：seed references 中直接包含 `git.kernel.org/stable/c/` 链接，`reference_matcher` 在 `build_initial_frontier_node` 中就能匹配到 `kernel_commit_patch`。但系统仍然启动浏览器访问 NVD 页面、调用 LLM 导航决策，最终耗时 27 秒。
- CVE-2022-2509（GnuTLS）：references 中没有直接 commit 链接，需要从 NVD -> Debian mailing list -> Debian security tracker -> GitLab commit 多跳探索。耗时 94 秒，5 次 LLM 调用。这才是 Browser Agent 的价值场景。

同时，当前 `SeedSourceResult` 只输出 `references: list[str]`，丢失了大量结构化信息：
- CVE 官方 `containers.adp[].references[]`（CISA Vulnrichment 数据）未解析
- CVE `containers.cna.affected[].versions[]` 中 `versionType == "git"` 的 fix commit SHA 未提取
- OSV `affected[].ranges[].events[].fixed` 未提取
- GHSA `vulnerabilities[].first_patched_version` 未提取
- OSV/NVD reference 的 `type` 标签（FIX、ADVISORY 等）未保留

## 当前仓库事实

- `backend/app/cve/seed_sources.py` 当前只返回 `references: list[str]`，没有结构化 seed 证据模型。
- `backend/app/cve/seed_resolver.py` 负责 source authority 合并，并将 `source_results` 写入 `SourceFetchRecord.response_meta_json`。
- `backend/app/cve/agent_state.py` 当前只有 `seed_references`、`direct_candidates` 等运行态字段，没有 `patch_evidence` / `seed_candidates` 之类的新抽象。
- `backend/app/cve/detail_service.py` 会将 `request_snapshot_json` / `response_meta_json` 原样序列化给前端，所以阶段 A 若写入新数据，必须先定义兼容字段名和读侧预期。
- 当前 `docs/superpowers/STATUS.md` 已将本 ADR 和 `codex-prompt-phase-a.md` 纳入 process 入口；后续阶段推进仍需保持与 active plan / active spec 的兼容关系。

## 从对话沉淀的全局原则

这份 ADR 不只是来自单篇分析报告，也吸收了当前项目迭代过程中已经被反复确认的全局约束：

- `CVE Patch Agent` 是当前产品主叙事，但它运行在共享平台之上。AetherFlow 现在已有三条真实链路：平台底座、CVE Patch Agent、安全公告提取/监控；因此这次改造应限定在 `backend/app/cve/` 主链，不扩大到平台层和公告层。
- 项目当前定位仍然是 `real-time only` 的按需情报获取服务，不将 `cvelistV5` 离线批处理或长期仓库索引作为主链默认方向。
- 现有 Browser Agent / LangGraph 主链方向被确认是正确的，问题不在于“是否还需要 Agent”，而在于 `backend/app/cve/agent_nodes.py` 承担了过多原本应由结构化提取、候选生成和确定性验证负责的职责。
- `agent_nodes.py` 仍然是现有测试、monkeypatch 和集成 harness 依赖的兼容 facade。后续抽取实现时，应保留这层稳定表面，而不是在阶段 A / B 直接打碎调用路径。
- `patch_downloader.py` 和下载验证仍是最终真实性裁决层。LLM、Candidate Judge、Browser Agent 都不能替代下载校验，也不能凭空生成或确认 patch URL。
- 详情页的长期契约是“结论优先 + 开发者详情”。`source_traces`、`search_graph`、`decision_history`、`final_patch_urls`、patch content 这些读侧事实必须继续存在，且新增的 evidence 层只能增强可解释性，不能让详情页变成空壳。
- `source_fetch_records` 已经是 seed 解析、页面抓取、patch 下载的稳定证据表，现有 `source_type`、`request_snapshot_json`、`response_meta_json` 足以承载阶段 A 的增量信息；本 ADR 不以新增 schema 为前提。
- `backend/results/` 是运行证据目录，不是源码资产。这次架构调整会依赖真实 acceptance 产物做判断，但不会把结果目录纳入实现设计契约或提交范围。
- 架构判断应以本仓库的 baseline、acceptance 和 detail/read-side 证据为主，而不是拿外部成功率或论文指标直接外推当前系统收益。
- 非维护范围生态，如 WordPress / WPScan / Trac 插件类样本，当前被视为 `non_maintained_component` 或 `no_public_patch` 类解释证据，不应借此次重构顺手扩 downloader 主链，除非未来有新证据改变分类。

## 保护性约束

这次 Evidence-first 改造要解决的是主链分层问题，不是顺手重写整个 CVE 子系统。为避免范围漂移，额外明确以下保护性约束：

- 不借此改造重新引入旧的 `httpx + page_fetcher + navigation` 旧主链；当前 Browser Agent 合约和 recorded integration fixture 仍是权威回归入口。
- 不把 Candidate Judge 从默认关闭改成默认开启，也不借此提前扩大它的职责边界。Candidate Judge 仍只负责候选模糊判断，不负责 source parsing、patch 下载或全局调度。
- 不把“高置信候选短路”直接等同于“跳过全部证据写入”。短路必须保留 source trace、decision 和 artifact 解释能力。
- 不把“fixed version”混同为“fix commit”。结构化 evidence 层必须区分 `reference_url`、`fix_commit`、`fixed_version`、`advisory`、`affected_range`，避免版本证据直接冒充 patch 证据。
- 不把这次设计收口成只服务 CVE API 的一次性优化。所有新增 evidence / candidate 抽象都应优先服务长期实现设计，而不是只为某一轮 acceptance 临时补丁。

---

## 目标架构

```
CVE ID
  |
  v
Layer 1: Source Fetching（多源获取）
  seed_sources.py — 增强：提取结构化字段，不只是 URL list
  |
  v
Layer 2: Evidence Normalization（证据归一化）
  patch_evidence.py — 新增：统一 PatchEvidence 模型
  |
  v
Layer 3: Candidate Generation（候选生成）
  candidate_generator.py — 新增：从 evidence 生成 typed candidate
  reference_matcher.py — 保留：URL -> candidate 的确定性规则
  |
  v
Layer 4: Deterministic Validation（确定性验证）
  patch_downloader.py — 保留：下载 + 格式验证
  |
  v
Layer 5: Scoring / Judge（评分与判断）
  candidate_scoring.py — 新增：多维可解释评分
  decisions/candidate_judge.py — 保留：LLM 处理模糊判断
  |
  v
Route Decision
  |-- 高置信候选已验证 -> finalize（短路）
  |-- 无候选 / 低置信 / 证据冲突 -> Layer 6
  |
  v
Layer 6: Browser Agent Exploration（浏览器探索）
  agent_graph.py + agent_nodes.py — 保留：LangGraph 状态机 + 浏览器导航
  |
  v
统一输出：candidates + evidence chain + execution summary
```

### LangGraph 图节点调整

当前图：
```
resolve_seeds -> build_initial_frontier -> fetch_next_batch
-> extract_links_and_candidates -> agent_decide
-> download_and_validate -> finalize_run
```

目标图：
```
resolve_sources -> normalize_evidence -> generate_candidates
-> validate_seed_candidates -> route_decision
  |-- verified_patch_found -> finalize
  |-- needs_exploration -> build_frontier -> fetch_next_batch
      -> extract_links_and_candidates -> agent_decide
      -> download_and_validate -> finalize
```

前半段（resolve -> normalize -> generate -> validate）是确定性的，不涉及浏览器和 LLM。

这个目标图描述的是终态结构，不是阶段 A / B 立即执行的节点重命名计划。阶段 A / B 保持现有
`resolve_seeds`、`build_initial_frontier`、`download_and_validate` 等 phase 名称和
外部契约不变，只在内部增加 evidence / candidate 抽象与兼容字段。

---

## 新增数据结构

### PatchEvidence

```python
@dataclass(frozen=True)
class PatchEvidence:
    evidence_type: str          # reference_url | fix_commit | fixed_version
                                # | advisory | affected_range
    source: str                 # cve_official | osv | github_advisory | nvd
    url: str | None
    commit_sha: str | None
    version: str | None
    repo_hint: str | None       # 从 URL 或 affected 推断的仓库
    semantic_tag: str | None    # patch | FIX | advisory | first_patched_version
    authority_score: int
    confidence: str             # high | medium | low
    raw_field_path: str         # 原始 JSON 路径，如 "containers.adp[0].references[2]"
```

### PatchCandidate

```python
@dataclass(frozen=True)
class PatchCandidate:
    candidate_type: str         # direct_patch | commit_patch | pr_patch
                                # | version_window | exploration_seed
    candidate_url: str
    patch_url: str | None       # 可直接下载的 URL
    patch_type: str             # github_commit_patch | kernel_commit_patch | ...
    canonical_key: str
    evidence_sources: list[PatchEvidence]
    score: int
    confidence: str             # high | medium | low
    downloadable: bool          # 是否可以直接尝试下载
```

### 扩展 SeedSourceResult

在现有字段基础上新增：

```python
structured_references: list[dict]   # 带 type/tag 的 reference
fix_commits: list[dict]             # 从 affected/ranges 提取的 fix commit
fixed_versions: list[dict]          # 从 affected/ranges 提取的 fixed version
```

保留 `references: list[str]` 向后兼容。

---

## 模块边界

| 文件 | 职责 | 变更类型 |
|------|------|---------|
| `seed_sources.py` | fetch + source-specific raw extraction | 增强 |
| `seed_resolver.py` | 多源合并、authority、source trace | 增强 |
| `patch_evidence.py` | 统一 evidence schema、归一化 | **新增** |
| `candidate_generator.py` | 从 evidence 生成 typed candidate | **新增** |
| `candidate_scoring.py` | 多维可解释评分 | **新增** |
| `reference_matcher.py` | URL -> candidate 的确定性规则 | 增强 |
| `source_trace.py` | structured seed trace 写入契约 | 增强 |
| `agent_graph.py` | LangGraph 编排 | 调整 |
| `agent_nodes.py` | 浏览器导航 + LLM 决策 | 精简 |
| `agent_state.py` | AgentState TypedDict | 增强 |
| `patch_downloader.py` | 下载 + 格式验证 | 保持不变 |
| `decisions/candidate_judge.py` | LLM 模糊判断 | 保持不变 |
| `detail_service.py` | 详情读侧序列化与兼容展示 | 增强 |
| `frontend/src/features/cve/types.ts` | detail payload 类型契约 | 后续增强 |
| `frontend/src/routes/CVERunDetailPage.tsx` | 层级执行摘要和 trace 展示 | 后续增强 |

---

## 实施路线

### 阶段 A：建立 Evidence-First 基础（不改变运行行为）

目标：把结构化证据收集起来，写入 state 和 source trace metadata，但不改变最终结果。

具体动作：
1. 扩展 `SeedSourceResult`，增加 `structured_references` / `fix_commits` / `fixed_versions`
2. `_extract_cve_official_references()` 增加解析 `containers.adp[].references[]` 和 `affected[].versions[]` git SHA
3. `_extract_osv_references()` 增加解析 `affected[].ranges[].events[]`
4. `_extract_github_advisory_references()` 增加提取 `first_patched_version` 和 `source_code_location`
5. 新增 `patch_evidence.py`，定义 `PatchEvidence` dataclass
6. 新增 `candidate_generator.py`，定义 `PatchCandidate` dataclass（此阶段只定义，不接入图）
7. `seed_resolver.py` 传递结构化字段
8. `seed_resolver.py` 将结构化统计写入 `SourceFetchRecord.response_meta_json` 的兼容字段，例如 `structured_reference_count`、`fix_commit_count`、`fixed_version_count`；不新增 schema，不新增新的 `source_type`
9. 现有测试全部通过，行为不变

阶段 A 的硬边界：

- 不改 `run.phase`
- 不改 `stop_reason`
- 不改 `source_type="cve_seed_resolve"`
- 不改 `SeedSourceResult.references` 的去重结果
- 不改 `build_initial_frontier_node`、`agent_decide_node`、`download_and_validate_node` 的既有判定逻辑
- 新增的 `patch_evidence` / `patch_candidates` 只写 state，不参与后续节点决策

验收标准：
- 新字段对已有 CVE 样本有值
- `PatchEvidence` 和 `PatchCandidate` 有完整单元测试
- 现有 `test_seed_sources.py`、`test_seed_resolver.py`、`test_reference_matcher.py` 全部通过
- 现有 acceptance 场景结果不变
- `source_traces` 的既有字段结构保持兼容，新增数据仅为增量字段

### 阶段 B：候选生成与评分独立化

目标：把 candidate 生成和排序从 `build_initial_frontier_node` 中拆出来。

具体动作：
1. `candidate_generator.py` 实现 evidence -> candidate 转换逻辑
2. `candidate_scoring.py` 实现多维评分替代 `CANDIDATE_PRIORITY`
3. `reference_matcher.py` 补充 compare/tag/Bitbucket URL 规则
4. `build_initial_frontier_node` 改为调用 `candidate_generator`
5. 保留旧字段兼容
6. 保持 `direct_candidates`、`decision_history`、`cve_candidate_artifacts` 的现有写法兼容

验收标准：
- 新模块有完整单元测试
- `build_initial_frontier_node` 输出与改造前等价
- 现有 acceptance 场景结果不变

### 阶段 C：引入受控短路（默认关闭）

目标：验证高置信 seed candidate 可以跳过 Browser Agent。

具体动作：
1. `agent_graph.py` 增加 `validate_seed_candidates` 节点和 `route_decision` 条件边
2. 加 feature flag `AETHERFLOW_CVE_SEED_FAST_PATH_ENABLED=false`
3. 短路结果写完整 evidence / decision / artifact / source_trace
4. 详情页能解释"为什么没有走 Browser Agent"

验收标准：
- flag=false 时行为与阶段 B 完全一致
- flag=true 时 CVE-2024-38545 类样本在 seed 阶段短路
- flag=true 时 CVE-2022-2509 类样本仍走 Browser Agent
- 短路结果的 `final_patch_urls` 与完整流程一致
- 短路结果仍保留可解释的 `source_traces` / `decision_history`，不会生成空壳详情页

### 阶段 D：Browser Agent 精细化与 no-patch 解释

目标：让 Browser Agent 更专注于长尾复杂样本。

具体动作：
1. Agent 只处理 `needs_exploration` 路由的 CVE
2. `finalize_run_node` 增加 `no_patch_reason` 分类
3. 前端详情页展示层级执行摘要

---

## 不做的事情

1. 不走 cvelistV5 离线批处理作为主链
2. 不实时克隆上游仓库
3. 不自建 commit embedding 索引
4. 不训练专用排序模型
5. 不让 LLM 替代确定性解析

---

## 对 Agent 产品定位的影响

这个改造不是弱化 Agent，是精准化 Agent。

改造前：Agent 是所有 CVE 的默认处理路径，大量时间花在处理规则引擎就能解决的简单 URL 匹配上。

改造后：Agent 只处理真正需要智能探索的 CVE。Agent 拿到的 context 更丰富（evidence 层已经告诉它"我们从 4 个数据源拿到了什么、缺什么"），探索方向更精准，每次启动都意味着"这是一个规则引擎解决不了的问题"。

产品定位：AetherFlow 的 CVE Patch Agent 是一个有结构化知识底座的智能 Agent——先用确定性方法穷尽已知信息，在信息不足时启动深度探索。

---

## 与现有文档的关系

- `cve-patch-acquisition-strategy-report.md` 是本 ADR 的论证材料，不是执行入口。
- 阶段执行以单独的 phase prompt / spec 为准，例如 `codex-prompt-phase-a.md`。
- `docs/design/` 下已有的 CVE 实现设计文档后续需要逐步按本 ADR 对齐，但本 ADR 本身不替代具体模块的源码级实现设计。

## 对项目其他部分的影响

CVE patch 获取只是 AetherFlow 的一个渠道。这次架构调整只影响 `backend/app/cve/` 内部实现，不影响平台层、公告渠道或未来其他渠道。把 Browser Agent 从"默认主路径"变成"可选能力"，反而让平台更灵活。

## 后续文档同步点

本 ADR 后续若被正式采纳，需要同步检查以下长期文档和读侧契约：

- `docs/design/cve-agent-orchestration.md`
- `docs/design/cve-agent-state-and-budget.md`
- `docs/design/cve-agent-search-graph-and-evidence.md`
- `docs/design/cve-agent-detail-api-and-frontend-projection.md`
- `docs/04-功能设计/M103-CVE数据源与页面探索规则功能设计.md`
- `docs/superpowers/STATUS.md` 与后续 active spec / active plan

同步原则不是一次性重写，而是按阶段 A/B/C 的真实实现逐步把“seed evidence -> candidate -> validation -> agent fallback”写回这些长期文档。
