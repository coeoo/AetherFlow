# B.4 frontier 完全接管 candidate_generator

## Goal

把 `build_initial_frontier_node` 从「桥接 PatchCandidate」升级为「完全调用 `candidate_generator`」，让所有 seed-derived 直接候选都经过统一的 evidence → candidate 通道，使 direct_candidates 的真相收敛于 `candidate_generator` + `candidate_scoring`。这是 ADR Phase B Step 4 字面要求（Plan 显式窄化为桥接，本任务作为 Phase B+ 升级，由维护者批准放开）。完成后 Phase C seed fast path 可在统一 candidate 通道之上直接接 validate_seed_candidates 节点。

## What I already know

权威设计：
- ADR `docs/design/adr-evidence-first-patch-engine.md` §阶段 B Step 4：`build_initial_frontier_node` 改为调用 `candidate_generator`，保留旧字段兼容；§验收标准要求等价输出。
- Phase B Plan `docs/superpowers/plans/2026-05-01-cve-evidence-first-phase-b.md` Task B.4 显式窄化为桥接版本；本任务**升级到 ADR 字面要求**。
- Boundary refactor spec `docs/superpowers/specs/2026-04-25-cve-agent-boundary-refactor-design.md` 是 facade 兼容契约的来源。

仓库现状：
- B.1/B.2 ✅ 合入主线（commit `98e0ca5`），reference_matcher 已支持 GitHub/GitLab/kernel/Bitbucket/Gitee/AOSP/Bugzilla 7 host。
- B.3 ⚠️ 半完成：`candidate_scoring.py` 已上线（commit `885cb20`），但：
  - `reference_matcher.CANDIDATE_PRIORITY` (reference_matcher.py:216-230) 仍是独立硬编码字典
  - `reference_matcher.get_candidate_priority` (reference_matcher.py:233-238) 仍走旧字典
  - 调用方 `agent_nodes.py:1026`、`decisions/fallback.py:184` 均未走新评分
  - **双源真相未收敛**——这会让 B.4 完整版 candidate_generator 的输出排序与下载阶段不一致
- B.4 桥接 dirty 在 worktree 未 commit：
  - `backend/app/cve/agent_nodes.py:442-473` 合入 PatchCandidate 到 direct_candidates 的桥接逻辑
  - `backend/tests/test_cve_agent_graph.py:268,313` 两个图测试 `test_build_initial_frontier_node_integrates_patch_candidates` / `test_build_initial_frontier_node_dedup_across_seed_and_enriched_paths`
  - `git status` 标 `M` —— 完整版会取代/演化这块逻辑
- B.4 acceptance baseline 未跑：`backend/results/candidate-cve-evidence-first-phase-b-mock/` 不存在；Plan B.4 Step 6 强制要求

`candidate_generator.generate_candidates` 当前能力（candidate_generator.py:43-106）：
- ✅ `fix_commit` evidence + GitHub repo_hint → `commit_patch` 候选
- ✅ `reference_url` evidence + match_reference_url 命中 → `commit_patch` / `pr_patch` / `direct_patch`
- ❌ `fix_commit` 在非 GitHub repo（GitLab/kernel/Bitbucket/...）下不输出候选
- ❌ `fixed_version` evidence 完全跳过（不生成候选）
- ❌ `advisory` evidence 完全跳过

`build_initial_frontier_node` 当前 seed-derived 路径（agent_nodes.py:399-441）：
- 遍历 `state["seed_references"]` → `normalize_frontier_url` → `match_reference_url` → 命中即 `build_candidate_record(source_kind="seed")` → `upsert_candidate_artifact` → 去重写入 `direct_candidates`

桥接路径（agent_nodes.py:442-473）：
- 遍历 `state["patch_candidates"]` (List[PatchCandidate]) → 跳过 not downloadable 与 canonical_key 重复 → 构造 bridge_dict → `build_candidate_record(source_kind="seed_enriched")` → `upsert_candidate_artifact` → 写入 `direct_candidates`

下游 source_kind 用法：
- `source_kind` 流向 `agent_evidence.build_candidate_record` → `discovery_sources[].source_kind`
- 详情页与 `frontier_planner` 不依赖 source_kind 决策（仅作为审计/解释字段）

## Assumptions (temporary)

1. 完整版迁移只需 candidate_generator 覆盖到 reference_url（已支持）+ fix_commit 多 host 扩展（GitLab/kernel/Bitbucket/Gitee/AOSP），不需要让 generator 处理 fixed_version 与 advisory（这两类不可下载，进入 evidence_only 通道由 frontier 阶段消化）。
2. 双源真相收敛（Plan B.3 余项）应该作为本任务的**前置 Step 1**，避免 candidate_generator 输出的排序与下载阶段排序不一致。
3. acceptance 等价验证使用 `scripts.acceptance_browser_agent --mock-mode llm-timeout-forced --profile rule-fallback-only`，与 baseline `backend/results/baseline-cve-agent-boundary-refactor-mock` 比对，要求 `high_value_path_regressed=false` 且 `patch_quality_degraded=false`。
4. 桥接 dirty 不单独 commit，而是直接演化为完整版（提交里说明从桥接演化为完整接管）。
5. `source_kind="seed"` 在完整版下统一改为 `"seed"`（reference 命中）+ `"seed_enriched"`（fix_commit/version 命中）—— 与现状一致，不破坏审计字段。

## Open Questions

（Q1 / Q2 / Q3 已收敛，见 Decision Log。如下面 Expansion Sweep 出现新问题再补。）

## Decision Log

**Q1 → 选项 A（先收敛 B.3 双源真相，再接管 candidate_generator）**

- 任务内 Step 1 先做 B.3 双源真相收敛：
  - `reference_matcher.get_candidate_priority(patch_type, candidate_url=None)` 内部委托 `candidate_scoring.get_candidate_priority`
  - `reference_matcher.CANDIDATE_PRIORITY` 字典若保留只能作为兼容 alias，并加注释说明真相已迁移至 candidate_scoring
  - 调用点 `agent_nodes.py:1026`（download_and_validate 排序）与 `decisions/fallback.py:184`（candidate_priority）保持公开 API，不改调用方式（仅改委托内部）
  - 补 `test_reference_matcher.py` 与 `test_candidate_scoring.py` 双源一致性测试
- 任务内 Step 2 再做 B.4 完整版接管 candidate_generator
- 拆为 2 个独立 commit：
  - `重构(cve): candidate_scoring 接入主链候选评分`
  - `重构(cve): build_initial_frontier 完全接管 candidate_generator`
- 后续 Phase C 评分主链统一，validate_seed_candidates 可直接消费 candidate_score 决定短路阈值

**Q2 → 选项 A（仅扩 fix_commit 多 host，fixed_version/advisory 跳过）**

- candidate_generator 在 Step 2 内重用 reference_matcher 的 host 表达式，为 `fix_commit` evidence 输出 commit_patch 候选，覆盖 6 类 host：
  - github.com → `github_commit_patch` URL（已实现，扩展为多 repo_hint 形态）
  - gitlab.com / gitlab.gnome.org / gitlab.freedesktop.org / salsa.debian.org → `gitlab_commit_patch`
  - git.kernel.org → `kernel_commit_patch`（含 `/stable/c/<sha>` 短链与 `/commit?id=<sha>` 长链）
  - bitbucket.org → `bitbucket_commit_patch`
  - gitee.com → `gitee_commit_patch`
  - android.googlesource.com → `aosp_commit_patch`
- `fixed_version` evidence 仍 skip（Phase B+ 不生成 version_window）
- `advisory` evidence 仍 skip（Phase B+ 不生成 exploration_seed）
- 重用 reference_matcher：fix_commit + repo_hint 不直接构造 URL，先合成对应 host 的 commit URL 字符串，再调 `match_reference_url` 走单一规则真相（避免 candidate_generator 维护第二份 host 知识）

**Q3 → 选项 B（mock-mode + 2 个真实样本双层验证）**

- 第一层 mock-mode（必须，作为 Plan B.4 Step 6 自动化报告）：
  ```
  PYTHONPATH=backend timeout 180s ./.venv/bin/python -m scripts.acceptance_browser_agent \
    --all --mock-mode llm-timeout-forced --profile rule-fallback-only \
    --database-url postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_baseline_20260425 \
    --results-dir backend/results/candidate-cve-evidence-first-phase-b-mock
  ```
  + compare 与 `backend/results/baseline-cve-agent-boundary-refactor-mock/acceptance_report.json`
  - 强制：`high_value_path_regressed=false`、`patch_quality_degraded=false`
- 第二层真实样本（必须）：
  - CVE-2024-38545（kernel commit，验证 multi-host fix_commit 打通；ADR 性能定位假设的反例）
  - CVE-2022-2509（gnutls，验证应该走 Browser 的路径不被误短路）
  - 命令模板：
    ```
    PYTHONPATH=backend timeout 600s ./.venv/bin/python -m scripts.acceptance_browser_agent \
      --cve-id CVE-2024-38545 \
      --database-url postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_baseline_20260425 \
      --results-dir backend/results/candidate-cve-evidence-first-phase-b-live-CVE-2024-38545
    ```
  - LLM API key 通过 `.env.local` 注入，不入 commit
  - acceptance 报告产物不入 commit，commit message 仅引用 final_patch_urls / duration / chain summary 摘要

**Q4（Expansion Sweep）→ 选项 A（仅接管 build_initial_frontier_node）**

- `extract_links_and_candidates_node` 的页面 candidate 路径**保持不变**（仍走 `match_reference_url` + `build_candidate_record`），不在本任务内重构
- candidate_generator 真相先覆盖 seed-derived 入口，页面 candidate 入口的统一留作未来独立任务
- Phase C fast path 不依赖页面 candidate 走 generator（短路决策只看 seed-derived candidate 评分）

**隐含技术约束（不需选择，trellis-implement 阶段必须遵守）**

- Step 1 双源真相收敛：`reference_matcher.get_candidate_priority` 内部委托 `candidate_scoring` 公开 type-only priority helper，保证 fallback.py:184 的 `>=90` 阈值不漂移
- Step 2 必须显式加测试断言：candidate_generator 输出的 PatchCandidate.patch_type ∈ reference_matcher 已知 patch_type 命名空间

**Q5（codex 协作时机 1 反馈采纳）→ 详情见 info.md §0**

关键改动（已落 info.md §0/§3/§6/§7）：

- Step 1 必须先补齐 `candidate_scoring._PATCH_TYPE_BASE_SCORE` 加 `aosp_commit_patch: 90`（防止 AOSP 静默退化）
- Step 1 必须暴露 `reference_matcher.KNOWN_PATCH_TYPES` 公开常量 + `candidate_scoring.get_type_priority` 公开 helper（避免引用私有 `_score_patch_type` 与第三份真相）
- Step 1 必须同步 `backend/scripts/acceptance_browser_agent.py:81` `_PATCH_TYPE_PRIORITY` 增加 5 类（bitbucket commit/pull、gitee、aosp、bugzilla），否则 `patch_quality_degraded` 对新 host 评分失真
- Step 2 fix_commit URL 合成必须是 commit page URL（不带 `.patch`），交给 matcher 输出 PatchType；带 `.patch` 会被 matcher 优先吞掉变 generic `patch`
- Step 2 repo_hint 三档处理：完整 URL 合成 / provider 前缀缩写合成 / 裸 owner/repo 默认跳过（不全局猜域名）
- Step 3 桥接测试改写为 `state["patch_evidence"]` 输入，不再注入 `state["patch_candidates"]` 桥接形态
- commit 拆分升级为 3 个（详见 info.md §6）：
  - commit 1：`重构(cve): 统一候选类型优先级来源`
  - commit 2：`功能(cve): 扩展 fix_commit 多 host 候选生成`
  - commit 3：`重构(cve): build_initial_frontier 接管 candidate_generator`
- commit 1 显式说明：仅接入 type-only priority（不接入 `score_candidate.total`）

**Q6（Step 3 实施期收敛 → scope 缩窄至 reference_url evidence）**

- mock-mode acceptance 验证发现：commit 2 candidate_generator 多 host 扩展后，若 build_initial_frontier 同时接管 reference_url + fix_commit evidence，CVE-2022-2509 出现 silent fast path 退化（visited_page_roles=[]，patches=1，违反 ADR §阶段 B 验收标准 "现有 acceptance 场景结果不变"）。
- 根因：fix_commit evidence 派生的高置信 `github_commit_patch` candidate 进入 direct_candidates → fallback.py:287 `>=90` 阈值在第一轮 decide 立即 `try_candidate_download`，Browser Agent 完全不探索。
- 收敛决定：build_initial_frontier 完整版**仅消费 reference_url evidence**（与 baseline seed-derived 路径行为等价）；fix_commit evidence 保留在 candidate_generator 的输出（resolve_seeds_node 仍写 state["patch_candidates"]），**主链 takeover 留给 Phase C fast path 节点 validate_seed_candidates 在 flag=true 时显式消费**。
- 这维持了 commit 2 candidate_generator 多 host 扩展能力（Phase C fast path 直接受益），同时不在 Phase B+ 引入主链 silent 短路。
- ADR 字面 "build_initial_frontier_node 改为调用 candidate_generator" 在 Phase B+ 阶段定义为：仅 reference_url evidence 走 generator → upsert 主链；fix_commit evidence 走 generator 但停在 state 层。
- mock-mode acceptance 验证：CVE-2022-2509 PASS（visited=['mailing_list_page','tracker_page','commit_page']，patches=6 与 baseline 等价），CVE-2024-3094 PASS（patches=5 与 baseline 等价）。

**Q7（codex review 时机 3 反馈采纳：reference_url 归一化边界）**

- codex review 指出 baseline build_initial_frontier_node 历史代码先 `normalize_frontier_url(reference.url)` 再 `match_reference_url(normalized)`；当前 candidate_generator 内部 reference_url 分支直接用 `ev.url` 与 baseline 不完全等价（带 fragment / 多余空白 / openwall http→https 形态会让 matcher 输出错误 patch URL）。
- 实施尝试：在 candidate_generator.generate_candidates reference_url 分支调用 `target_url = normalize_frontier_url(ev.url) or ev.url`，单元测试 PASS（含新增 fragment/openwall 测试）。
- 但 mock-mode acceptance 出现反向退化：CVE-2022-2509 patches=0、failure_category=candidate_missing。推测 normalize 让某些 reference URL 的 candidate_url 形态变化触发下游 pick 顺序漂移；本任务时间窗口内未能完全定位根因。
- 收敛决定：本任务保持 baseline 等价（不在 candidate_generator 内部 normalize），把 normalize-before-match 标记为 **Phase C 入口前置**。Phase C 任务必须先：
  1. 在 candidate_generator.generate_candidates 的 reference_url 分支补 normalize_frontier_url + 配套 acceptance 回归保护
  2. 调试 CVE-2022-2509 mock-mode 在 normalize 后退化的根因（dump 受影响的 reference URL 集合 + canonical_key 漂移路径）
- 已在 candidate_generator.py 与 build_initial_frontier_node 注释中显式标注此边界。

## Requirements

**Step 1 — 统一候选类型优先级来源（commit 1）**

- `candidate_scoring._PATCH_TYPE_BASE_SCORE` 补 `aosp_commit_patch: 90`（防 AOSP 静默退化）
- `candidate_scoring` 暴露公开 `get_type_priority(patch_type: str) -> int`（type-only 维度，与 `score_candidate.total` 区分）
- `reference_matcher` 暴露公开 `KNOWN_PATCH_TYPES: frozenset[str]`（由 `CANDIDATE_PRIORITY` keys 派生）
- `reference_matcher.get_candidate_priority(patch_type, candidate_url=None)` 内部委托 `candidate_scoring.get_type_priority`，保留 distro URL 降权外壳（patch/diff/debdiff + `_is_distribution_patch_url` → 20）
- `backend/scripts/acceptance_browser_agent.py:81 _PATCH_TYPE_PRIORITY` 同步增加：bitbucket_commit_patch=95、bitbucket_pull_patch=85、gitee_commit_patch=90、aosp_commit_patch=90、bugzilla_attachment_patch=40
- `agent_nodes.py:1026`、`decisions/fallback.py:184` 不动调用方式
- `test_candidate_scoring.py` 新增双源一致性测试：`KNOWN_PATCH_TYPES` 中每个 patch_type 在 `reference_matcher.get_candidate_priority(p, None)` 与 `candidate_scoring.get_type_priority(p)` 返回相同值
- `test_reference_matcher.py` 新增 AOSP commit_patch 在 `>=90` 高质量阈值仍命中的回归

**Step 2 — 扩展 fix_commit 多 host 候选生成（commit 2）**

- `candidate_generator.generate_candidates` 重写 fix_commit 处理：
  - 校验 commit_sha 是 7-40 位 hex
  - 校验 repo_hint 以 `http://` / `https://` 开头（裸 owner/repo 跳过）
  - 按 host 合成 commit page URL（不带 `.patch`，详见 info.md §1 实现伪代码）
  - 调 `match_reference_url(commit_page_url)` 获取 patch_type + canonical patch_url
  - 输出 `PatchCandidate(candidate_url=commit_page_url, patch_url=match["candidate_url"], patch_type=match["patch_type"], ...)`
  - 6 类 host：github / gitlab.* / git.kernel.org / bitbucket / gitee / android.googlesource.com
- 移除现有 `_build_commit_patch_url`（带 `.patch` 的实现）
- `fixed_version` / `advisory` evidence 仍跳过
- `test_candidate_generator.py` 新增：每类 host 至少 1 个 fix_commit 输出对应 patch_type；裸 owner/repo 跳过；非 hex commit_sha 跳过；未知 host 跳过
- `test_candidate_generator.py` 新增 patch_type 命名空间断言：所有输出 candidate.patch_type ∈ `reference_matcher.KNOWN_PATCH_TYPES`

**Step 3 — build_initial_frontier 接管 candidate_generator（commit 3）**

- `build_initial_frontier_node` 不再直接调用 `match_reference_url` + `build_candidate_record(source_kind="seed")`；改为：
  1. 先调 `candidate_generator.generate_candidates(state["patch_evidence"])` 获取所有候选
  2. 遍历 PatchCandidate，只处理 `downloadable=True` 的项
  3. 按 evidence_type 决定 source_kind："reference_url" → "seed"，"fix_commit" → "seed_enriched"
  4. 调 `build_candidate_record` + `upsert_candidate_artifact`
  5. 写入 `state["direct_candidates"]`，按 canonical_key 去重
  6. 移除 dirty 桥接逻辑（agent_nodes.py:442-473）
- 保留 frontier URL 规划（`plan_frontier`）逻辑不变
- `test_cve_agent_graph.py` 桥接测试改写：
  - `test_build_initial_frontier_node_integrates_patch_candidates` → 改名 `test_build_initial_frontier_node_generates_direct_candidates_from_patch_evidence`，输入改为 `state["patch_evidence"]`（含 reference_url + fix_commit）
  - `test_build_initial_frontier_node_dedup_across_seed_and_enriched_paths` → 输入改为同 commit 的 reference_url evidence + fix_commit evidence；断言 canonical_key 去重保留单条
- 保留现有等价契约：direct_candidates / decision_history / cve_candidate_artifacts 字段格式不变

**Step 4 — acceptance 双层验证（不单独 commit，结果写入 commit 3）**

- 第一层 mock-mode（必须）：`scripts.acceptance_browser_agent --all --mock-mode llm-timeout-forced --profile rule-fallback-only` + compare baseline，强制 `high_value_path_regressed=false` + `patch_quality_degraded=false`
- 第二层真实样本（必须）：CVE-2024-38545 + CVE-2022-2509，验证 final_patch_urls 与 baseline 等价
- compare 摘要（scenario_count / pass_count / failure_category / patch_url_set / duration / chain summary）写入 commit 3 message

**横切约束**

- 不修改 LangGraph 图拓扑
- 不引入 fast path（短路逻辑留给 Phase C）
- 不修改 `extract_links_and_candidates_node`（页面 candidate 路径保留）
- 不动 `patch_downloader.py` 主下载逻辑
- 不改 Candidate Judge 默认关闭策略
- 中文 commit、三段式（改了什么 / 为什么 / 验证了什么），不要 Co-Authored-By 不要 emoji 不要 --no-verify
- backend/results/ 不入 commit；非本任务的 dirty 不混入

## Acceptance Criteria

- [ ] **Step 1（commit 1）**：
  - [ ] `candidate_scoring._PATCH_TYPE_BASE_SCORE` 含 `aosp_commit_patch: 90`
  - [ ] `reference_matcher.KNOWN_PATCH_TYPES` 公开常量；`candidate_scoring.get_type_priority` 公开 helper
  - [ ] `reference_matcher.get_candidate_priority` 委托后双源一致
  - [ ] `backend/scripts/acceptance_browser_agent.py _PATCH_TYPE_PRIORITY` 含 bitbucket/gitee/aosp/bugzilla 类型
  - [ ] `fallback.py:184 >=90` 阈值仍命中 github / gitlab / kernel / aosp commit_patch
  - [ ] 双源一致性 + AOSP 高质量阈值测试 PASS
- [ ] **Step 2（commit 2）**：
  - [ ] `candidate_generator.generate_candidates` fix_commit 覆盖 6 host
  - [ ] 合成 URL 不带 `.patch`（commit page URL 形态）
  - [ ] repo_hint 裸 owner/repo 跳过；非 hex commit_sha 跳过
  - [ ] patch_type 命名空间断言通过
  - [ ] `test_candidate_generator.py` PASS
- [ ] **Step 3（commit 3）**：
  - [ ] `build_initial_frontier_node` 不再直接调 `match_reference_url`
  - [ ] dirty 桥接逻辑（agent_nodes.py:442-473）已被完整版替换
  - [ ] 桥接图测试改写为 patch_evidence 输入；测试 PASS
  - [ ] direct_candidates / decision_history / cve_candidate_artifacts 字段兼容
- [ ] **Step 4（acceptance 验证）**：
  - [x] mock-mode 报告 `backend/results/candidate-cve-evidence-first-phase-b-mock/` 生成
  - [x] mock-mode compare `high_value_path_regressed=false` + `patch_quality_degraded=false`
  - [x] CVE-2022-2509 + CVE-2024-3094 真实样本 final_patch_urls 与 baseline 等价（dashscope-stable profile，PASS / PASS，total 185.6s，chain_completion_rate=1.0；报告 `backend/results/candidate-cve-evidence-first-phase-b-live/`）
  - [x] 三层 compare 摘要写入 commit 3 message + 真实样本摘要追加到 task PRD 与 commit 5 文档
- [ ] `make backend-test` 全量回归 PASS（已执行：482 passed + 8 pre-existing failures，与本任务无关）

## Definition of Done

- 单元测试 + 图测试 + acceptance 三层验证全 PASS
- 非本任务 dirty 文件未混入 commit
- 3 个独立中文三段式 commit
- 必要时按 trellis-update-spec 规则将"candidate_generator 是 seed-derived candidate 唯一入口"写入 `.trellis/spec/backend/`

## Out of Scope (explicit)

- LangGraph 图拓扑改造（留给 Phase C）
- `validate_seed_candidates_node`、`AETHERFLOW_CVE_SEED_FAST_PATH_ENABLED` flag（留给 Phase C）
- patch_downloader.py 主下载逻辑改造
- Candidate Judge 默认开启策略
- 新建 reference_matcher compare URL / tag URL 模式（ADR 字面有提，但本任务确认不做）
- 详情页投影变更（留给 Phase C 的"为什么没走 Browser Agent"解释）
- **fix_commit evidence 主链 takeover**（Q6 决策；Phase C fast path 节点显式消费）

## Technical Notes

关键文件：
- `backend/app/cve/agent_nodes.py:393-510`（build_initial_frontier_node）
- `backend/app/cve/candidate_generator.py:43-106`（generate_candidates 待扩展）
- `backend/app/cve/candidate_scoring.py:131-179`（多维评分接口）
- `backend/app/cve/reference_matcher.py:216-238`（CANDIDATE_PRIORITY 双源真相）
- `backend/app/cve/agent_evidence.py::build_candidate_record / upsert_candidate_artifact`
- `backend/app/cve/decisions/fallback.py:184`（candidate_priority 调用点）
- `backend/tests/test_cve_agent_graph.py:268,313`（dirty 桥接测试）
- `backend/tests/test_candidate_generator.py`（已存在；待补 fix_commit 多 host）
- `backend/tests/test_candidate_scoring.py`（已存在；待补双源一致性）

测试与 acceptance 命令：
- 单元/图测试：`./.venv/bin/python -m pytest backend/tests/test_<module>.py -v`
- 全量回归：`make backend-test`（带 TEST_DATABASE_URL + 60s 超时）
- acceptance：`PYTHONPATH=backend timeout 180s ./.venv/bin/python -m scripts.acceptance_browser_agent --all --mock-mode llm-timeout-forced --profile rule-fallback-only --database-url postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_baseline_20260425 --results-dir backend/results/candidate-cve-evidence-first-phase-b-mock`
- compare：`PYTHONPATH=backend timeout 60s ./.venv/bin/python -m scripts.acceptance_browser_agent --baseline-report backend/results/baseline-cve-agent-boundary-refactor-mock/acceptance_report.json --candidate-report backend/results/candidate-cve-evidence-first-phase-b-mock/acceptance_report.json`

PostgreSQL：`make pg-up`（容器 infra-postgres-1）。

## Research References

（待补：candidate_generator 的 fix_commit 多 host URL 构造模式可能需要从 reference_matcher 现有形态反向归纳，留作 Step 1 实现细节，不需要外部研究。）
