# 技术决策沉淀（phase-b4-frontier-full-takeover）

> 本文件是 trellis-implement / trellis-check 的隐含约束清单，PRD 不重复展开。

---

## 0. Codex 协作时机 1 反馈采纳记录

> Codex SESSION_ID `019de209-4087-7241-ad0e-84c26a2aa5df`（用于后续续接）

### 已采纳（影响实施）

1. **AOSP 静默退化**：`reference_matcher.CANDIDATE_PRIORITY` 含 `aosp_commit_patch: 90`，但 `candidate_scoring._PATCH_TYPE_BASE_SCORE` 缺。委托后 AOSP 从 90 退到 50，`fallback.py:184` 的 `>=90` 阈值对 AOSP commit 失效。**Step 1 必须先补齐 candidate_scoring AOSP 基础分**。
2. **fix_commit URL 合成必须是 commit page URL，不带 `.patch`**：`match_reference_url` 优先匹配 `.patch/.diff/.debdiff` 后缀（reference_matcher.py:32-46），如果合成带 `.patch` 会被识别为 generic `patch` 而非 `github_commit_patch`。Step 2 合成时一律用 commit page URL 形态（不带 `.patch`），交给 matcher 输出 PatchType。
3. **裸 owner/repo 缩写不猜 host**：repo_hint 三档处理 — 完整 URL 正常合成、provider 前缀缩写（`github:owner/repo` 等）安全合成、裸 `owner/repo` 默认跳过（不全局猜域名，避免误合成）。
4. **patch_type 命名空间从 reference_matcher 暴露公开常量**：新增 `reference_matcher.KNOWN_PATCH_TYPES` 公开常量，`candidate_scoring._PATCH_TYPE_BASE_SCORE` 用同集合 key，acceptance compare 同步引用。避免第三份真相。
5. **桥接测试改写为 patch_evidence 输入**：原 `state["patch_candidates"]` 注入桥接形态被取代；新测试用 `state["patch_evidence"]` 输入，断言 generate_candidates 行为 + 双来源 evidence 合并。
6. **acceptance_browser_agent._PATCH_TYPE_PRIORITY 必须同步**：当前 acceptance_browser_agent.py:81 缺 bitbucket_commit_patch / bitbucket_pull_patch / gitee_commit_patch / aosp_commit_patch / bugzilla_attachment_patch。Step 1 同步补齐，否则 `patch_quality_degraded` 对新 host 评分失真。
7. **commit 拆分升级为 3 个**：
   - commit 1：`重构(cve): 统一候选类型优先级来源`（candidate_scoring 公开 type-only priority + 补 AOSP + reference_matcher 委托 + acceptance script priority 同步 + 双源一致性测试）
   - commit 2：`功能(cve): 扩展 fix_commit 多 host 候选生成`（candidate_generator URL 合成 + 多 host 支持 + 单元测试）
   - commit 3：`重构(cve): build_initial_frontier 接管 candidate_generator`（agent_nodes 改造 + 图测试改写 + acceptance 双层验证）
8. **commit 1 标题修订**：原"candidate_scoring 接入主链候选评分"易误解为接入 `score_candidate.total`，改为"统一候选类型优先级来源"。

### Noted（trellis-implement 阶段如遇边界再补）

9. **PatchCandidate provenance 多来源合并**：当 reference_url evidence 与 fix_commit evidence 都命中同一 commit URL 时，candidate_generator 当前按 canonical_key 保留最高 score 一条，可能丢失双 evidence_type 来源。trellis-implement 在实现 generate_candidates 时如能轻量保留 provenance（例如让 PatchCandidate.evidence_sources 累计多个 raw_field_path 而不只是覆盖），就采纳；否则在图测试中接受单源 + 通过 upsert_candidate_artifact 的 evidence merge 在 DB 层兼并。

---

## 1. fix_commit → commit URL 形态映射

`candidate_generator.generate_candidates` 处理 `evidence_type == "fix_commit"` 时，应**重用 `reference_matcher.match_reference_url` 的 host 规则**：先合成对应 host 的 **commit page URL（不带 `.patch`）**，再调 matcher 拿 PatchType + canonical patch_url。**禁止**在 candidate_generator 内部重写第二份 host 知识，**禁止**合成时附加 `.patch`/`.diff` 后缀（会被 matcher 优先吞掉）。

### 各 host 的 commit page URL 合成形态（不带 .patch）

| host | repo_hint 形态 | 合成 commit page URL | matcher 命中 patch_type | matcher 输出 candidate_url 形态 |
|---|---|---|---|---|
| `github.com` | `https://github.com/<owner>/<repo>` | `https://github.com/<owner>/<repo>/commit/<sha>` | `github_commit_patch` | 同 URL + `.patch` |
| `gitlab.com` / `gitlab.gnome.org` / `gitlab.freedesktop.org` / `salsa.debian.org` | `https://<host>/<group>/<repo>` 或多级 group | `https://<host>/<group>/.../<repo>/-/commit/<sha>` | `gitlab_commit_patch` | 同 URL + `.patch` |
| `git.kernel.org` | `https://git.kernel.org` 或 stable repo | `https://git.kernel.org/stable/c/<sha>`（短链；长链 `/.../commit?id=<sha>` 也可由 matcher 处理） | `kernel_commit_patch` | matcher 重写为 `/pub/scm/.../patch/?id=<sha>` |
| `bitbucket.org` | `https://bitbucket.org/<owner>/<repo>` | `https://bitbucket.org/<owner>/<repo>/commits/<sha>`（matcher 同时接受 `commit` 与 `commits`，优先 `commits` 形态） | `bitbucket_commit_patch` | 同 URL + `/raw` |
| `gitee.com` | `https://gitee.com/<owner>/<repo>` | `https://gitee.com/<owner>/<repo>/commit/<sha>` | `gitee_commit_patch` | 同 URL + `.patch` |
| `android.googlesource.com` | `https://android.googlesource.com/<repo-path>` | `https://android.googlesource.com/<repo-path>/+/<sha>` | `aosp_commit_patch` | 同 URL + `.patch` |

### 实现伪代码

```python
def _commit_url_from_evidence(ev: PatchEvidence) -> str | None:
    if not ev.repo_hint or not ev.commit_sha:
        return None
    # 校验 sha 是 7-40 位 hex
    if not re.fullmatch(r"[0-9a-f]{7,40}", ev.commit_sha, re.IGNORECASE):
        return None
    # repo_hint 必须是 URL；裸 owner/repo 不猜 host
    if not ev.repo_hint.startswith(("http://", "https://")):
        return None
    parsed = urlparse(ev.repo_hint)
    netloc = parsed.netloc.lower()
    base = ev.repo_hint.rstrip("/")
    if netloc == "github.com":
        return f"{base}/commit/{ev.commit_sha}"  # 不带 .patch
    if netloc in {"gitlab.com", "gitlab.gnome.org", "gitlab.freedesktop.org", "salsa.debian.org"}:
        return f"{base}/-/commit/{ev.commit_sha}"
    if netloc == "git.kernel.org":
        return f"https://git.kernel.org/stable/c/{ev.commit_sha}"
    if netloc == "bitbucket.org":
        return f"{base}/commits/{ev.commit_sha}"  # matcher 同时支持 commit/commits
    if netloc == "gitee.com":
        return f"{base}/commit/{ev.commit_sha}"
    if netloc == "android.googlesource.com":
        return f"{base}/+/{ev.commit_sha}"
    return None  # 未知 host 跳过
```

### 注意

- repo_hint 可能是带 `/` 结尾或带 `.git` 后缀；trim 时同时处理（可加 `.removesuffix(".git")`）
- repo_hint 缺 scheme 时跳过（不要全局猜 https://github.com）
- commit_sha 已在 PatchEvidence 归一化阶段做了基本格式校验（`patch_evidence.py`），合成时再做一次 hex 长度校验避免 tag/branch 误合成

---

## 2. patch_type 命名空间清单

`candidate_generator.generate_candidates` 输出的所有 PatchCandidate.patch_type 必须 ∈ 以下集合。测试断言显式覆盖。

| patch_type | 来源 | get_candidate_priority |
|---|---|---|
| `github_commit_patch` | reference_url GitHub commit / fix_commit github.com | 100 |
| `gitlab_commit_patch` | reference_url GitLab commit / fix_commit gitlab.* | 100 |
| `kernel_commit_patch` | reference_url kernel.org / fix_commit git.kernel.org | 100 |
| `bitbucket_commit_patch` | reference_url bitbucket commit / fix_commit bitbucket.org | 95 |
| `gitee_commit_patch` | reference_url gitee commit / fix_commit gitee.com | 90 |
| `aosp_commit_patch` | reference_url AOSP commit / fix_commit android.googlesource.com | 90 |
| `github_pull_patch` | reference_url GitHub PR | 90 |
| `gitlab_merge_request_patch` | reference_url GitLab MR | 90 |
| `bitbucket_pull_patch` | reference_url Bitbucket PR | 85 |
| `patch` | reference_url `.patch` 后缀 / `patch=` query | 50（distro URL 降为 20） |
| `diff` | reference_url `.diff` 后缀 / `.diff` query | 50（distro URL 降为 20） |
| `bugzilla_attachment_patch` | reference_url bugzilla allowlist + id | 40 |
| `debdiff` | reference_url `.debdiff` | 20 |

权威来源：`reference_matcher.CANDIDATE_PRIORITY` 字典 + `_DISTRIBUTION_HOSTS` 降权规则。Step 1 双源真相收敛后，权威来源迁移到 `candidate_scoring._PATCH_TYPE_BASE_SCORE`，但数值集合保持一致。

---

## 3. distro 降权语义保持（B.3 收敛细节）

### 问题

`candidate_scoring.score_candidate.total` 是 4 维加权（type / source / discovery / authority），即使 type_score=100 的 github_commit_patch，在缺 source/discovery 信号时 total 可能 ≈ 55-65，**远低于 fallback.py:184 的 `>=90` 高质量阈值**。直接切换会让 fallback 高质量短路失效（silent 退化）。

### 收敛方案

`reference_matcher.get_candidate_priority(patch_type, candidate_url=None)` 内部：

```python
def get_candidate_priority(patch_type: str, candidate_url: str | None = None) -> int:
    from app.cve.candidate_scoring import _score_patch_type, _is_distribution_patch_url
    base = _score_patch_type(patch_type)
    if candidate_url and patch_type in {"patch", "diff", "debdiff"}:
        # 复用旧 distro 降权语义，避免 fallback 阈值漂移
        if _is_distribution_patch_url(candidate_url):
            return 20
    return base
```

### 不切换为 `score_candidate.total` 的原因

- `total` 受 source/discovery/authority 信号影响，会随 evidence 数量变化，不稳定
- fallback 高质量阈值 `>=90` 是基于 type 单维度的产品契约，不应转 4 维加权
- 4 维加权是 candidate_generator 内部去重选择最优候选的工具（见 `candidate_generator.py` 现有 `existing.score < candidate.score` 比较），不是 fallback 阈值的输入

### `_is_distribution_patch_url`

`reference_matcher._is_distribution_patch_url` 当前是真相，candidate_scoring 内部维护重复定义但权重不同（-30 vs -20）。Step 1 让 reference_matcher 的 distro URL 降权 wrapper 仍是 distro URL 语义的真相，candidate_scoring 的 `_DISTRIBUTION_HOST_PATTERNS` 仅用于 source_score 维度（不影响 type-only priority）。两者分工：
- **type-only priority**：`reference_matcher.get_candidate_priority(patch_type)` 走 candidate_scoring 公开 helper（type 维度），用于 `fallback.py:184` 高质量阈值。
- **source_score 维度**：`candidate_scoring.score_candidate.total` 内部用，generator 候选去重的辅助信号。

### Step 1 必需补齐项（来自 codex 反馈）

1. `candidate_scoring._PATCH_TYPE_BASE_SCORE` 新增 `aosp_commit_patch: 90`
2. `reference_matcher` 新增公开 `KNOWN_PATCH_TYPES: frozenset[str]`，由 `CANDIDATE_PRIORITY` 派生
3. `candidate_scoring` 新增公开 `get_type_priority(patch_type: str) -> int`（type 维度），不与 `score_candidate.total` 混淆
4. `reference_matcher.get_candidate_priority` 内部委托 `candidate_scoring.get_type_priority`
5. `acceptance_browser_agent._PATCH_TYPE_PRIORITY`（acceptance_browser_agent.py:81-90）补齐 5 类：bitbucket_commit_patch/95、bitbucket_pull_patch/85、gitee_commit_patch/90、aosp_commit_patch/90、bugzilla_attachment_patch/40
6. 双源一致性测试：每个 patch_type 在 reference_matcher 与 candidate_scoring 间返回相同 type-only priority

---

## 4. 等价契约清单（B.4 完整版后必须保持的字段语义）

`build_initial_frontier_node` 完整版后，`state["direct_candidates"]` 中每个 candidate 必须保持以下字段：

| 字段 | 桥接版来源 | 完整版来源 | 必须等价 |
|---|---|---|---|
| `candidate_url` | matcher 命中 / PatchCandidate.candidate_url | candidate_generator 输出 PatchCandidate.candidate_url | ✅ 同 canonical_key 下值相同 |
| `patch_type` | matcher dict / PatchCandidate.patch_type | PatchCandidate.patch_type | ✅ |
| `canonical_key` | canonicalize_candidate_url(...) | candidate_generator 内部 canonical_key | ✅ |
| `canonical_candidate_key` | 同 canonical_key | 同 canonical_key | ✅ |
| `discovered_from_url` | normalized seed reference URL | normalized seed reference URL（reference_url evidence）或 commit URL（fix_commit evidence） | 兼容（fix_commit 来源会变） |
| `discovery_rule` | matcher / bugzilla_attachment | matcher / bugzilla_attachment | ✅ |
| `source_kind` | "seed" / "seed_enriched" | "seed"（reference_url evidence）/ "seed_enriched"（fix_commit evidence） | ✅ 字面值相同 |
| `evidence_source_count` | persisted evidence_json 回填 | persisted evidence_json 回填 | ✅ |
| `discovery_sources` | persisted evidence_json 回填 | persisted evidence_json 回填 | ✅ |

`cve_candidate_artifacts` 表的 `(run_id, canonical_key)` 唯一约束在完整版下仍保持，候选数 ≤ 桥接版（去重更彻底，因为 generator 内部已去重）。

`decision_history` 不受影响（本任务不动 agent_decide_node）。

---

## 5. acceptance 等价契约

mock-mode + rule-fallback-only profile 下，candidate-cve-evidence-first-phase-b-mock 与 baseline-cve-agent-boundary-refactor-mock 比对必须满足：

- `scenario_count` 一致
- `pass_count` / `fail_count` / `skip_count` 一致
- 每个 scenario 的 `failure_category` 一致（如 baseline 有 fail，candidate 必须同样 fail 同样原因）
- `patch_found_count` 一致
- `patch_url_set` 等价（同 canonical_key 下 URL 集合相同；URL 字符串顺序可以变）
- `high_value_path_regressed=false`
- `patch_quality_degraded=false`
- `duration` 不强制改善（本任务不优化 duration，duration 改善目标在 Phase C）

真实样本 CVE-2024-38545 / CVE-2022-2509 必须满足：
- `final_patch_urls` 集合与 baseline 等价
- `chain_summary` 中 chain status 与 baseline 等价（CVE-2022-2509 仍走 Browser Agent，不被误短路）

---

## 6. commit 拆分契约（升级为 3 个 commit）

| commit | 文件 | 摘要 |
|---|---|---|
| 1 | `backend/app/cve/candidate_scoring.py`、`backend/app/cve/reference_matcher.py`、`backend/scripts/acceptance_browser_agent.py`、`backend/tests/test_reference_matcher.py`、`backend/tests/test_candidate_scoring.py` | `重构(cve): 统一候选类型优先级来源` |
| 2 | `backend/app/cve/candidate_generator.py`、`backend/tests/test_candidate_generator.py` | `功能(cve): 扩展 fix_commit 多 host 候选生成` |
| 3 | `backend/app/cve/agent_nodes.py`、`backend/tests/test_cve_agent_graph.py` | `重构(cve): build_initial_frontier 接管 candidate_generator` |

commit 1 显式说明：仅接入 type-only priority（不接入 `score_candidate.total`），保持 `fallback.py:184 >=90` 阈值语义。

commit 3 commit message 引用 acceptance compare 摘要（mock-mode + CVE-2024-38545 + CVE-2022-2509 三层验证结果）。

**绝对不能混入**（git status 当前 dirty）：
- `.trellis/.template-hashes.json`（工具链）
- `.claude/agents/`、`.claude/commands/`、`.claude/hooks/`、`.claude/settings.json`、`.claude/skills/trellis-*`（本会话工作产物）

`backend/results/candidate-cve-evidence-first-phase-b-mock` / `*-live-CVE-*` 不入 commit；commit 3 message 仅引用 compare summary 摘要。

---

## 7. 子代理执行边界（按 3 commit 拆分重新表述）

- **trellis-implement Step 1（commit 1）**：只动 candidate_scoring + reference_matcher + acceptance_browser_agent + 对应测试。不动 candidate_generator / agent_nodes。
- **trellis-implement Step 2（commit 2）**：只动 candidate_generator + test_candidate_generator。不动 agent_nodes。fix_commit 多 host 必须重用 reference_matcher.match_reference_url 而非重写 host 知识。
- **trellis-implement Step 3（commit 3）**：动 agent_nodes.build_initial_frontier_node + test_cve_agent_graph。dirty 桥接逻辑替换为完整版；桥接测试改写为 patch_evidence 输入。
- **trellis-check 每 commit 后**：核对 acceptance criteria + spec 合规 + commit 拆分清晰；如发现退化必须停下来汇报，不要自动修复。
- **acceptance 双层验证**：commit 3 完成后由主线（不是子代理）执行 mock-mode + 真实样本，结果填入 commit 3 message。
