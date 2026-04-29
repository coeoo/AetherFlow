# Codex 执行指令：阶段 A — Evidence-First 基础层

## 你的角色

你是 AetherFlow 项目的实现者。你的任务是执行阶段 A：建立 Evidence-First 基础层。
这是一个纯增量改造，不改变任何现有运行行为。

## 背景

AetherFlow 的 CVE Patch Agent 正在从 Browser-Agent-first 架构演进为
Evidence-first 分层架构。完整的架构决策记录在：
`docs/design/adr-evidence-first-patch-engine.md`

阶段 A 的目标是：把结构化证据收集起来，写入 state 和 source trace metadata，
但不改变最终结果。所有现有 acceptance 行为必须保持不变。

## 项目结构

关键文件位置：
```
backend/app/cve/
├── seed_sources.py          # 4 源数据获取，SeedSourceResult dataclass
├── seed_resolver.py         # 多源合并，SeedReference dataclass，SOURCE_AUTHORITY
├── reference_matcher.py     # URL 规则匹配，CANDIDATE_PRIORITY
├── patch_downloader.py      # 下载 + 验证
├── agent_graph.py           # LangGraph 图定义
├── agent_nodes.py           # 图节点实现（resolve_seeds_node 等）
├── agent_state.py           # AgentState TypedDict
├── agent_evidence.py        # 证据辅助函数
├── agent_policy.py          # 预算控制
├── decisions/
│   ├── candidate_judge.py   # LLM 候选判断
│   ├── navigation.py        # LLM 导航决策
│   └── fallback.py          # 规则降级决策
├── source_trace.py          # source_trace 记录
└── ...

backend/tests/
├── test_seed_sources.py
├── test_seed_resolver.py
├── test_reference_matcher.py
├── test_patch_downloader.py
├── test_cve_agent_schema_contract.py
└── ...

backend/app/models/cve.py    # SQLAlchemy 模型
```

## 当前数据结构（你需要了解的）

### SeedSourceResult（seed_sources.py）
```python
@dataclass(frozen=True)
class SeedSourceResult:
    source: str                    # "cve_official" | "osv" | "github_advisory" | "nvd"
    status: str                    # "success" | "not_found" | "failed"
    status_code: int | None
    reference_count: int
    error_kind: str | None
    error_message: str | None
    references: list[str]          # 只有 URL 列表，没有语义信息
    request_url: str
```

### SeedReference（seed_resolver.py）
```python
@dataclass(frozen=True)
class SeedReference:
    url: str
    source: str
    authority_score: int
```

### 当前 extract 函数的问题

`_extract_cve_official_references()` 只提取 `containers.cna.references[].url`
和 `containers.cveProgram.references[].url`。它丢掉了：
- `containers.adp[].references[]`（CISA Vulnrichment 数据）
- `containers.cna.affected[].versions[]` 中 `versionType == "git"` 的 fix SHA
- reference 上的 `tags` 字段（如 `["patch"]`、`["vendor-advisory"]`）

`_extract_osv_references()` 只提取 `references[].url`。它丢掉了：
- `references[].type`（如 "FIX"、"ADVISORY"、"WEB"）
- `affected[].ranges[].events[]`（`introduced` 和 `fixed` commit/version）
- `affected[].ranges[].type`（"GIT"、"SEMVER"、"ECOSYSTEM"）
- `affected[].package.name` 和 `affected[].package.ecosystem`

`_extract_github_advisory_references()` 只提取 URL。它丢掉了：
- `vulnerabilities[].first_patched_version`
- `vulnerabilities[].package.name` 和 `vulnerabilities[].package.ecosystem`
- `source_code_location`（仓库地址）
- `identifiers[]`（CVE ID 等）

`_extract_nvd_references()` 只提取 `references[].url`。它丢掉了：
- reference 上的 `tags`
- `source` / `name`
- 后续 evidence 归一化可用的语义标签

## 你需要做的事情

### 任务 1：扩展 SeedSourceResult

在 `seed_sources.py` 中，给 `SeedSourceResult` 增加三个可选字段：

```python
@dataclass(frozen=True)
class StructuredReference:
    url: str
    ref_type: str | None = None      # OSV: "FIX" / "ADVISORY" / "WEB" 等
    tags: tuple[str, ...] = ()       # CVE: ("patch",) / ("vendor-advisory",) 等
    source: str = ""                 # 来自哪个数据源

@dataclass(frozen=True)
class FixCommitEvidence:
    commit_sha: str
    repo_hint: str | None = None     # 从 URL 或 affected 推断的仓库
    source: str = ""
    field_path: str = ""             # 原始 JSON 路径

@dataclass(frozen=True)
class FixedVersionEvidence:
    version: str
    version_type: str | None = None  # "git" / "semver" / "ecosystem"
    package_name: str | None = None
    package_ecosystem: str | None = None
    repo_hint: str | None = None
    source: str = ""
    field_path: str = ""

@dataclass(frozen=True)
class SeedSourceResult:
    source: str
    status: str
    status_code: int | None
    reference_count: int
    error_kind: str | None
    error_message: str | None
    references: list[str]                              # 保留，向后兼容
    request_url: str
    structured_references: list[StructuredReference] = field(default_factory=list)
    fix_commits: list[FixCommitEvidence] = field(default_factory=list)
    fixed_versions: list[FixedVersionEvidence] = field(default_factory=list)
```

注意：`SeedSourceResult` 当前是 `frozen=True` 的 dataclass。新字段必须有默认值，
确保所有现有构造调用（`_success_result`、`_not_found_result`、`_failed_result`）
不需要修改签名。

### 任务 2：增强 CVE 官方数据提取

在 `_extract_cve_official_references()` 中（或新增辅助函数），增加：

1. 解析 `containers.adp[].references[]`，合并到 references 列表
2. 提取每个 reference 的 `tags` 字段
3. 解析 `containers.cna.affected[].versions[]`：
   - 当 `versionType == "git"` 时，`lessThan` 字段是 fix commit SHA
   - 构造 `FixCommitEvidence`
4. 输出 `structured_references` 和 `fix_commits`

CVE 官方 API 响应结构示例（你需要处理的字段）：
```json
{
  "containers": {
    "cna": {
      "references": [
        {"url": "https://...", "tags": ["patch"]}
      ],
      "affected": [
        {
          "versions": [
            {
              "versionType": "git",
              "lessThan": "abc123def456...",
              "status": "affected",
              "version": "0"
            }
          ]
        }
      ]
    },
    "adp": [
      {
        "references": [
          {"url": "https://...", "tags": ["patch"]}
        ]
      }
    ]
  }
}
```

### 任务 3：增强 OSV 数据提取

在 `_extract_osv_references()` 中（或新增辅助函数），增加：

1. 提取 `references[].type`
2. 解析 `affected[].ranges[].events[]`：
   - `type == "GIT"` 时，`events[].fixed` 是 commit SHA
   - `type == "SEMVER"` 或 `"ECOSYSTEM"` 时，`events[].fixed` 是版本号
3. 提取 `affected[].package.name` 和 `affected[].package.ecosystem`
4. 从 `affected[].ranges[].repo` 提取仓库地址（如果有）
5. 输出 `structured_references`、`fix_commits`、`fixed_versions`

OSV API 响应结构示例：
```json
{
  "references": [
    {"type": "FIX", "url": "https://github.com/org/repo/commit/abc123"},
    {"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-..."}
  ],
  "affected": [
    {
      "package": {"name": "linux", "ecosystem": "Linux"},
      "ranges": [
        {
          "type": "GIT",
          "repo": "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
          "events": [
            {"introduced": "aaa111"},
            {"fixed": "bbb222"}
          ]
        }
      ]
    }
  ]
}
```

### 任务 4：增强 GHSA 数据提取

在 `_extract_github_advisory_references()` 中（或新增辅助函数），增加：

1. 提取 `vulnerabilities[].first_patched_version`
2. 提取 `vulnerabilities[].package.name` 和 `vulnerabilities[].package.ecosystem`
3. 提取 `source_code_location`（仓库地址）
4. 输出 `structured_references`、`fixed_versions`

GHSA API 响应结构示例：
```json
[
  {
    "ghsa_id": "GHSA-xxxx-xxxx-xxxx",
    "html_url": "https://github.com/advisories/GHSA-...",
    "references": ["https://..."],
    "vulnerabilities": [
      {
        "package": {"name": "gnutls", "ecosystem": "npm"},
        "first_patched_version": "3.7.7",
        "vulnerable_version_range": "< 3.7.7"
      }
    ],
    "source_code_location": "https://github.com/gnutls/gnutls"
  }
]
```

### 任务 5：增强 NVD 数据提取

在 `_extract_nvd_references()` 中（或新增辅助函数），增加：

1. 提取每个 reference 的 `tags`
2. 提取 `source` / `name`（如果有）
3. 输出 `structured_references`

注意：NVD 在阶段 A 不要求提取新的 `fix_commits` / `fixed_versions`，
只要求保留 reference 语义标签，便于后续 evidence 归一化。

### 任务 6：新增 patch_evidence.py

创建 `backend/app/cve/patch_evidence.py`，定义统一的 evidence 模型：

```python
@dataclass(frozen=True)
class PatchEvidence:
    evidence_type: str          # "reference_url" | "fix_commit" | "fixed_version"
                                # | "advisory" | "affected_range"
    source: str                 # "cve_official" | "osv" | "github_advisory" | "nvd"
    url: str | None = None
    commit_sha: str | None = None
    version: str | None = None
    repo_hint: str | None = None
    semantic_tag: str | None = None  # "patch" | "FIX" | "advisory" | "first_patched_version"
    authority_score: int = 0
    confidence: str = "medium"       # "high" | "medium" | "low"
    raw_field_path: str = ""
```

并实现一个归一化函数：

```python
def normalize_seed_to_evidence(
    seed_results: list[SeedSourceResult],
) -> list[PatchEvidence]:
    """将多个 SeedSourceResult 归一化为统一的 PatchEvidence 列表。"""
    ...
```

这个函数应该：
- 从 `structured_references` 中生成 `reference_url` 类型的 evidence
- 从 `fix_commits` 中生成 `fix_commit` 类型的 evidence
- 从 `fixed_versions` 中生成 `fixed_version` 类型的 evidence
- 带 `[patch]` 或 `[FIX]` 标签的 reference -> confidence = "high"
- fix_commit 类型 -> confidence = "high"
- 普通 reference -> confidence = "medium"
- 去重（同一个 URL 或 commit SHA 只保留 authority_score 最高的）

### 任务 7：新增 candidate_generator.py（骨架）

创建 `backend/app/cve/candidate_generator.py`，定义候选模型和生成函数骨架：

```python
@dataclass(frozen=True)
class PatchCandidate:
    candidate_type: str         # "direct_patch" | "commit_patch" | "pr_patch"
                                # | "version_window" | "exploration_seed"
    candidate_url: str
    patch_url: str | None
    patch_type: str
    canonical_key: str
    evidence_sources: tuple[str, ...]  # evidence 的 raw_field_path 列表
    score: int = 0
    confidence: str = "medium"
    downloadable: bool = False


def generate_candidates(
    evidence_list: list[PatchEvidence],
) -> list[PatchCandidate]:
    """从 PatchEvidence 列表生成 PatchCandidate 列表。

    阶段 A 只实现基础转换：
    - fix_commit evidence -> commit_patch candidate（如果能构造 patch URL）
    - reference_url evidence + reference_matcher -> 对应类型的 candidate
    - 其他 evidence -> 暂不生成 candidate（留给阶段 B）
    """
    ...
```

阶段 A 只需要实现基础转换逻辑。复杂的评分和版本窗口候选留给阶段 B。

### 任务 8：将新数据写入 AgentState（不改变行为）

在 `agent_state.py` 的 `AgentState` TypedDict 中增加可选字段：

```python
class AgentState(TypedDict, total=False):
    # ... 现有字段保持不变 ...
    patch_evidence: list[dict[str, object]]      # PatchEvidence 序列化
    patch_candidates: list[dict[str, object]]     # PatchCandidate 序列化
```

在 `agent_nodes.py` 的 `resolve_seeds_node` 中，在现有逻辑之后，
调用 `normalize_seed_to_evidence()` 和 `generate_candidates()`，
将结果写入 state。但不改变后续节点的行为。

明确要求：

- `build_initial_frontier_node` 不读取 `patch_evidence`
- `agent_decide_node` 不读取 `patch_candidates`
- `download_and_validate_node` 不读取这些新字段
- 新字段仅用于阶段 A 的观测和后续阶段的接口预留

### 任务 9：将结构化统计写入 source trace（不改变接口）

在 `seed_resolver.py` 中，保持 `source_type="cve_seed_resolve"` 不变，仅向
`response_meta_json` 增量写入兼容统计字段，例如：

```python
{
    "structured_reference_count": 12,
    "fix_commit_count": 2,
    "fixed_version_count": 3,
}
```

要求：

- 不修改数据库 schema
- 不新增新的 `SourceFetchRecord.source_type`
- 不改已有 `request_snapshot_json` / `response_meta_json` 的主结构
- 新字段只增量附加，不删除、不重命名现有字段

### 任务 10：测试

1. 为 `StructuredReference`、`FixCommitEvidence`、`FixedVersionEvidence` 写单元测试
2. 为增强后的 `_extract_cve_official_references()` 写测试，覆盖：
   - 有 `adp` 的情况
   - 有 `affected[].versions[]` 且 `versionType == "git"` 的情况
   - 没有这些字段的情况（向后兼容）
3. 为增强后的 `_extract_osv_references()` 写测试，覆盖：
   - 有 `affected[].ranges[].events[].fixed` 的情况
   - `type == "GIT"` 和 `type == "SEMVER"` 的情况
4. 为增强后的 `_extract_github_advisory_references()` 写测试
5. 为增强后的 `_extract_nvd_references()` 写测试
6. 为 `normalize_seed_to_evidence()` 写测试
7. 为 `generate_candidates()` 写测试
8. 为 `seed_resolver.py` 新增的 trace 统计字段写测试
9. 先跑 targeted tests，再决定是否跑全量：
   ```bash
   timeout 60s ./.venv/bin/python -m pytest \
     backend/tests/test_seed_sources.py \
     backend/tests/test_seed_resolver.py \
     backend/tests/test_cve_agent_graph.py \
     -q
   ```
10. 如 targeted tests 通过，再视情况补跑：
   ```bash
   timeout 60s ./.venv/bin/python -m pytest backend/tests -x -q
   ```

## 硬约束

1. **不改变任何现有运行行为**。所有现有 acceptance 场景的结果必须完全一致。
2. **不修改 LangGraph 图结构**。`agent_graph.py` 的节点和边不变。
3. **不修改 `patch_downloader.py`**。
4. **不修改 `decisions/` 下的任何文件**。
5. **不修改数据库 schema**。新数据只写入现有 JSON 字段：`SourceFetchRecord.response_meta_json` 和 `AgentState` 运行态内存字段。
6. **不引入新的外部依赖**。
7. **`SeedSourceResult` 的 `references: list[str]` 字段必须保留且内容不变**。
   新字段是增量添加，不替代旧字段。
8. **所有新增 dataclass 使用 `frozen=True`**。
9. **所有新增函数必须有 type hints**。
10. **测试文件命名遵循现有模式**：`test_patch_evidence.py`、`test_candidate_generator.py`。
11. **不改现有外部契约**：`run.phase`、`stop_reason`、`source_type="cve_seed_resolve"`、`direct_candidates`、`decision_history` 保持现状。

## 验收检查

完成后，运行以下命令确认：

```bash
timeout 60s ./.venv/bin/python -m pytest \
  backend/tests/test_seed_sources.py \
  backend/tests/test_seed_resolver.py \
  backend/tests/test_cve_agent_graph.py \
  -q
```

如 targeted tests 通过，再按需补跑全量 backend tests。

## 代码风格

参考现有代码风格：
- 使用 `from __future__ import annotations`
- dataclass 用 `frozen=True`
- 私有函数用 `_` 前缀
- 日志用 `logging.getLogger(__name__)`
- 错误消息用中文
- 类型注解用 `str | None` 而非 `Optional[str]`
