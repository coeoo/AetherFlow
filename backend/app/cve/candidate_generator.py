from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from app.cve.patch_evidence import PatchEvidence
from app.cve.reference_matcher import match_reference_url

logger = logging.getLogger(__name__)

_COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)
_GITLAB_LIKE_HOSTS: frozenset[str] = frozenset({
    "gitlab.com",
    "gitlab.gnome.org",
    "gitlab.freedesktop.org",
    "salsa.debian.org",
})


@dataclass(frozen=True)
class PatchCandidate:
    candidate_type: str         # "direct_patch" | "commit_patch" | "pr_patch"
                                # | "version_window" | "exploration_seed"
    candidate_url: str
    patch_url: str | None
    patch_type: str
    canonical_key: str
    evidence_sources: tuple[str, ...]  # evidence raw_field_path 列表
    score: int = 0
    confidence: str = "medium"
    downloadable: bool = False


def _normalize_repo_hint(repo_hint: str | None) -> str | None:
    """规范化 repo_hint 为可合成 URL 的 base：
    - 必须是 http(s) URL；裸 owner/repo 跳过（不全局猜域名）
    - 剥 trailing slash 与 ``.git`` 后缀
    - 返回标准化 base URL，None 表示无法合成
    """
    if not repo_hint:
        return None
    if not repo_hint.startswith(("http://", "https://")):
        return None
    base = repo_hint.rstrip("/")
    if base.endswith(".git"):
        base = base[:-4]
    return base or None


def _commit_page_url_from_evidence(ev: PatchEvidence) -> str | None:
    """根据 fix_commit evidence 合成 commit page URL（不带 ``.patch`` 后缀）。

    返回 None 表示无法合成（commit_sha 非法 / repo_hint 缺失或裸 owner/repo / 未知 host）。
    合成的 URL 交给 :func:`match_reference_url` 推断 patch_type 与可下载 patch URL，
    避免在本模块维护第二份 host 知识。
    """
    if not ev.commit_sha or not _COMMIT_SHA_RE.fullmatch(ev.commit_sha):
        return None
    base = _normalize_repo_hint(ev.repo_hint)
    if base is None:
        return None
    netloc = urlparse(base).netloc.lower()
    sha = ev.commit_sha
    if netloc == "github.com":
        return f"{base}/commit/{sha}"
    if netloc in _GITLAB_LIKE_HOSTS:
        return f"{base}/-/commit/{sha}"
    if netloc == "git.kernel.org":
        # 用 stable 短链；matcher 会重写为可下载的 stable patch URL。
        return f"https://git.kernel.org/stable/c/{sha}"
    if netloc == "bitbucket.org":
        return f"{base}/commits/{sha}"
    if netloc == "gitee.com":
        return f"{base}/commit/{sha}"
    if netloc == "android.googlesource.com":
        return f"{base}/+/{sha}"
    return None


def _candidate_type_from_patch_type(patch_type: str) -> str:
    if "commit" in patch_type:
        return "commit_patch"
    if "pull" in patch_type or "merge_request" in patch_type:
        return "pr_patch"
    return "direct_patch"


def generate_candidates(
    evidence_list: list[PatchEvidence],
) -> list[PatchCandidate]:
    """从 PatchEvidence 列表生成 PatchCandidate 列表。

    支持的 evidence_type：
    - ``fix_commit`` + 合法 commit_sha + http(s) repo_hint：合成对应 host 的 commit page URL，
      调 :func:`match_reference_url` 拿到 patch_type 与可下载 patch URL。
    - ``reference_url`` + ``url``：直接调 :func:`match_reference_url`（暂不 normalize_frontier_url；
      留给 Phase C 入口补齐，详情见 phase-b4 prd Q7）。
    - 其他类型（``fixed_version``、``advisory`` 等）暂不生成候选，留待后续阶段。

    去重策略：按 :func:`canonicalize_candidate_url` 的 canonical_key 保留最高 score 候选。
    """
    # 延迟导入以打破 circular import
    from app.cve.canonical import canonicalize_candidate_url  # noqa: C0415

    candidates_by_key: dict[str, PatchCandidate] = {}

    for ev in evidence_list:
        commit_page_url: str | None = None
        target_url: str | None = None

        if ev.evidence_type == "fix_commit":
            commit_page_url = _commit_page_url_from_evidence(ev)
            if commit_page_url is None:
                continue
            target_url = commit_page_url
        elif ev.evidence_type == "reference_url" and ev.url:
            # 注：codex review 建议在此处先 normalize_frontier_url 与 baseline seed-derived
            # 路径完全等价（剥 fragment / 多余空白 / openwall http→https）。但 mock-mode
            # acceptance 实测发现对 CVE-2022-2509 反向退化（candidate_missing），
            # 推测是 evidence URL 经 normalize 后 candidate_url 与既有 canonical_key 形态错位，
            # 触发下游 pick 顺序变化。Phase C 入口前需补齐这一归一化（含 acceptance 回归保护），
            # 详情见 prd.md Q7。
            target_url = ev.url
        else:
            continue

        match = match_reference_url(target_url)
        if match is None:
            continue

        patch_type = match["patch_type"]
        downloadable_url = match["candidate_url"]
        # candidate_url 与 patch_url 统一为 matcher 输出的可下载 URL，
        # 让 build_initial_frontier_node 写入 CVECandidateArtifact.candidate_url 时
        # 直接是下游 patch_downloader 可消费的形态（避免 fix_commit 与 reference_url
        # 两条路径产生不同的 candidate_url 语义）。
        candidate_url = downloadable_url
        patch_url = downloadable_url

        candidate = PatchCandidate(
            candidate_type=_candidate_type_from_patch_type(patch_type),
            candidate_url=candidate_url,
            patch_url=patch_url,
            patch_type=patch_type,
            canonical_key=canonicalize_candidate_url(candidate_url),
            evidence_sources=(ev.raw_field_path,) if ev.raw_field_path else (),
            score=ev.authority_score,
            confidence=ev.confidence,
            downloadable=True,
        )
        existing = candidates_by_key.get(candidate.canonical_key)
        if existing is None or existing.score < candidate.score:
            candidates_by_key[candidate.canonical_key] = candidate

    return list(candidates_by_key.values())
