from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from app.cve.patch_evidence import PatchEvidence
from app.cve.reference_matcher import match_reference_url

logger = logging.getLogger(__name__)

_GITHUB_REPO_RE = re.compile(r"^/([^/]+/[^/]+)")


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


def _build_commit_patch_url(commit_sha: str, repo_hint: str | None) -> str | None:
    """尝试从 commit SHA 和 repo_hint 构造 patch URL。"""
    if not repo_hint:
        return None
    parsed = urlparse(repo_hint)
    if parsed.netloc == "github.com":
        match = _GITHUB_REPO_RE.match(parsed.path)
        if match:
            repo_path = match.group(1).rstrip("/")
            return f"https://github.com/{repo_path}/commit/{commit_sha}.patch"
    return None


def generate_candidates(
    evidence_list: list[PatchEvidence],
) -> list[PatchCandidate]:
    """从 PatchEvidence 列表生成 PatchCandidate 列表。

    阶段 A 只实现基础转换：
    - fix_commit evidence -> commit_patch candidate（如果能构造 patch URL）
    - reference_url evidence + reference_matcher -> 对应类型的 candidate
    - 其他 evidence -> 暂不生成 candidate（留给阶段 B）
    """
    # 延迟导入以打破 circular import
    from app.cve.canonical import canonicalize_candidate_url  # noqa: C0415

    candidates_by_key: dict[str, PatchCandidate] = {}

    for ev in evidence_list:
        if ev.evidence_type == "fix_commit" and ev.commit_sha:
            patch_url = _build_commit_patch_url(ev.commit_sha, ev.repo_hint)
            if patch_url:
                candidate_url = patch_url.removesuffix(".patch")
                candidate = PatchCandidate(
                    candidate_type="commit_patch",
                    candidate_url=candidate_url,
                    patch_url=patch_url,
                    patch_type="github_commit_patch",
                    canonical_key=canonicalize_candidate_url(candidate_url),
                    evidence_sources=(ev.raw_field_path,) if ev.raw_field_path else (),
                    score=ev.authority_score,
                    confidence="high",
                    downloadable=True,
                )
                existing = candidates_by_key.get(candidate.canonical_key)
                if existing is None or existing.score < candidate.score:
                    candidates_by_key[candidate.canonical_key] = candidate

        elif ev.evidence_type == "reference_url" and ev.url:
            match = match_reference_url(ev.url)
            if match is None:
                continue
            patch_type = match["patch_type"]
            candidate_url = match["candidate_url"]
            if "commit" in patch_type:
                ctype = "commit_patch"
            elif "pull" in patch_type or "merge_request" in patch_type:
                ctype = "pr_patch"
            else:
                ctype = "direct_patch"

            candidate = PatchCandidate(
                candidate_type=ctype,
                candidate_url=candidate_url,
                patch_url=candidate_url,
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
