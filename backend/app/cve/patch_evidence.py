from __future__ import annotations

import logging
from dataclasses import dataclass

from app.cve.seed_sources import SeedSourceResult

logger = logging.getLogger(__name__)

# Authority scores aligned with seed_resolver.SOURCE_AUTHORITY
_SOURCE_AUTHORITY: dict[str, int] = {
    "cve_official": 100,
    "osv": 80,
    "github_advisory": 70,
    "nvd": 60,
}

# Tags that indicate high confidence
_HIGH_CONFIDENCE_TAGS: frozenset[str] = frozenset({
    "patch", "Patch", "FIX",
})


@dataclass(frozen=True)
class PatchEvidence:
    evidence_type: str  # "reference_url" | "fix_commit" | "fixed_version"
    source: str         # "cve_official" | "osv" | "github_advisory" | "nvd"
    url: str | None = None
    commit_sha: str | None = None
    version: str | None = None
    repo_hint: str | None = None
    semantic_tag: str | None = None
    authority_score: int = 0
    confidence: str = "medium"
    raw_field_path: str = ""


def _determine_confidence(
    *,
    tags: tuple[str, ...] = (),
    ref_type: str | None = None,
    evidence_type: str,
) -> str:
    """Determine confidence level based on semantic tags and evidence type."""
    if evidence_type == "fix_commit":
        return "high"
    for tag in tags:
        if tag in _HIGH_CONFIDENCE_TAGS:
            return "high"
    if ref_type in _HIGH_CONFIDENCE_TAGS:
        return "high"
    return "medium"


def normalize_seed_to_evidence(
    seed_results: list[SeedSourceResult],
) -> list[PatchEvidence]:
    """将多个 SeedSourceResult 归一化为统一的 PatchEvidence 列表。

    去重规则：同一个 URL 或 commit SHA 只保留 authority_score 最高的。
    """
    evidence_by_key: dict[str, PatchEvidence] = {}

    for result in seed_results:
        if result.status != "success":
            continue
        authority = _SOURCE_AUTHORITY.get(result.source, 0)

        # structured_references -> reference_url evidence
        for sref in result.structured_references:
            semantic_tag = sref.ref_type
            if not semantic_tag and sref.tags:
                semantic_tag = sref.tags[0]
            confidence = _determine_confidence(
                tags=sref.tags,
                ref_type=sref.ref_type,
                evidence_type="reference_url",
            )
            ev = PatchEvidence(
                evidence_type="reference_url",
                source=result.source,
                url=sref.url,
                semantic_tag=semantic_tag,
                authority_score=authority,
                confidence=confidence,
            )
            key = f"url:{sref.url}"
            existing = evidence_by_key.get(key)
            if existing is None or existing.authority_score < authority:
                evidence_by_key[key] = ev

        # fix_commits -> fix_commit evidence
        for fc in result.fix_commits:
            ev = PatchEvidence(
                evidence_type="fix_commit",
                source=result.source,
                commit_sha=fc.commit_sha,
                repo_hint=fc.repo_hint,
                authority_score=authority,
                confidence="high",
                raw_field_path=fc.field_path,
            )
            key = f"commit:{fc.commit_sha}"
            existing = evidence_by_key.get(key)
            if existing is None or existing.authority_score < authority:
                evidence_by_key[key] = ev

        # fixed_versions -> fixed_version evidence
        for fv in result.fixed_versions:
            ev = PatchEvidence(
                evidence_type="fixed_version",
                source=result.source,
                version=fv.version,
                repo_hint=fv.repo_hint,
                semantic_tag=fv.version_type,
                authority_score=authority,
                confidence="medium",
                raw_field_path=fv.field_path,
            )
            key = f"version:{fv.version}:{fv.package_name or ''}"
            existing = evidence_by_key.get(key)
            if existing is None or existing.authority_score < authority:
                evidence_by_key[key] = ev

    return list(evidence_by_key.values())
