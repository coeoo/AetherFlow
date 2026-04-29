"""Tests for patch_evidence.normalize_seed_to_evidence."""
from app.cve.patch_evidence import PatchEvidence, normalize_seed_to_evidence
from app.cve.seed_sources import (
    FixCommitEvidence,
    FixedVersionEvidence,
    SeedSourceResult,
    StructuredReference,
)


def _success_result(
    source: str,
    *,
    structured_references: list[StructuredReference] | None = None,
    fix_commits: list[FixCommitEvidence] | None = None,
    fixed_versions: list[FixedVersionEvidence] | None = None,
) -> SeedSourceResult:
    return SeedSourceResult(
        source=source,
        status="success",
        status_code=200,
        reference_count=0,
        error_kind=None,
        error_message=None,
        references=[],
        request_url="https://example.com",
        structured_references=structured_references or [],
        fix_commits=fix_commits or [],
        fixed_versions=fixed_versions or [],
    )


def test_normalize_reference_url_evidence() -> None:
    result = _success_result(
        "cve_official",
        structured_references=[
            StructuredReference(url="https://example.com/patch", tags=("patch",), source="cve_official"),
        ],
    )
    evidence = normalize_seed_to_evidence([result])
    assert len(evidence) == 1
    ev = evidence[0]
    assert ev.evidence_type == "reference_url"
    assert ev.url == "https://example.com/patch"
    assert ev.source == "cve_official"
    assert ev.authority_score == 100
    assert ev.confidence == "high"  # "patch" tag -> high


def test_normalize_fix_commit_evidence() -> None:
    result = _success_result(
        "osv",
        fix_commits=[
            FixCommitEvidence(
                commit_sha="deadbeef",
                repo_hint="https://github.com/org/repo",
                source="osv",
                field_path="affected[].ranges[].events[].fixed",
            ),
        ],
    )
    evidence = normalize_seed_to_evidence([result])
    assert len(evidence) == 1
    ev = evidence[0]
    assert ev.evidence_type == "fix_commit"
    assert ev.commit_sha == "deadbeef"
    assert ev.repo_hint == "https://github.com/org/repo"
    assert ev.confidence == "high"
    assert ev.authority_score == 80


def test_normalize_fixed_version_evidence() -> None:
    result = _success_result(
        "github_advisory",
        fixed_versions=[
            FixedVersionEvidence(
                version="2.0.1",
                package_name="pkg",
                package_ecosystem="npm",
                source="github_advisory",
                field_path="vulnerabilities[].first_patched_version",
            ),
        ],
    )
    evidence = normalize_seed_to_evidence([result])
    assert len(evidence) == 1
    ev = evidence[0]
    assert ev.evidence_type == "fixed_version"
    assert ev.version == "2.0.1"
    assert ev.confidence == "medium"
    assert ev.authority_score == 70


def test_normalize_deduplicates_by_url_keeping_highest_authority() -> None:
    """Same URL from two sources: keep the one with higher authority."""
    cve_result = _success_result(
        "cve_official",
        structured_references=[
            StructuredReference(url="https://example.com/fix", source="cve_official"),
        ],
    )
    nvd_result = _success_result(
        "nvd",
        structured_references=[
            StructuredReference(url="https://example.com/fix", source="nvd"),
        ],
    )
    evidence = normalize_seed_to_evidence([cve_result, nvd_result])
    assert len(evidence) == 1
    assert evidence[0].source == "cve_official"
    assert evidence[0].authority_score == 100


def test_normalize_deduplicates_commits_by_sha() -> None:
    osv_result = _success_result(
        "osv",
        fix_commits=[
            FixCommitEvidence(commit_sha="abc123", source="osv", field_path="osv.path"),
        ],
    )
    cve_result = _success_result(
        "cve_official",
        fix_commits=[
            FixCommitEvidence(commit_sha="abc123", source="cve_official", field_path="cve.path"),
        ],
    )
    evidence = normalize_seed_to_evidence([osv_result, cve_result])
    assert len(evidence) == 1
    assert evidence[0].source == "cve_official"  # higher authority


def test_normalize_skips_non_success_results() -> None:
    failed = SeedSourceResult(
        source="nvd",
        status="failed",
        status_code=503,
        reference_count=0,
        error_kind="http_error",
        error_message="503",
        references=[],
        request_url="https://example.com",
        structured_references=[
            StructuredReference(url="https://should-be-ignored.com", source="nvd"),
        ],
    )
    evidence = normalize_seed_to_evidence([failed])
    assert evidence == []


def test_normalize_medium_confidence_for_untagged_reference() -> None:
    result = _success_result(
        "nvd",
        structured_references=[
            StructuredReference(url="https://example.com/info", source="nvd"),
        ],
    )
    evidence = normalize_seed_to_evidence([result])
    assert len(evidence) == 1
    assert evidence[0].confidence == "medium"
