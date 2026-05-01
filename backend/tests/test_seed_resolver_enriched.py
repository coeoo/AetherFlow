"""Tests for seed_resolver.resolve_seed_enriched — the enriched pipeline."""
from unittest.mock import MagicMock, patch

from app.cve.canonical import canonicalize_candidate_url
from app.cve.seed_resolver import (
    SeedReference,
    SeedResolutionResult,
    resolve_seed_enriched,
    resolve_seed_references,
)
from app.cve.seed_sources import (
    FixCommitEvidence,
    SeedSourceResult,
    StructuredReference,
)


def _osv_result_with_fix_commit() -> SeedSourceResult:
    return SeedSourceResult(
        source="osv",
        status="success",
        status_code=200,
        reference_count=1,
        error_kind=None,
        error_message=None,
        references=["https://github.com/org/repo/commit/abc12345"],
        request_url="https://api.osv.dev/v1/vulns/CVE-2024-0001",
        structured_references=[
            StructuredReference(
                url="https://github.com/org/repo/commit/abc12345",
                tags=("patch",),
                source="osv",
            ),
        ],
        fix_commits=[
            FixCommitEvidence(
                commit_sha="abc12345",
                repo_hint="https://github.com/org/repo",
                source="osv",
                field_path="affected[].ranges[].events[].fixed",
            ),
        ],
    )


def _nvd_result_with_reference_only() -> SeedSourceResult:
    return SeedSourceResult(
        source="nvd",
        status="success",
        status_code=200,
        reference_count=1,
        error_kind=None,
        error_message=None,
        references=["https://example.com/advisory"],
        request_url="https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-0001",
    )


@patch("app.cve.seed_resolver.record_source_fetch")
@patch("app.cve.seed_resolver.resolve_all_seed_sources")
def test_resolve_seed_enriched_returns_resolution_result(
    mock_resolve_all: MagicMock,
    mock_record: MagicMock,
) -> None:
    mock_resolve_all.return_value = [
        _osv_result_with_fix_commit(),
        _nvd_result_with_reference_only(),
    ]
    session = MagicMock()
    run = MagicMock()

    result = resolve_seed_enriched(session, run=run, cve_id="CVE-2024-0001")

    assert isinstance(result, SeedResolutionResult)
    assert len(result.references) >= 1
    assert all(isinstance(r, SeedReference) for r in result.references)
    # OSV fix_commit should produce at least one PatchEvidence
    assert len(result.evidence) >= 1
    fix_commit_evidence = [e for e in result.evidence if e.evidence_type == "fix_commit"]
    assert len(fix_commit_evidence) == 1
    assert fix_commit_evidence[0].commit_sha == "abc12345"
    # fix_commit with repo_hint should produce a downloadable candidate
    assert len(result.candidates) >= 1
    commit_candidates = [c for c in result.candidates if c.candidate_type == "commit_patch"]
    assert len(commit_candidates) >= 1
    assert commit_candidates[0].downloadable is True


@patch("app.cve.seed_resolver.record_source_fetch")
@patch("app.cve.seed_resolver.resolve_all_seed_sources")
def test_resolve_seed_enriched_response_meta_includes_counts(
    mock_resolve_all: MagicMock,
    mock_record: MagicMock,
) -> None:
    mock_resolve_all.return_value = [_osv_result_with_fix_commit()]
    session = MagicMock()
    run = MagicMock()

    resolve_seed_enriched(session, run=run, cve_id="CVE-2024-0001")

    # Verify record_source_fetch was called with evidence/candidate counts
    mock_record.assert_called_once()
    call_kwargs = mock_record.call_args
    response_meta = call_kwargs.kwargs.get("response_meta") or call_kwargs[1].get("response_meta")
    assert response_meta is not None
    assert "evidence_count" in response_meta
    assert "candidate_count" in response_meta
    assert response_meta["evidence_count"] > 0
    assert response_meta["candidate_count"] > 0
    assert "structured_reference_count" in response_meta
    assert "fix_commit_count" in response_meta
    assert "fixed_version_count" in response_meta
    assert response_meta["fix_commit_count"] >= 0
    assert response_meta["structured_reference_count"] >= 0


@patch("app.cve.seed_resolver.record_source_fetch")
@patch("app.cve.seed_resolver.resolve_all_seed_sources")
def test_resolve_seed_references_backward_compatible(
    mock_resolve_all: MagicMock,
    mock_record: MagicMock,
) -> None:
    """resolve_seed_references still returns list[SeedReference]."""
    mock_resolve_all.return_value = [_osv_result_with_fix_commit()]
    session = MagicMock()
    run = MagicMock()

    result = resolve_seed_references(session, run=run, cve_id="CVE-2024-0001")

    assert isinstance(result, list)
    assert all(isinstance(r, SeedReference) for r in result)


@patch("app.cve.seed_resolver.record_source_fetch")
@patch("app.cve.seed_resolver.resolve_all_seed_sources")
def test_resolve_seed_enriched_raises_when_all_sources_fail(
    mock_resolve_all: MagicMock,
    mock_record: MagicMock,
) -> None:
    mock_resolve_all.return_value = [
        SeedSourceResult(
            source="osv",
            status="failed",
            status_code=503,
            reference_count=0,
            error_kind="http_error",
            error_message="503",
            references=[],
            request_url="https://api.osv.dev/v1/vulns/CVE-2024-0001",
        ),
    ]
    session = MagicMock()
    run = MagicMock()

    try:
        resolve_seed_enriched(session, run=run, cve_id="CVE-2024-0001")
        assert False, "Expected RuntimeError"
    except RuntimeError:
        pass


@patch("app.cve.seed_resolver.record_source_fetch")
@patch("app.cve.seed_resolver.resolve_all_seed_sources")
def test_resolve_seed_enriched_mixed_success_failure(
    mock_resolve_all: MagicMock,
    mock_record: MagicMock,
) -> None:
    """混合 success/failure：部分源成功即可，不抛异常。"""
    mock_resolve_all.return_value = [
        SeedSourceResult(
            source="osv",
            status="failed",
            status_code=503,
            reference_count=0,
            error_kind="http_error",
            error_message="503",
            references=[],
            request_url="https://api.osv.dev/v1/vulns/CVE-2024-0001",
        ),
        _nvd_result_with_reference_only(),
    ]
    session = MagicMock()
    run = MagicMock()

    result = resolve_seed_enriched(session, run=run, cve_id="CVE-2024-0001")

    assert isinstance(result, SeedResolutionResult)
    assert len(result.references) >= 1
    # NVD 只有 reference_url（无 fix_commit），需 match_reference_url 匹配
    assert isinstance(result.evidence, list)
    assert isinstance(result.candidates, list)


@patch("app.cve.seed_resolver.record_source_fetch")
@patch("app.cve.seed_resolver.resolve_all_seed_sources")
def test_resolve_seed_enriched_skip_non_downloadable(
    mock_resolve_all: MagicMock,
    mock_record: MagicMock,
) -> None:
    """fix_commit 无 repo_hint 时不应生成可下载候选。"""
    mock_resolve_all.return_value = [
        SeedSourceResult(
            source="osv",
            status="success",
            status_code=200,
            reference_count=0,
            error_kind=None,
            error_message=None,
            references=[],
            request_url="https://api.osv.dev/v1/vulns/CVE-2024-0002",
            fix_commits=[
                FixCommitEvidence(
                    commit_sha="def56789",
                    repo_hint=None,
                    source="osv",
                    field_path="affected[].ranges[].events[].fixed",
                ),
            ],
        ),
    ]
    session = MagicMock()
    run = MagicMock()

    result = resolve_seed_enriched(session, run=run, cve_id="CVE-2024-0002")

    # fix_commit 存在但不能构造 patch URL → __build_commit_patch_url 返回 None
    # → evidence 有 1 条 fix_commit，但 generate_candidates 不产出下载候选
    assert len(result.evidence) == 1
    assert result.evidence[0].evidence_type == "fix_commit"
    assert result.evidence[0].commit_sha == "def56789"
    # 无法构造 patch URL → candidate 列表应为空
    assert len(result.candidates) == 0


@patch("app.cve.seed_resolver.record_source_fetch")
@patch("app.cve.seed_resolver.resolve_all_seed_sources")
def test_resolve_seed_enriched_dedup_evidence_across_sources(
    mock_resolve_all: MagicMock,
    mock_record: MagicMock,
) -> None:
    """同一 fix_commit 来自多个源时只保留最高 authority 的 PatchCandidate。"""
    mock_resolve_all.return_value = [
        SeedSourceResult(
            source="cve_official",
            status="success",
            status_code=200,
            reference_count=1,
            error_kind=None,
            error_message=None,
            references=[],
            request_url="https://cveawg.mitre.org/api/cve/CVE-2024-0003",
            fix_commits=[
                FixCommitEvidence(
                    commit_sha="abc12345",
                    repo_hint="https://github.com/org/repo",
                    source="cve_official",
                    field_path="containers.cna.affected[].versions[].lessThan",
                ),
            ],
        ),
        SeedSourceResult(
            source="nvd",
            status="success",
            status_code=200,
            reference_count=0,
            error_kind=None,
            error_message=None,
            references=[],
            request_url="https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-0003",
            fix_commits=[
                FixCommitEvidence(
                    commit_sha="abc12345",
                    repo_hint="https://github.com/org/repo",
                    source="nvd",
                    field_path="some.other.path",
                ),
            ],
        ),
    ]
    session = MagicMock()
    run = MagicMock()

    result = resolve_seed_enriched(session, run=run, cve_id="CVE-2024-0003")

    # cve_official (authority=100) 覆盖 nvd (authority=60)
    fix_evidence = [e for e in result.evidence if e.evidence_type == "fix_commit"]
    assert len(fix_evidence) == 1
    assert fix_evidence[0].source == "cve_official"
    assert fix_evidence[0].authority_score == 100
    # 同一 commit SHA → 同一 canonical_key → candidates 中去重
    assert len(result.candidates) == 1
    assert result.candidates[0].canonical_key == canonicalize_candidate_url(
        "https://github.com/org/repo/commit/abc12345"
    )
    assert result.candidates[0].downloadable is True


@patch("app.cve.seed_resolver.record_source_fetch")
@patch("app.cve.seed_resolver.resolve_all_seed_sources")
def test_resolve_seed_enriched_empty_evidence(
    mock_resolve_all: MagicMock,
    mock_record: MagicMock,
) -> None:
    """无 structured_data 时 evidence 和 candidates 均为空列表。"""
    mock_resolve_all.return_value = [
        SeedSourceResult(
            source="nvd",
            status="success",
            status_code=200,
            reference_count=1,
            error_kind=None,
            error_message=None,
            references=["https://example.com/advisory"],
            request_url="https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2024-0004",
        ),
    ]
    session = MagicMock()
    run = MagicMock()

    result = resolve_seed_enriched(session, run=run, cve_id="CVE-2024-0004")

    # NVD 返回无 tags/structured_references → 不产出 reference_url evidence
    assert len(result.evidence) == 0
    assert len(result.candidates) == 0
    assert len(result.references) == 1
