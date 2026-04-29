"""Tests for candidate_generator.generate_candidates."""
from app.cve.candidate_generator import PatchCandidate, generate_candidates
from app.cve.patch_evidence import PatchEvidence


def test_generates_commit_patch_from_fix_commit_with_github_repo_hint() -> None:
    evidence = [
        PatchEvidence(
            evidence_type="fix_commit",
            source="osv",
            commit_sha="deadbeef1234",
            repo_hint="https://github.com/owner/repo",
            authority_score=80,
            confidence="high",
            raw_field_path="affected[].ranges[].events[].fixed",
        ),
    ]
    candidates = generate_candidates(evidence)
    assert len(candidates) == 1
    c = candidates[0]
    assert c.candidate_type == "commit_patch"
    assert c.patch_type == "github_commit_patch"
    assert c.patch_url == "https://github.com/owner/repo/commit/deadbeef1234.patch"
    assert c.downloadable is True
    assert c.score == 80


def test_generates_candidate_from_reference_url_github_commit() -> None:
    evidence = [
        PatchEvidence(
            evidence_type="reference_url",
            source="cve_official",
            url="https://github.com/owner/repo/commit/abc123def456",
            authority_score=100,
            confidence="high",
        ),
    ]
    candidates = generate_candidates(evidence)
    assert len(candidates) == 1
    c = candidates[0]
    assert c.candidate_type == "commit_patch"
    assert c.patch_type == "github_commit_patch"
    assert c.patch_url == "https://github.com/owner/repo/commit/abc123def456.patch"
    assert c.downloadable is True
    assert c.score == 100


def test_generates_candidate_from_reference_url_direct_patch() -> None:
    evidence = [
        PatchEvidence(
            evidence_type="reference_url",
            source="nvd",
            url="https://example.com/fix.patch",
            authority_score=60,
            confidence="medium",
        ),
    ]
    candidates = generate_candidates(evidence)
    assert len(candidates) == 1
    c = candidates[0]
    assert c.candidate_type == "direct_patch"
    assert c.patch_type == "patch"
    assert c.downloadable is True


def test_deduplicates_by_canonical_key_keeping_highest_score() -> None:
    evidence = [
        PatchEvidence(
            evidence_type="reference_url",
            source="nvd",
            url="https://github.com/owner/repo/commit/abc123d",
            authority_score=60,
            confidence="medium",
        ),
        PatchEvidence(
            evidence_type="reference_url",
            source="cve_official",
            url="https://github.com/owner/repo/commit/abc123d",
            authority_score=100,
            confidence="high",
        ),
    ]
    candidates = generate_candidates(evidence)
    assert len(candidates) == 1
    assert candidates[0].score == 100


def test_skips_non_matching_reference_urls() -> None:
    evidence = [
        PatchEvidence(
            evidence_type="reference_url",
            source="nvd",
            url="https://example.com/advisory",
            authority_score=60,
            confidence="medium",
        ),
    ]
    candidates = generate_candidates(evidence)
    assert candidates == []


def test_skips_fix_commit_without_repo_hint() -> None:
    evidence = [
        PatchEvidence(
            evidence_type="fix_commit",
            source="cve_official",
            commit_sha="abc123",
            repo_hint=None,
            authority_score=100,
            confidence="high",
        ),
    ]
    candidates = generate_candidates(evidence)
    assert candidates == []


def test_mixed_evidence_types() -> None:
    evidence = [
        PatchEvidence(
            evidence_type="fix_commit",
            source="osv",
            commit_sha="deadbeef",
            repo_hint="https://github.com/org/lib",
            authority_score=80,
            confidence="high",
            raw_field_path="osv.path",
        ),
        PatchEvidence(
            evidence_type="reference_url",
            source="nvd",
            url="https://example.com/fix.diff",
            authority_score=60,
            confidence="medium",
        ),
        PatchEvidence(
            evidence_type="fixed_version",
            source="github_advisory",
            version="2.0.1",
            authority_score=70,
            confidence="medium",
        ),
    ]
    candidates = generate_candidates(evidence)
    # fix_commit -> 1 candidate, reference_url -> 1 candidate, fixed_version -> skipped
    assert len(candidates) == 2
    types = {c.candidate_type for c in candidates}
    assert "commit_patch" in types
    assert "direct_patch" in types
