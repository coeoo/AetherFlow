"""Tests for candidate_scoring — multi-dimensional candidate scoring."""

from app.cve.candidate_scoring import (
    CandidateScore,
    ScorerWeights,
    get_candidate_priority,
    score_candidate,
)


class TestScoreCandidate:
    def test_github_commit_scores_highest(self) -> None:
        result = score_candidate("github_commit_patch", "https://github.com/org/repo/commit/abc123.patch")
        assert result.total > 50
        assert result.type_score == 100
        assert result.source_score > 20

    def test_gitlab_commit_scores_high(self) -> None:
        result = score_candidate("gitlab_commit_patch", "https://gitlab.com/org/repo/-/commit/abc123.patch")
        assert result.total > 50
        assert result.type_score == 100

    def test_kernel_commit_scores_high(self) -> None:
        result = score_candidate("kernel_commit_patch")
        assert result.type_score == 100

    def test_bitbucket_commit_scores_high(self) -> None:
        result = score_candidate("bitbucket_commit_patch", "https://bitbucket.org/org/repo/commits/abc.patch")
        assert result.type_score == 95

    def test_distribution_patch_downgraded(self) -> None:
        result = score_candidate("debdiff", "https://patches.ubuntu.com/example.debdiff")
        assert result.type_score == 20
        assert result.source_score < 20

    def test_unknown_type_returns_default(self) -> None:
        result = score_candidate("some_unknown_type")
        assert result.type_score == 50

    def test_discovery_count_boosts_score(self) -> None:
        single = score_candidate("github_commit_patch", discovery_count=1)
        multi = score_candidate("github_commit_patch", discovery_count=5)
        assert multi.discovery_score > single.discovery_score
        assert multi.total > single.total

    def test_authority_score_affects_total(self) -> None:
        low_auth = score_candidate("github_commit_patch", authority_score=0)
        high_auth = score_candidate("github_commit_patch", authority_score=100)
        assert high_auth.total > low_auth.total

    def test_result_is_dataclass_instance(self) -> None:
        result = score_candidate("patch")
        assert isinstance(result, CandidateScore)
        assert hasattr(result, "total")
        assert hasattr(result, "type_score")

    def test_to_dict_returns_expected_keys(self) -> None:
        result = score_candidate("diff").to_dict()
        assert set(result.keys()) == {"total", "type_score", "source_score", "discovery_score", "authority_score"}

    def test_custom_weights_are_applied(self) -> None:
        custom = ScorerWeights(type_weight=1.0, source_weight=0.0, discovery_weight=0.0, authority_weight=0.0)
        result = score_candidate("github_commit_patch", weights=custom)
        # type_score=100, all other weights are 0
        assert result.total == 100


class TestGetCandidatePriority:
    def test_returns_int(self) -> None:
        assert isinstance(get_candidate_priority("patch"), int)

    def test_github_commit_is_highest(self) -> None:
        gh = get_candidate_priority("github_commit_patch", "https://github.com/org/repo/commit/abc.patch")
        diff = get_candidate_priority("diff", "https://example.com/fix.diff")
        assert gh > diff

    def test_debian_patch_is_low(self) -> None:
        result = get_candidate_priority("patch", "https://bugs.debian.org/bugreport.cgi?bug=123")
        assert result < 40


class TestCandidateScore:
    def test_low_quality_threshold(self) -> None:
        threshold = CandidateScore.low_quality_threshold()
        assert isinstance(threshold, int)
        assert 0 <= threshold <= 100
