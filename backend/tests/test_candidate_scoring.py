"""Tests for candidate_scoring — multi-dimensional candidate scoring."""

from app.cve.candidate_scoring import (
    CandidateScore,
    ScorerWeights,
    _PATCH_TYPE_BASE_SCORE,
    get_candidate_priority,
    get_type_priority,
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


class TestGetTypePriority:
    """get_type_priority 是 fallback.py >=90 高质量阈值的输入语义。"""

    def test_returns_default_for_unknown_type(self) -> None:
        assert get_type_priority("some_unknown_type") == 50

    def test_aosp_commit_patch_is_high_quality(self) -> None:
        # 防止 AOSP 在 reference_matcher 委托后静默退化为默认 50
        assert get_type_priority("aosp_commit_patch") == 90

    def test_known_upstream_commit_types_meet_high_quality_threshold(self) -> None:
        # fallback.py:287 的 high_quality 阈值是 >=90
        for patch_type in (
            "github_commit_patch",
            "gitlab_commit_patch",
            "kernel_commit_patch",
            "bitbucket_commit_patch",
            "gitee_commit_patch",
            "aosp_commit_patch",
            "github_pull_patch",
            "gitlab_merge_request_patch",
        ):
            assert get_type_priority(patch_type) >= 90, patch_type

    def test_distro_only_types_below_high_quality_threshold(self) -> None:
        # 通用 patch / diff / debdiff 不算高质量（distro 进一步降权由 reference_matcher 外壳处理）
        for patch_type in ("patch", "diff", "debdiff", "bugzilla_attachment_patch"):
            assert get_type_priority(patch_type) < 90, patch_type

    def test_matches_internal_score_patch_type_for_all_known_types(self) -> None:
        # _score_patch_type 应该与 get_type_priority 行为一致（单一真相）
        from app.cve.candidate_scoring import _score_patch_type

        for patch_type in _PATCH_TYPE_BASE_SCORE:
            assert get_type_priority(patch_type) == _score_patch_type(patch_type)


class TestKnownPatchTypesAlignment:
    """candidate_scoring 与 reference_matcher 的 patch_type 命名空间必须对齐。"""

    def test_known_patch_types_match_reference_matcher_priority_keys(self) -> None:
        from app.cve.reference_matcher import CANDIDATE_PRIORITY, KNOWN_PATCH_TYPES

        assert KNOWN_PATCH_TYPES == frozenset(CANDIDATE_PRIORITY.keys())

    def test_candidate_scoring_covers_all_reference_matcher_known_types(self) -> None:
        # 防止新增 patch_type 时 candidate_scoring 漏覆盖（导致 fallback 阈值漂移）
        from app.cve.reference_matcher import KNOWN_PATCH_TYPES

        scoring_keys = frozenset(_PATCH_TYPE_BASE_SCORE.keys())
        missing = KNOWN_PATCH_TYPES - scoring_keys
        assert not missing, f"candidate_scoring._PATCH_TYPE_BASE_SCORE 缺失类型: {missing}"
