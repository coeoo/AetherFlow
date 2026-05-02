"""Tests for candidate_generator.generate_candidates."""
from app.cve.candidate_generator import PatchCandidate, generate_candidates
from app.cve.patch_evidence import PatchEvidence
from app.cve.reference_matcher import KNOWN_PATCH_TYPES


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


def test_normalizes_reference_url_fragment_before_match() -> None:
    # GitHub commit URL 带 fragment（如 #diff-1）经 normalize_frontier_url
    # 剥除后再 match，candidate_url 不应含 fragment（与 baseline seed-derived 等价）
    evidence = [
        PatchEvidence(
            evidence_type="reference_url",
            source="cve_official",
            url="https://github.com/owner/repo/commit/abc123def456#diff-1",
            authority_score=100,
            confidence="high",
        ),
    ]
    candidates = generate_candidates(evidence)
    assert len(candidates) == 1
    c = candidates[0]
    assert c.patch_type == "github_commit_patch"
    assert c.patch_url == "https://github.com/owner/repo/commit/abc123def456.patch"
    assert "#" not in c.candidate_url


def test_normalizes_reference_url_whitespace_before_match() -> None:
    # reference_url 前后多余空白（来自 source 数据清洗不彻底），
    # normalize_frontier_url 应 strip 后再 match
    evidence = [
        PatchEvidence(
            evidence_type="reference_url",
            source="nvd",
            url="  https://github.com/owner/repo/commit/abc123def456  ",
            authority_score=80,
            confidence="medium",
        ),
    ]
    candidates = generate_candidates(evidence)
    assert len(candidates) == 1
    c = candidates[0]
    assert c.patch_type == "github_commit_patch"
    assert c.patch_url == "https://github.com/owner/repo/commit/abc123def456.patch"
    assert " " not in c.candidate_url


def test_normalizes_reference_url_openwall_http_to_https() -> None:
    # openwall mailing list URL 是 http 形态（来自 NVD reference 历史数据），
    # normalize_frontier_url 应升级为 https；openwall 本身不是 commit/patch 域，
    # match_reference_url 仍返回 None；但 normalize 不应丢弃 evidence
    evidence = [
        PatchEvidence(
            evidence_type="reference_url",
            source="nvd",
            url="http://www.openwall.com/lists/oss-security/2022/07/01/2",
            authority_score=60,
            confidence="medium",
        ),
    ]
    candidates = generate_candidates(evidence)
    # openwall 不是 commit/patch URL，match 返回 None，无 candidate；
    # 关键是函数不抛异常、不影响其他 evidence
    assert candidates == []


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


# ─────────── 多 host fix_commit 扩展（Phase B+ Step 2）────────────


def test_generates_commit_patch_from_fix_commit_with_gitlab_repo_hint() -> None:
    sha = "0123456789abcdef0123456789abcdef01234567"
    candidates = generate_candidates([
        PatchEvidence(
            evidence_type="fix_commit",
            source="osv",
            commit_sha=sha,
            repo_hint="https://gitlab.gnome.org/GNOME/glib",
            authority_score=80,
            confidence="high",
            raw_field_path="osv.path",
        ),
    ])
    assert len(candidates) == 1
    c = candidates[0]
    assert c.candidate_type == "commit_patch"
    assert c.patch_type == "gitlab_commit_patch"
    assert c.candidate_url == f"https://gitlab.gnome.org/GNOME/glib/-/commit/{sha}.patch"
    assert c.patch_url == f"https://gitlab.gnome.org/GNOME/glib/-/commit/{sha}.patch"
    assert c.downloadable is True


def test_generates_commit_patch_from_fix_commit_with_kernel_repo_hint() -> None:
    sha = "34dfac0c904829967d500c51f216916ce1452957"
    candidates = generate_candidates([
        PatchEvidence(
            evidence_type="fix_commit",
            source="cve_official",
            commit_sha=sha,
            repo_hint="https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
            authority_score=100,
            confidence="high",
            raw_field_path="containers.cna.affected[0].versions[0]",
        ),
    ])
    assert len(candidates) == 1
    c = candidates[0]
    assert c.candidate_type == "commit_patch"
    assert c.patch_type == "kernel_commit_patch"
    # matcher 重写 stable 短链为可下载的 stable patch URL，candidate_url 与 patch_url 都是该形态
    assert c.candidate_url is not None
    assert c.candidate_url.startswith("https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/patch/")
    assert sha in c.candidate_url
    assert c.patch_url == c.candidate_url


def test_generates_commit_patch_from_fix_commit_with_bitbucket_repo_hint() -> None:
    sha = "0123456789abcdef0123456789abcdef01234567"
    candidates = generate_candidates([
        PatchEvidence(
            evidence_type="fix_commit",
            source="osv",
            commit_sha=sha,
            repo_hint="https://bitbucket.org/acme/project",
            authority_score=70,
            confidence="medium",
            raw_field_path="osv.path",
        ),
    ])
    assert len(candidates) == 1
    c = candidates[0]
    assert c.patch_type == "bitbucket_commit_patch"
    assert c.candidate_url == f"https://bitbucket.org/acme/project/commits/{sha}/raw"
    assert c.patch_url == f"https://bitbucket.org/acme/project/commits/{sha}/raw"


def test_generates_commit_patch_from_fix_commit_with_gitee_repo_hint() -> None:
    sha = "0123456789abcdef0123456789abcdef01234567"
    candidates = generate_candidates([
        PatchEvidence(
            evidence_type="fix_commit",
            source="osv",
            commit_sha=sha,
            repo_hint="https://gitee.com/acme/project",
            authority_score=70,
            confidence="medium",
            raw_field_path="osv.path",
        ),
    ])
    assert len(candidates) == 1
    c = candidates[0]
    assert c.patch_type == "gitee_commit_patch"
    assert c.candidate_url == f"https://gitee.com/acme/project/commit/{sha}.patch"
    assert c.patch_url == f"https://gitee.com/acme/project/commit/{sha}.patch"


def test_generates_commit_patch_from_fix_commit_with_aosp_repo_hint() -> None:
    sha = "0123456789abcdef0123456789abcdef01234567"
    candidates = generate_candidates([
        PatchEvidence(
            evidence_type="fix_commit",
            source="cve_official",
            commit_sha=sha,
            repo_hint="https://android.googlesource.com/platform/system/core",
            authority_score=100,
            confidence="high",
            raw_field_path="containers.cna.affected[0].versions[0]",
        ),
    ])
    assert len(candidates) == 1
    c = candidates[0]
    assert c.patch_type == "aosp_commit_patch"
    assert c.candidate_url == f"https://android.googlesource.com/platform/system/core/+/{sha}.patch"
    assert c.patch_url == f"https://android.googlesource.com/platform/system/core/+/{sha}.patch"


def test_generates_commit_patch_strips_trailing_slash_and_dot_git() -> None:
    # repo_hint 带 .git 后缀或 trailing slash 仍应正确合成
    sha = "deadbeef0123456789abcdef"
    candidates = generate_candidates([
        PatchEvidence(
            evidence_type="fix_commit",
            source="osv",
            commit_sha=sha,
            repo_hint="https://github.com/owner/repo.git/",
            authority_score=80,
            confidence="high",
            raw_field_path="osv.path",
        ),
    ])
    assert len(candidates) == 1
    assert candidates[0].patch_type == "github_commit_patch"
    assert candidates[0].candidate_url == f"https://github.com/owner/repo/commit/{sha}.patch"


def test_skips_fix_commit_with_bare_owner_repo_hint() -> None:
    # 裸 owner/repo（非 URL）默认不猜 host
    candidates = generate_candidates([
        PatchEvidence(
            evidence_type="fix_commit",
            source="osv",
            commit_sha="deadbeef0123456",
            repo_hint="acme/project",  # 没有 http:// 前缀
            authority_score=80,
            confidence="high",
            raw_field_path="osv.path",
        ),
    ])
    assert candidates == []


def test_skips_fix_commit_with_invalid_commit_sha() -> None:
    # commit_sha 必须是 7-40 位 hex；tag/branch/版本号不应被合成 commit URL
    for invalid_sha in ("abc12", "v1.2.3", "main", "ABCDEFG_NOT_HEX", "1234567890" * 5):
        candidates = generate_candidates([
            PatchEvidence(
                evidence_type="fix_commit",
                source="osv",
                commit_sha=invalid_sha,
                repo_hint="https://github.com/owner/repo",
                authority_score=80,
                confidence="high",
                raw_field_path="osv.path",
            ),
        ])
        assert candidates == [], f"expected skip for invalid sha={invalid_sha!r}"


def test_skips_fix_commit_with_unknown_host() -> None:
    # 未知 host 不合成（避免 silent 误判）
    candidates = generate_candidates([
        PatchEvidence(
            evidence_type="fix_commit",
            source="osv",
            commit_sha="0123456789abcdef0123456789abcdef01234567",
            repo_hint="https://example.googlesource.com/repo",
            authority_score=80,
            confidence="high",
            raw_field_path="osv.path",
        ),
    ])
    assert candidates == []


def test_dedup_across_reference_url_and_fix_commit_paths_for_github_commit() -> None:
    # 同一 GitHub commit 通过 reference_url 与 fix_commit 双路径，
    # canonical_key 应一致（canonicalize 剥 .patch 对齐），保留高 score 的一条。
    sha = "abc123def456abc123def456abc123def456abc1"
    candidates = generate_candidates([
        PatchEvidence(
            evidence_type="reference_url",
            source="nvd",
            url=f"https://github.com/owner/repo/commit/{sha}",
            authority_score=60,
            confidence="medium",
        ),
        PatchEvidence(
            evidence_type="fix_commit",
            source="cve_official",
            commit_sha=sha,
            repo_hint="https://github.com/owner/repo",
            authority_score=100,
            confidence="high",
            raw_field_path="containers.cna.affected[0].versions[0]",
        ),
    ])
    assert len(candidates) == 1
    assert candidates[0].patch_type == "github_commit_patch"
    assert candidates[0].score == 100  # 保留高 score


def test_all_generated_patch_types_are_in_known_patch_types_namespace() -> None:
    # 防止 candidate_generator 引入第三份 patch_type 命名空间
    sha = "0123456789abcdef0123456789abcdef01234567"
    evidence = [
        PatchEvidence(
            evidence_type="fix_commit",
            source="osv",
            commit_sha=sha,
            repo_hint="https://github.com/o/r",
            authority_score=80,
            confidence="high",
            raw_field_path="p1",
        ),
        PatchEvidence(
            evidence_type="fix_commit",
            source="osv",
            commit_sha=sha,
            repo_hint="https://gitlab.com/o/r",
            authority_score=80,
            confidence="high",
            raw_field_path="p2",
        ),
        PatchEvidence(
            evidence_type="fix_commit",
            source="cve_official",
            commit_sha=sha,
            repo_hint="https://git.kernel.org",
            authority_score=100,
            confidence="high",
            raw_field_path="p3",
        ),
        PatchEvidence(
            evidence_type="fix_commit",
            source="osv",
            commit_sha=sha,
            repo_hint="https://bitbucket.org/o/r",
            authority_score=70,
            confidence="medium",
            raw_field_path="p4",
        ),
        PatchEvidence(
            evidence_type="fix_commit",
            source="osv",
            commit_sha=sha,
            repo_hint="https://gitee.com/o/r",
            authority_score=70,
            confidence="medium",
            raw_field_path="p5",
        ),
        PatchEvidence(
            evidence_type="fix_commit",
            source="cve_official",
            commit_sha=sha,
            repo_hint="https://android.googlesource.com/platform/x",
            authority_score=100,
            confidence="high",
            raw_field_path="p6",
        ),
        PatchEvidence(
            evidence_type="reference_url",
            source="nvd",
            url="https://example.com/fix.patch",
            authority_score=60,
            confidence="medium",
        ),
    ]
    candidates = generate_candidates(evidence)
    assert candidates, "expected at least 1 candidate"
    for c in candidates:
        assert c.patch_type in KNOWN_PATCH_TYPES, f"unknown patch_type: {c.patch_type}"
