from app.cve.reference_matcher import get_candidate_priority, match_reference_url, match_reference_urls


def test_matcher_keeps_direct_patch_url() -> None:
    candidate = match_reference_url("https://example.com/fixes/CVE-2024-0001.patch")

    assert candidate == {
        "candidate_url": "https://example.com/fixes/CVE-2024-0001.patch",
        "patch_type": "patch",
    }


def test_matcher_keeps_direct_diff_url() -> None:
    candidate = match_reference_url("https://example.com/fixes/CVE-2024-0001.diff")

    assert candidate == {
        "candidate_url": "https://example.com/fixes/CVE-2024-0001.diff",
        "patch_type": "diff",
    }


def test_matcher_keeps_direct_debdiff_url() -> None:
    candidate = match_reference_url("https://example.com/fixes/CVE-2024-0001.debdiff")

    assert candidate == {
        "candidate_url": "https://example.com/fixes/CVE-2024-0001.debdiff",
        "patch_type": "debdiff",
    }


def test_matcher_recognizes_patch_filename_in_query_params() -> None:
    candidate = match_reference_url(
        "https://bugs.debian.org/cgi-bin/bugreport.cgi?att=1;bug=1068024;filename=dpkg.patch;msg=62"
    )

    assert candidate == {
        "candidate_url": "https://bugs.debian.org/cgi-bin/bugreport.cgi?att=1;bug=1068024;filename=dpkg.patch;msg=62",
        "patch_type": "patch",
    }


def test_matcher_keeps_legacy_patch_query_url() -> None:
    candidate = match_reference_url("https://example.com/view?patch=1")

    assert candidate == {
        "candidate_url": "https://example.com/view?patch=1",
        "patch_type": "patch",
    }


def test_matcher_recognizes_diff_filename_in_query_params() -> None:
    candidate = match_reference_url("https://vendor.example/download?file=fix.diff&id=42")

    assert candidate == {
        "candidate_url": "https://vendor.example/download?file=fix.diff&id=42",
        "patch_type": "diff",
    }


def test_matcher_recognizes_debdiff_filename_in_query_params() -> None:
    candidate = match_reference_url(
        "https://bugs.debian.org/cgi-bin/bugreport.cgi?att=1;bug=848132;filename=most.debdiff;msg=5"
    )

    assert candidate == {
        "candidate_url": "https://bugs.debian.org/cgi-bin/bugreport.cgi?att=1;bug=848132;filename=most.debdiff;msg=5",
        "patch_type": "debdiff",
    }


def test_matcher_converts_github_commit_to_patch_url() -> None:
    candidate = match_reference_url(
        "https://github.com/acme/project/commit/0123456789abcdef0123456789abcdef01234567"
    )

    assert candidate == {
        "candidate_url": "https://github.com/acme/project/commit/0123456789abcdef0123456789abcdef01234567.patch",
        "patch_type": "github_commit_patch",
    }


def test_matcher_converts_github_pull_request_to_patch_url() -> None:
    candidate = match_reference_url("https://github.com/acme/project/pull/42")

    assert candidate == {
        "candidate_url": "https://github.com/acme/project/pull/42.patch",
        "patch_type": "github_pull_patch",
    }


def test_matcher_converts_gitlab_commit_to_patch_url() -> None:
    candidate = match_reference_url(
        "https://gitlab.gnome.org/GNOME/glib/-/commit/0123456789abcdef0123456789abcdef01234567"
    )

    assert candidate == {
        "candidate_url": "https://gitlab.gnome.org/GNOME/glib/-/commit/0123456789abcdef0123456789abcdef01234567.patch",
        "patch_type": "gitlab_commit_patch",
    }


def test_matcher_converts_gitlab_merge_request_to_patch_url() -> None:
    candidate = match_reference_url("https://gitlab.freedesktop.org/mesa/mesa/-/merge_requests/12345")

    assert candidate == {
        "candidate_url": "https://gitlab.freedesktop.org/mesa/mesa/-/merge_requests/12345.patch",
        "patch_type": "gitlab_merge_request_patch",
    }


def test_matcher_converts_kernel_stable_shortlink_to_patch_url() -> None:
    candidate = match_reference_url(
        "https://git.kernel.org/stable/c/34dfac0c904829967d500c51f216916ce1452957"
    )

    assert candidate == {
        "candidate_url": "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/patch/?id=34dfac0c904829967d500c51f216916ce1452957",
        "patch_type": "kernel_commit_patch",
    }


def test_matcher_converts_bitbucket_commit_to_patch_url() -> None:
    candidate = match_reference_url(
        "https://bitbucket.org/acme/project/commit/0123456789abcdef0123456789abcdef01234567"
    )

    assert candidate == {
        "candidate_url": "https://bitbucket.org/acme/project/commit/0123456789abcdef0123456789abcdef01234567/raw",
        "patch_type": "bitbucket_commit_patch",
    }


def test_matcher_converts_bitbucket_commits_plural_path_to_patch_url() -> None:
    candidate = match_reference_url(
        "https://bitbucket.org/acme/project/commits/0123456789abcdef0123456789abcdef01234567"
    )

    assert candidate == {
        "candidate_url": "https://bitbucket.org/acme/project/commits/0123456789abcdef0123456789abcdef01234567/raw",
        "patch_type": "bitbucket_commit_patch",
    }


def test_matcher_converts_bitbucket_pull_request_to_patch_url() -> None:
    candidate = match_reference_url("https://bitbucket.org/acme/project/pull-requests/42")

    assert candidate == {
        "candidate_url": "https://bitbucket.org/acme/project/pull-requests/42.patch",
        "patch_type": "bitbucket_pull_patch",
    }


def test_matcher_skips_bitbucket_non_commit_path() -> None:
    assert match_reference_url("https://bitbucket.org/acme/project/issues/42") is None
    assert match_reference_url("https://bitbucket.org/acme/project/wiki/Home") is None


def test_matcher_converts_gitee_commit_to_patch_url() -> None:
    candidate = match_reference_url(
        "https://gitee.com/acme/project/commit/0123456789abcdef0123456789abcdef01234567"
    )

    assert candidate == {
        "candidate_url": "https://gitee.com/acme/project/commit/0123456789abcdef0123456789abcdef01234567.patch",
        "patch_type": "gitee_commit_patch",
    }


def test_matcher_skips_gitee_non_commit_path() -> None:
    assert match_reference_url("https://gitee.com/acme/project/issues/I12345") is None


def test_matcher_converts_aosp_gitiles_commit_to_patch_url() -> None:
    commit_id = "abc1234567890abcdef1234567890abcdef12345"
    candidate = match_reference_url(
        f"https://android.googlesource.com/platform/system/core/+/{commit_id}"
    )

    # TODO: 使用真实 AOSP 样本确认 Gitiles commit patch URL 的 .patch 后缀形态是否可下载。
    assert candidate == {
        "candidate_url": f"https://android.googlesource.com/platform/system/core/+/{commit_id}.patch",
        "patch_type": "aosp_commit_patch",
    }


def test_matcher_skips_aosp_log_page() -> None:
    assert (
        match_reference_url(
            "https://android.googlesource.com/platform/system/core/+/log/abc1234567890abcdef1234567890abcdef12345"
        )
        is None
    )


def test_matcher_skips_aosp_refs_branch_page() -> None:
    assert (
        match_reference_url(
            "https://android.googlesource.com/platform/system/core/+/refs/heads/main"
        )
        is None
    )


def test_matcher_skips_non_aosp_gitiles_host() -> None:
    assert (
        match_reference_url(
            "https://example.googlesource.com/repo/+/abc1234567890abcdef1234567890abcdef12345"
        )
        is None
    )


def test_matcher_skips_aosp_path_with_double_plus_segments() -> None:
    # 病态路径：/x/+/y/+/<sha> 不是合法 AOSP commit URL；贪婪正则若无守卫会误匹配。
    assert (
        match_reference_url(
            "https://android.googlesource.com/x/+/y/+/abc1234567890abcdef1234567890abcdef12345"
        )
        is None
    )


def test_matcher_converts_redhat_bugzilla_attachment_to_patch_url() -> None:
    candidate = match_reference_url("https://bugzilla.redhat.com/attachment.cgi?id=123456")

    assert candidate == {
        "candidate_url": "https://bugzilla.redhat.com/attachment.cgi?id=123456",
        "patch_type": "bugzilla_attachment_patch",
    }


def test_matcher_converts_suse_bugzilla_attachment_to_patch_url() -> None:
    candidate = match_reference_url("https://bugzilla.suse.com/attachment.cgi?id=123456")

    assert candidate == {
        "candidate_url": "https://bugzilla.suse.com/attachment.cgi?id=123456",
        "patch_type": "bugzilla_attachment_patch",
    }


def test_matcher_skips_arbitrary_host_attachment_cgi() -> None:
    assert match_reference_url("https://evil.example.com/attachment.cgi?id=123") is None


def test_matcher_skips_bugzilla_attachment_without_id_param() -> None:
    assert (
        match_reference_url("https://bugzilla.redhat.com/attachment.cgi?action=download")
        is None
    )


def test_matcher_does_not_misclassify_issue_or_generic_pages() -> None:
    assert match_reference_url("https://gitlab.com/gitlab-org/gitlab/-/issues/42") is None
    assert match_reference_url("https://example.com/advisories/CVE-2024-0001") is None


def test_match_reference_urls_preserves_input_order_and_skips_non_matches() -> None:
    candidates = match_reference_urls(
        [
            "https://example.com/advisories/CVE-2024-0001",
            "https://github.com/acme/project/pull/42",
            "https://example.com/fixes/CVE-2024-0001.debdiff",
        ]
    )

    assert candidates == [
        {
            "candidate_url": "https://github.com/acme/project/pull/42.patch",
            "patch_type": "github_pull_patch",
        },
        {
            "candidate_url": "https://example.com/fixes/CVE-2024-0001.debdiff",
            "patch_type": "debdiff",
        },
    ]


def test_get_candidate_priority_upstream_commit_is_highest() -> None:
    assert get_candidate_priority("github_commit_patch") == 100
    assert get_candidate_priority("gitlab_commit_patch") == 100
    assert get_candidate_priority("kernel_commit_patch") == 100


def test_get_candidate_priority_distro_patch_is_lowest() -> None:
    assert get_candidate_priority("debdiff") == 20


def test_get_candidate_priority_downgrades_ubuntu_distro_patch_url() -> None:
    assert (
        get_candidate_priority(
            "patch",
            "https://patches.ubuntu.com/g/gnutls28/gnutls28_3.8.12-2ubuntu1.patch",
        )
        == 20
    )


def test_get_candidate_priority_bitbucket_commit_higher_than_pull() -> None:
    assert get_candidate_priority("bitbucket_commit_patch") > get_candidate_priority(
        "bitbucket_pull_patch"
    )


def test_get_candidate_priority_aosp_commit_lower_than_kernel() -> None:
    assert get_candidate_priority("aosp_commit_patch") < get_candidate_priority("kernel_commit_patch")


def test_get_candidate_priority_unknown_type_returns_default() -> None:
    assert get_candidate_priority("some_unknown_type") == 50
