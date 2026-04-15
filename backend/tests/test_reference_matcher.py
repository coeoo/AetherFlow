from app.cve.reference_matcher import match_reference_url, match_reference_urls


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
