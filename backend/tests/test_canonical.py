from app.cve.canonical import canonicalize_candidate_url


def test_canonicalize_candidate_url_normalizes_github_commit_patch() -> None:
    assert (
        canonicalize_candidate_url(
            "https://github.com/Acme/Repo/commit/ABCDEF1.patch#diff"
        )
        == "https://github.com/acme/repo/commit/ABCDEF1"
    )


def test_canonicalize_candidate_url_normalizes_gitlab_merge_request_patch() -> None:
    assert (
        canonicalize_candidate_url(
            "https://gitlab.com/acme/repo/-/merge_requests/123.patch?b=2&a=1"
        )
        == "https://gitlab.com/acme/repo/-/merge_requests/123?a=1&b=2"
    )


def test_canonicalize_candidate_url_sorts_query_params() -> None:
    left = canonicalize_candidate_url("https://example.com/download?patch=1&file=fix.patch")
    right = canonicalize_candidate_url("https://example.com/download?file=fix.patch&patch=1")

    assert left == right == "https://example.com/download?file=fix.patch&patch=1"


def test_canonicalize_candidate_url_strips_fragment() -> None:
    assert (
        canonicalize_candidate_url("https://example.com/fix.patch#L10")
        == "https://example.com/fix.patch"
    )


def test_canonicalize_candidate_url_normalizes_host_case() -> None:
    assert (
        canonicalize_candidate_url("HTTPS://EXAMPLE.COM/Fix.patch")
        == "https://example.com/Fix.patch"
    )


def test_canonicalize_candidate_url_normalizes_trailing_slash() -> None:
    assert (
        canonicalize_candidate_url("https://example.com/advisory/")
        == "https://example.com/advisory"
    )
