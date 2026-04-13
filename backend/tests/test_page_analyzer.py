from app.cve.page_analyzer import analyze_page


def test_analyze_page_only_returns_explicit_patch_urls_and_supported_commit_urls() -> None:
    snapshot = {
        "url": "https://example.com/advisory",
        "content": """
        https://example.com/files/fix.diff
        https://github.com/example/repo/commit/abc123
        https://example.com/repo/commit/abc123
        https://example.com/download/attachment/42
        https://example.com/view?patch=1
        """,
    }

    candidates = analyze_page(snapshot)

    assert candidates == [
        {
            "candidate_url": "https://example.com/files/fix.diff",
            "patch_type": "diff",
        },
        {
            "candidate_url": "https://example.com/view?patch=1",
            "patch_type": "patch",
        },
        {
            "candidate_url": "https://github.com/example/repo/commit/abc123",
            "patch_type": "patch",
        },
    ]
