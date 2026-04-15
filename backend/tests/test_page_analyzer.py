from app.cve.page_analyzer import analyze_page


def test_analyze_page_only_returns_explicit_patch_urls_and_supported_commit_urls() -> None:
    snapshot = {
        "url": "https://example.com/advisory",
        "content": """
        https://example.com/files/fix.diff
        https://github.com/example/repo/commit/abc1234
        https://example.com/repo/commit/abc1234
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
            "candidate_url": "https://github.com/example/repo/commit/abc1234.patch",
            "patch_type": "github_commit_patch",
        },
        {
            "candidate_url": "https://example.com/view?patch=1",
            "patch_type": "patch",
        },
    ]


def test_analyze_page_uses_reference_matcher_for_github_pull_gitlab_and_kernel_urls() -> None:
    snapshot = {
        "url": "https://www.openwall.com/lists/oss-security/2024/03/29/4",
        "content": """
        <html>
          <body>
            <a href="https://github.com/acme/project/pull/42">PR</a>
            <a href="https://gitlab.freedesktop.org/mesa/mesa/-/merge_requests/12345">MR</a>
            <a href="https://git.kernel.org/stable/c/34dfac0c904829967d500c51f216916ce1452957">Kernel</a>
          </body>
        </html>
        """,
    }

    candidates = analyze_page(snapshot)

    assert candidates == [
        {
            "candidate_url": "https://github.com/acme/project/pull/42.patch",
            "patch_type": "github_pull_patch",
        },
        {
            "candidate_url": "https://gitlab.freedesktop.org/mesa/mesa/-/merge_requests/12345.patch",
            "patch_type": "gitlab_merge_request_patch",
        },
        {
            "candidate_url": "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/patch/?id=34dfac0c904829967d500c51f216916ce1452957",
            "patch_type": "kernel_commit_patch",
        },
    ]


def test_analyze_page_extracts_bugzilla_raw_attachment_from_bz_patch_rows() -> None:
    snapshot = {
        "url": "https://bugzilla.redhat.com/show_bug.cgi?id=832532",
        "content": """
        <html>
          <body>
            <table id="attachment_table">
              <tr id="a1" class="bz_contenttype_text_plain bz_patch bz_tr_obsolete bz_default_hidden">
                <td>
                  <a href="attachment.cgi?id=593003" title="View the content of the attachment">Patch</a>
                </td>
                <td>
                  <a href="attachment.cgi?id=593003&amp;action=edit">Details</a>
                  |
                  <a href="attachment.cgi?id=593003&amp;action=diff">Diff</a>
                </td>
              </tr>
            </table>
          </body>
        </html>
        """,
    }

    candidates = analyze_page(snapshot)

    assert candidates == [
        {
            "candidate_url": "https://bugzilla.redhat.com/attachment.cgi?id=593003",
            "patch_type": "bugzilla_attachment_patch",
        }
    ]


def test_analyze_page_skips_bugzilla_action_diff_links() -> None:
    snapshot = {
        "url": "https://bugzilla.redhat.com/show_bug.cgi?id=832532",
        "content": """
        <html>
          <body>
            <table id="attachment_table">
              <tr id="a1" class="bz_contenttype_text_plain bz_patch">
                <td>
                  <a href="attachment.cgi?id=593003&amp;action=diff">Diff</a>
                </td>
              </tr>
            </table>
          </body>
        </html>
        """,
    }

    assert analyze_page(snapshot) == []
