from app.cve.agent_frontier_skill import build_frontier_candidate_records
from app.cve.agent_frontier_skill import classify_tracker_page_relevance
from app.cve.agent_frontier_skill import filter_candidate_matches_for_page
from app.cve.agent_frontier_skill import is_blocked_or_empty_page
from app.cve.agent_state import build_initial_agent_state
from app.cve.browser.base import BrowserPageSnapshot
from app.cve.browser.base import PageLink


def _snapshot(
    url: str,
    *,
    final_url: str | None = None,
    title: str = "fake",
    markdown_content: str = "fake",
    raw_html: str = "<html><body>fake</body></html>",
    accessibility_tree: str = "heading fake",
    page_role_hint: str = "frontier_page",
    links: list[PageLink] | None = None,
) -> BrowserPageSnapshot:
    return BrowserPageSnapshot(
        url=url,
        final_url=final_url or url,
        status_code=200,
        title=title,
        raw_html=raw_html,
        accessibility_tree=accessibility_tree,
        markdown_content=markdown_content,
        links=list(links or []),
        page_role_hint=page_role_hint,
        fetch_duration_ms=100,
    )


def _link(
    url: str,
    *,
    text: str = "",
    context: str = "",
    role: str = "",
) -> PageLink:
    return PageLink(
        url=url,
        text=text,
        context=context,
        is_cross_domain=False,
        estimated_target_role=role,
    )


def test_tracker_page_relevance_distinguishes_target_and_off_target() -> None:
    target_snapshot = _snapshot(
        "https://security-tracker.debian.org/tracker/CVE-2024-3094",
        title="CVE-2024-3094",
        page_role_hint="tracker_page",
    )
    off_target_snapshot = _snapshot(
        "https://security-tracker.debian.org/tracker/CVE-2022-2509",
        title="CVE-2022-2509",
        page_role_hint="tracker_page",
    )

    assert (
        classify_tracker_page_relevance(
            target_snapshot,
            target_cve_id="CVE-2024-3094",
        )
        == "target"
    )
    assert (
        classify_tracker_page_relevance(
            off_target_snapshot,
            target_cve_id="CVE-2024-3094",
        )
        == "off_target"
    )


def test_tracker_page_defers_high_priority_upstream_patch_candidates() -> None:
    state = build_initial_agent_state(run_id="run-1", cve_id="CVE-2024-3094")
    snapshot = _snapshot(
        "https://security-tracker.debian.org/tracker/CVE-2024-3094",
        title="CVE-2024-3094",
        page_role_hint="tracker_page",
    )

    filtered = filter_candidate_matches_for_page(
        state,
        snapshot=snapshot,
        candidate_matches=[
            {
                "candidate_url": "https://github.com/acme/project/commit/abcdef.patch",
                "patch_type": "github_commit_patch",
            },
            {
                "candidate_url": "https://patches.example/fix.patch",
                "patch_type": "patch",
            },
        ],
    )

    assert filtered == [
        {
            "candidate_url": "https://patches.example/fix.patch",
            "patch_type": "patch",
        }
    ]


def test_build_frontier_candidate_records_prioritizes_commit_from_tracker() -> None:
    state = build_initial_agent_state(run_id="run-1", cve_id="CVE-2024-3094")
    state["budget"]["max_children_per_node"] = 5
    commit_url = "https://github.com/acme/project/commit/abcdef"
    snapshot = _snapshot(
        "https://security-tracker.debian.org/tracker/CVE-2024-3094",
        title="CVE-2024-3094",
        page_role_hint="tracker_page",
        links=[
            _link(
                "https://bugzilla.example/show_bug.cgi?id=CVE-2024-3094",
                text="Bugzilla",
                context="bug reference",
                role="bugtracker_page",
            ),
            _link(
                commit_url,
                text="upstream fix commit",
                context="fix CVE-2024-3094",
                role="commit_page",
            ),
        ],
    )

    records = build_frontier_candidate_records(state, snapshot=snapshot, depth=1)

    assert records[0]["url"] == commit_url
    assert records[0]["page_role"] == "commit_page"


def test_agent_nodes_keeps_private_frontier_skill_facade() -> None:
    from app.cve import agent_frontier_skill
    from app.cve import agent_nodes

    assert agent_nodes._build_frontier_candidate_records is (
        agent_frontier_skill.build_frontier_candidate_records
    )
    assert agent_nodes._filter_candidate_matches_for_page is (
        agent_frontier_skill.filter_candidate_matches_for_page
    )
    assert agent_nodes._is_blocked_or_empty_page is (
        agent_frontier_skill.is_blocked_or_empty_page
    )
    assert agent_nodes._CODE_FIX_PAGE_ROLES is agent_frontier_skill.CODE_FIX_PAGE_ROLES


def test_blocked_or_empty_page_detects_browser_blockers() -> None:
    assert is_blocked_or_empty_page(
        _snapshot(
            "https://example.test",
            final_url="chrome-error://chromewebdata/",
            markdown_content="",
            raw_html="<html><body></body></html>",
            accessibility_tree="",
        )
    )
    assert is_blocked_or_empty_page(
        _snapshot(
            "https://example.test",
            title="Just a moment",
            markdown_content="Checking your browser before accessing",
        )
    )
