from app.cve.agent_search_tools import filter_frontier_links
from app.cve.agent_search_tools import coerce_rank
from app.cve.agent_search_tools import extract_cve_ids
from app.cve.agent_search_tools import is_high_value_frontier_link
from app.cve.agent_search_tools import is_mailing_list_navigation_noise
from app.cve.agent_search_tools import is_navigation_noise_url
from app.cve.agent_search_tools import score_frontier_candidate
from app.cve.agent_search_tools import should_skip_frontier_link
from app.cve.agent_search_tools import textual_fix_signal_score
from app.cve.browser.base import PageLink


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


def test_navigation_noise_url_rejects_global_noise_and_keeps_fix_pages() -> None:
    assert is_navigation_noise_url("mailto:security@example.test")
    assert is_navigation_noise_url(
        "https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator"
    )
    assert not is_navigation_noise_url("https://github.com/acme/project/commit/abcdef")


def test_mailing_list_navigation_noise_recognizes_archive_controls() -> None:
    assert is_mailing_list_navigation_noise(
        _link(
            "https://lists.debian.org/debian-lts-announce/prev-date.html",
            text="Date Prev",
            context="mail archive navigation",
            role="mailing_list_page",
        )
    )
    assert not is_mailing_list_navigation_noise(
        _link(
            "https://lists.debian.org/debian-lts-announce/2022/08/msg00001.html",
            text="CVE-2022-2509 fix",
            context="upstream patch reference",
            role="mailing_list_page",
        )
    )


def test_high_value_frontier_link_keeps_tracker_and_commit_targets() -> None:
    assert is_high_value_frontier_link(
        _link(
            "https://security-tracker.debian.org/tracker/CVE-2022-2509",
            role="tracker_page",
        )
    )
    assert is_high_value_frontier_link(
        _link("https://github.com/acme/project/commit/abcdef", role="commit_page")
    )
    assert not is_high_value_frontier_link(
        _link("https://www.debian.org/security/", role="tracker_page")
    )


def test_filter_frontier_links_deduplicates_and_skips_navigation_noise() -> None:
    links = [
        _link(
            "https://lists.debian.org/debian-lts-announce/prev-date.html",
            text="Date Prev",
            context="mail archive navigation",
            role="mailing_list_page",
        ),
        _link("https://github.com/acme/project/commit/abcdef", role="commit_page"),
        _link("https://github.com/acme/project/commit/abcdef", role="commit_page"),
        _link("https://example.com/about", text="About"),
    ]

    filtered_links = filter_frontier_links("mailing_list_page", links)

    assert [link.url for link in filtered_links] == [
        "https://github.com/acme/project/commit/abcdef"
    ]


def test_agent_nodes_keeps_private_search_tool_facade() -> None:
    from app.cve import agent_nodes
    from app.cve import agent_search_tools

    assert agent_nodes._filter_frontier_links is (
        agent_search_tools.filter_frontier_links
    )
    assert agent_nodes._score_frontier_candidate is (
        agent_search_tools.score_frontier_candidate
    )
    assert agent_nodes._coerce_rank is agent_search_tools.coerce_rank


def test_should_skip_frontier_link_keeps_high_value_link_before_noise_checks() -> None:
    assert not should_skip_frontier_link(
        "advisory_page",
        _link("https://github.com/acme/project/commit/abcdef", role="commit_page"),
    )
    assert should_skip_frontier_link(
        "advisory_page",
        _link("https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator"),
    )


def test_extract_cve_ids_normalizes_multiple_values() -> None:
    assert extract_cve_ids(
        "https://tracker.example/CVE-2022-2509",
        "fixed cve-2024-3094",
        "",
    ) == {"CVE-2022-2509", "CVE-2024-3094"}


def test_score_frontier_candidate_rewards_target_and_penalizes_off_target() -> None:
    target_link = _link(
        "https://github.com/acme/project/commit/abcdef",
        text="fix CVE-2024-3094",
        role="commit_page",
    )
    off_target_link = _link(
        "https://github.com/acme/project/commit/123456",
        text="fix CVE-2022-2509",
        role="commit_page",
    )

    target_score = score_frontier_candidate(
        normalized_url=target_link.url,
        link=target_link,
        target_cve_id="CVE-2024-3094",
        source_page_role="tracker_page",
    )
    off_target_score = score_frontier_candidate(
        normalized_url=off_target_link.url,
        link=off_target_link,
        target_cve_id="CVE-2024-3094",
        source_page_role="tracker_page",
    )

    assert target_score > off_target_score


def test_textual_fix_signal_score_counts_patch_related_signals() -> None:
    score = textual_fix_signal_score(
        {
            "url": "https://github.com/acme/project/commit/abcdef",
            "anchor_text": "Fix CVE-2024-3094 vulnerability",
            "link_context": "security patch",
        }
    )

    assert score >= 5


def test_coerce_rank_uses_default_for_invalid_values() -> None:
    assert coerce_rank("2") == 2
    assert coerce_rank(None) == 999
    assert coerce_rank("not-a-rank", default=7) == 7
