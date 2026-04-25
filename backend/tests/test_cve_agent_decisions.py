from __future__ import annotations

from dataclasses import asdict

from app.cve.agent_state import build_initial_agent_state
from app.cve.browser.base import BrowserPageSnapshot
from app.cve.decisions import fallback
from app.cve.decisions.fallback import build_rule_fallback_decision
from app.cve.decisions.fallback import select_fallback_frontier_urls


def _make_snapshot(
    url: str,
    *,
    page_role_hint: str = "frontier_page",
    title: str = "fake",
) -> BrowserPageSnapshot:
    return BrowserPageSnapshot(
        url=url,
        final_url=url,
        status_code=200,
        title=title,
        raw_html="<html><body>fake</body></html>",
        accessibility_tree="heading 'fake'",
        markdown_content="fake",
        links=[],
        page_role_hint=page_role_hint,
        fetch_duration_ms=100,
    )


def test_rule_fallback_prefers_direct_candidate_download() -> None:
    state = {
        "direct_candidates": [
            {
                "canonical_key": "commit-key",
                "patch_type": "github_commit_patch",
                "candidate_url": "https://github.com/acme/project/commit/abcdef1",
            }
        ],
        "frontier": [],
        "budget": {},
    }

    decision = build_rule_fallback_decision(state)

    assert decision["action"] == "try_candidate_download"
    assert decision["selected_candidate_keys"] == ["commit-key"]
    assert decision["selected_urls"] == []


def test_rule_fallback_explores_when_low_quality_candidate_has_frontier() -> None:
    state = {
        "direct_candidates": [
            {
                "canonical_key": "distro-key",
                "patch_type": "debdiff",
                "candidate_url": "https://bugs.debian.org/bugreport.cgi?bug=1;filename=fix.diff",
            }
        ],
        "frontier": [
            {
                "url": "https://git.example.org/project/commit/abcdef1",
                "expanded": False,
                "score": 30,
                "page_role": "commit_page",
            }
        ],
        "budget": {
            "max_children_per_node": 1,
            "max_cross_domain_expansions": 1,
        },
        "visited_urls": [],
        "browser_snapshots": {},
    }

    decision = build_rule_fallback_decision(state)

    assert decision["action"] == "expand_frontier"
    assert decision["selected_urls"] == ["https://git.example.org/project/commit/abcdef1"]
    assert decision["selected_candidate_keys"] == []
    assert decision["reason_summary"] == "规则回退：仅有低质量候选，继续探索寻找上游 commit。"


def test_chain_guided_fallback_prefers_active_chain_expected_roles() -> None:
    state = build_initial_agent_state(run_id="run-1", cve_id="CVE-2024-0001")
    state["current_page_url"] = "https://lists.example.org/post"
    state["budget"]["max_children_per_node"] = 1
    state["budget"]["max_cross_domain_expansions"] = 1
    state["navigation_chains"] = [
        {
            "chain_id": "chain-1",
            "status": "in_progress",
            "expected_next_roles": ["commit_page", "pull_request_page"],
        }
    ]
    state["frontier"] = [
        {
            "url": "https://lists.example.org/archive",
            "expanded": False,
            "score": 100,
            "page_role": "mailing_list_page",
        },
        {
            "url": "https://github.com/acme/project/commit/abcdef1",
            "expanded": False,
            "score": 10,
            "page_role": "commit_page",
        },
    ]

    decision = build_rule_fallback_decision(state)

    assert decision["action"] == "expand_frontier"
    assert decision["selected_urls"] == ["https://github.com/acme/project/commit/abcdef1"]
    assert decision["reason_summary"] == "规则回退：按活跃链路优先扩展期望角色 frontier。"


def test_stage_guided_fallback_uses_current_snapshot_role_before_url_role() -> None:
    current_url = "https://nvd.nist.gov/vuln/detail/CVE-2024-3094"
    state = build_initial_agent_state(run_id="run-1", cve_id="CVE-2024-3094")
    state["current_page_url"] = current_url
    state["browser_snapshots"] = {
        current_url: asdict(
            _make_snapshot(
                current_url,
                page_role_hint="tracker_page",
                title="CVE-2024-3094 tracker",
            )
        )
    }
    state["budget"]["max_children_per_node"] = 1
    state["budget"]["max_cross_domain_expansions"] = 1
    state["frontier"] = [
        {
            "url": "https://example.com/advisory",
            "expanded": False,
            "score": 200,
            "page_role": "advisory_page",
        },
        {
            "url": "https://github.com/acme/project/commit/abcdef1",
            "expanded": False,
            "score": 10,
            "page_role": "commit_page",
        },
    ]

    decision = build_rule_fallback_decision(state)

    assert decision["action"] == "expand_frontier"
    assert decision["selected_urls"] == ["https://github.com/acme/project/commit/abcdef1"]
    assert decision["reason_summary"] == "规则回退：按当前链路阶段优先扩展目标角色 frontier。"


def test_fallback_url_selection_respects_cross_domain_budget() -> None:
    state = build_initial_agent_state(run_id="run-1", cve_id="CVE-2024-0001")
    state["current_page_url"] = "https://tracker.example.org/CVE-2024-0001"
    state["budget"]["max_children_per_node"] = 2
    state["budget"]["max_cross_domain_expansions"] = 0

    selected_urls = select_fallback_frontier_urls(
        state,
        [
            {
                "url": "https://git.example.org/project/commit/abcdef1",
                "expanded": False,
                "score": 100,
                "page_role": "commit_page",
            },
        ],
    )

    assert selected_urls == []


def test_rule_fallback_stops_when_no_candidates_or_frontier() -> None:
    decision = build_rule_fallback_decision(
        {
            "direct_candidates": [],
            "frontier": [],
            "budget": {},
        }
    )

    assert decision["action"] == "stop_search"
    assert decision["reason_summary"] == "规则回退：没有可继续扩展的 frontier，也没有 patch 候选。"
    assert decision["selected_urls"] == []
    assert decision["selected_candidate_keys"] == []


def test_agent_nodes_keeps_private_fallback_decision_facade() -> None:
    from app.cve import agent_nodes

    assert agent_nodes._STAGE_FALLBACK_TARGET_ROLES_BY_SOURCE is (
        fallback.STAGE_FALLBACK_TARGET_ROLES_BY_SOURCE
    )
    assert agent_nodes._candidate_priority is fallback.candidate_priority
    assert agent_nodes._select_fallback_frontier_urls is (
        fallback.select_fallback_frontier_urls
    )
    assert agent_nodes._select_chain_guided_frontier_urls is (
        fallback.select_chain_guided_frontier_urls
    )
    assert agent_nodes._target_roles_for_current_stage is (
        fallback.target_roles_for_current_stage
    )
    assert agent_nodes._filter_frontier_items_by_target_roles is (
        fallback.filter_frontier_items_by_target_roles
    )
    assert agent_nodes._select_stage_guided_frontier_urls is (
        fallback.select_stage_guided_frontier_urls
    )
    assert agent_nodes._build_rule_fallback_decision is fallback.build_rule_fallback_decision
