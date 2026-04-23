from app.cve.agent_policy import evaluate_stop_condition
from app.cve.agent_policy import validate_agent_decision
from app.cve.agent_policy import validate_needs_human_review
from app.cve.agent_state import build_initial_agent_state


def _build_state() -> dict[str, object]:
    state = build_initial_agent_state(run_id="run-1", cve_id="CVE-2024-3094")
    state["frontier"] = [
        {
            "url": "https://example.com/frontier",
            "depth": 0,
            "score": 10,
            "expanded": False,
        }
    ]
    state["page_nodes"] = [
        {
            "url": "https://example.com/frontier",
        }
    ]
    state["page_observations"] = {
        "https://example.com/frontier": {
            "extracted_links": ["https://example.com/child", "https://other.example.com/cross"],
        }
    }
    return state


def test_validate_agent_decision_rejects_unknown_action() -> None:
    decision = validate_agent_decision(
        _build_state(),
        {"action": "invent_new_action", "selected_urls": []},
    )

    assert decision.accepted is False
    assert decision.rejection_reason == "invalid_action"


def test_validate_agent_decision_rejects_unknown_selected_url() -> None:
    decision = validate_agent_decision(
        _build_state(),
        {"action": "expand_frontier", "selected_urls": ["https://evil.example.com/patch"]},
    )

    assert decision.accepted is False
    assert decision.rejection_reason == "selected_url_not_in_current_page_or_frontier"


def test_validate_agent_decision_rejects_cross_domain_when_budget_exhausted() -> None:
    state = _build_state()
    state["budget"]["max_cross_domain_expansions"] = 0
    state["page_observations"]["https://example.com/frontier"]["frontier_candidates"] = [
        {
            "url": "https://other.example.com/cross",
            "anchor_text": "cross",
            "link_context": "candidate",
            "page_role": "tracker_page",
            "score": 20,
        }
    ]
    decision = validate_agent_decision(
        state,
        {"action": "expand_frontier", "selected_urls": ["https://other.example.com/cross"]},
    )

    assert decision.accepted is False
    assert decision.rejection_reason == "cross_domain_budget_exhausted"


def test_validate_agent_decision_rejects_duplicate_url() -> None:
    state = _build_state()
    state["visited_urls"] = ["https://example.com/child"]
    decision = validate_agent_decision(
        state,
        {"action": "expand_frontier", "selected_urls": ["https://example.com/child"]},
    )

    assert decision.accepted is False
    assert decision.rejection_reason == "duplicate_url"


def test_validate_agent_decision_forces_stop_search_when_page_budget_exhausted() -> None:
    state = _build_state()
    state["budget"]["max_pages_total"] = 1
    state["current_page_url"] = "https://example.com/frontier"
    state["page_observations"] = {
        "https://example.com/frontier": {
            "fetch_status": "fetched",
            "extracted_links": ["https://example.com/child"],
        }
    }
    decision = validate_agent_decision(
        state,
        {"action": "expand_frontier", "selected_urls": ["https://example.com/child"]},
    )

    assert decision.accepted is False
    assert decision.rejection_reason == "max_pages_total_exhausted"
    assert decision.normalized_action == "stop_search"


def test_validate_agent_decision_ignores_queued_children_for_page_budget() -> None:
    state = _build_state()
    state["budget"]["max_pages_total"] = 2
    state["current_page_url"] = "https://example.com/frontier"
    state["page_nodes"] = [
        {
            "url": "https://example.com/frontier",
            "fetch_status": "fetched",
        },
        {
            "url": "https://example.com/queued-1",
            "fetch_status": "queued",
        },
        {
            "url": "https://example.com/queued-2",
            "fetch_status": "queued",
        },
    ]
    state["page_observations"] = {
        "https://example.com/frontier": {
            "fetch_status": "fetched",
            "extracted_links": ["https://example.com/child"],
        }
    }

    decision = validate_agent_decision(
        state,
        {"action": "expand_frontier", "selected_urls": ["https://example.com/child"]},
    )

    assert decision.accepted is True
    assert decision.rejection_reason is None


def test_evaluate_stop_condition_keeps_running_when_active_chains_exist() -> None:
    state = build_initial_agent_state(run_id="run-1", cve_id="CVE-2024-3094")
    state["navigation_chains"] = [
        {
            "chain_id": "chain-1",
            "status": "in_progress",
            "expected_next_roles": ["commit_page"],
        }
    ]
    state["budget"]["max_pages_total"] = 20
    state["page_observations"] = {}

    evaluation = evaluate_stop_condition(state)

    assert evaluation.should_stop is False
    assert evaluation.reason == "active_chains_in_progress"


def test_evaluate_stop_condition_stops_immediately_when_patch_downloaded() -> None:
    state = build_initial_agent_state(run_id="run-1", cve_id="CVE-2024-3094")
    state["patches"] = [
        {
            "download_status": "downloaded",
            "candidate_url": "https://example.com/fix.patch",
        }
    ]
    state["navigation_chains"] = [
        {
            "chain_id": "chain-1",
            "status": "in_progress",
            "expected_next_roles": ["commit_page"],
        }
    ]
    state["frontier"] = [{"url": "https://example.com/next", "expanded": False}]
    state["page_observations"] = {}

    evaluation = evaluate_stop_condition(state)

    assert evaluation.should_stop is True
    assert evaluation.reason == "patches_downloaded"


def test_evaluate_stop_condition_does_not_stop_on_empty_patch_list() -> None:
    state = build_initial_agent_state(run_id="run-1", cve_id="CVE-2024-3094")
    state["patches"] = []
    state["navigation_chains"] = [
        {
            "chain_id": "chain-1",
            "status": "in_progress",
            "expected_next_roles": ["commit_page"],
        }
    ]
    state["page_observations"] = {}

    evaluation = evaluate_stop_condition(state)

    assert evaluation.should_stop is False
    assert evaluation.reason == "active_chains_in_progress"


def test_validate_needs_human_review_rejects_when_active_chain_exists() -> None:
    state = build_initial_agent_state(run_id="run-1", cve_id="CVE-2024-3094")
    state["navigation_chains"] = [
        {
            "chain_id": "chain-1",
            "status": "in_progress",
            "expected_next_roles": ["commit_page"],
        }
    ]

    assert validate_needs_human_review(state) is False


def test_validate_agent_decision_accepts_browser_snapshot_links() -> None:
    state = build_initial_agent_state(run_id="run-1", cve_id="CVE-2024-3094")
    state["current_page_url"] = "https://security-tracker.debian.org/tracker/CVE-2022-2509"
    state["page_observations"] = {
        "https://security-tracker.debian.org/tracker/CVE-2022-2509": {
            "frontier_candidates": [
                {
                    "url": "https://gitlab.com/org/proj/-/commit/abc1234",
                    "anchor_text": "upstream fix",
                    "link_context": "tracker -> commit",
                    "page_role": "commit_page",
                    "score": 120,
                }
            ]
        }
    }

    decision = validate_agent_decision(
        state,
        {
            "action": "expand_frontier",
            "selected_urls": ["https://gitlab.com/org/proj/-/commit/abc1234"],
        },
    )

    assert decision.accepted is True
    assert decision.normalized_selected_urls == [
        "https://gitlab.com/org/proj/-/commit/abc1234"
    ]


def test_validate_agent_decision_rejects_historical_page_link_not_in_current_candidates() -> None:
    state = build_initial_agent_state(run_id="run-1", cve_id="CVE-2024-3094")
    state["current_page_url"] = "https://security-tracker.debian.org/tracker/CVE-2022-2509"
    state["page_observations"] = {
        "https://security-tracker.debian.org/tracker/CVE-2022-2509": {
            "frontier_candidates": [
                {
                    "url": "https://gitlab.com/org/proj/-/commit/current1234",
                    "anchor_text": "current fix",
                    "link_context": "tracker -> commit",
                    "page_role": "commit_page",
                    "score": 120,
                }
            ]
        },
        "https://example.com/older-page": {
            "frontier_candidates": [
                {
                    "url": "https://gitlab.com/org/proj/-/commit/old9999",
                    "anchor_text": "old fix",
                    "link_context": "older page candidate",
                    "page_role": "commit_page",
                    "score": 80,
                }
            ]
        },
    }

    decision = validate_agent_decision(
        state,
        {
            "action": "expand_frontier",
            "selected_urls": ["https://gitlab.com/org/proj/-/commit/old9999"],
        },
    )

    assert decision.accepted is False
    assert decision.rejection_reason == "selected_url_not_in_current_page_or_frontier"


def test_validate_agent_decision_rejects_unknown_selected_candidate_key() -> None:
    state = build_initial_agent_state(run_id="run-1", cve_id="CVE-2024-3094")
    state["direct_candidates"] = [
        {
            "canonical_key": "https://gitlab.com/org/proj/-/commit/abc1234.patch",
            "candidate_url": "https://gitlab.com/org/proj/-/commit/abc1234.patch",
            "patch_type": "github_commit_patch",
        }
    ]

    decision = validate_agent_decision(
        state,
        {
            "action": "try_candidate_download",
            "selected_candidate_keys": ["https://example.com/not-found.patch"],
        },
    )

    assert decision.accepted is False
    assert decision.rejection_reason == "selected_candidate_key_not_in_candidates"
