from __future__ import annotations

import uuid

from app.models.cve import CVESearchNode
from scripts.acceptance_browser_agent import _build_navigation_context_presence
from scripts.acceptance_browser_agent import _build_scenario_report
from scripts.acceptance_browser_agent import _build_performance_summary
from scripts.acceptance_browser_agent import _determine_verdict


def test_determine_verdict_marks_cve_2022_2509_as_pass_when_patch_chain_is_complete() -> None:
    report = {
        "cve_id": "CVE-2022-2509",
        "status": "succeeded",
        "stop_reason": "patches_downloaded",
        "patch_found": True,
        "patch_urls": ["https://gitlab.com/gnutls/gnutls/-/commit/ce37f9eb.patch"],
        "chain_count": 1,
        "completed_chains": 1,
        "dead_end_chains": 0,
        "page_roles_visited": ["advisory_page", "tracker_page", "commit_page"],
        "cross_domain_edges_count": 1,
        "db_validation": {
            "run_summary_present": True,
            "nodes_have_page_role": True,
            "edges_recorded": True,
            "decisions_include_navigation_context": True,
            "candidates_recorded": True,
        },
        "error": None,
    }

    verdict, reason = _determine_verdict(report)

    assert verdict == "PASS"
    assert reason is None


def test_determine_verdict_marks_cve_2024_3094_as_pass_without_patch_when_multi_chain_completes() -> None:
    report = {
        "cve_id": "CVE-2024-3094",
        "status": "failed",
        "stop_reason": "no_remaining_frontier_or_candidates",
        "patch_found": False,
        "patch_urls": [],
        "chain_count": 2,
        "completed_chains": 1,
        "dead_end_chains": 1,
        "page_roles_visited": ["mailing_list_page", "advisory_page", "commit_page"],
        "cross_domain_edges_count": 2,
        "db_validation": {
            "run_summary_present": True,
            "nodes_have_page_role": True,
            "edges_recorded": True,
            "decisions_include_navigation_context": True,
            "candidates_recorded": False,
        },
        "error": None,
    }

    verdict, reason = _determine_verdict(report)

    assert verdict == "PASS"
    assert reason is None


def test_determine_verdict_marks_runtime_error_as_skip() -> None:
    report = {
        "cve_id": "CVE-2022-2509",
        "status": "failed",
        "stop_reason": "fetch_next_batch_failed",
        "patch_found": False,
        "patch_urls": [],
        "chain_count": 0,
        "completed_chains": 0,
        "dead_end_chains": 0,
        "page_roles_visited": [],
        "cross_domain_edges_count": 0,
        "db_validation": {
            "run_summary_present": True,
            "nodes_have_page_role": False,
            "edges_recorded": False,
            "decisions_include_navigation_context": False,
            "candidates_recorded": False,
        },
        "error": "page.goto: net::ERR_NAME_NOT_RESOLVED",
    }

    verdict, reason = _determine_verdict(report)

    assert verdict == "SKIP"
    assert "ERR_NAME_NOT_RESOLVED" in str(reason)


def test_build_performance_summary_aggregates_duration_and_chain_rate() -> None:
    summary = _build_performance_summary(
        [
            {
                "duration_seconds": 45.0,
                "chain_count": 1,
                "completed_chains": 1,
                "verdict": "PASS",
            },
            {
                "duration_seconds": 80.0,
                "chain_count": 2,
                "completed_chains": 1,
                "verdict": "PASS",
            },
        ]
    )

    assert summary["total_duration_seconds"] == 125.0
    assert summary["max_single_run_seconds"] == 80.0
    assert summary["all_under_3_minutes"] is True
    assert summary["chain_completion_rate"] == 0.67


def test_build_navigation_context_presence_accepts_rule_fallback_with_navigation_context() -> None:
    decisions = [
        {
            "decision_type": "rule_fallback",
            "input_json": {
                "current_page": {"url": "https://nvd.nist.gov/vuln/detail/CVE-2022-2509"},
                "navigation_path": ["advisory_page: https://nvd.nist.gov/vuln/detail/CVE-2022-2509"],
            },
        }
    ]

    assert _build_navigation_context_presence(decisions) is True


def test_determine_verdict_allows_llm_timeout_fallback_without_failed_db_validation() -> None:
    report = {
        "cve_id": "CVE-2022-2509",
        "status": "failed",
        "stop_reason": "stop_search",
        "patch_found": False,
        "patch_urls": [],
        "chain_count": 5,
        "completed_chains": 0,
        "dead_end_chains": 0,
        "page_roles_visited": ["advisory_page", "tracker_page"],
        "cross_domain_edges_count": 4,
        "db_validation": {
            "run_summary_present": True,
            "nodes_have_page_role": True,
            "edges_recorded": True,
            "decisions_include_navigation_context": True,
            "candidates_recorded": False,
        },
        "error": None,
    }

    verdict, reason = _determine_verdict(report)

    assert verdict == "FAIL"
    assert "patch 链路" in str(reason)


def test_build_scenario_report_only_counts_fetched_page_roles() -> None:
    run = type(
        "_Run",
        (),
        {
            "run_id": uuid.uuid4(),
            "status": "failed",
            "stop_reason": "stop_search",
            "summary_json": {
                "patch_found": False,
                "chain_summary": [],
            },
        },
    )()
    fetched_node = CVESearchNode(
        run_id=run.run_id,
        url="https://nvd.nist.gov/vuln/detail/CVE-2022-2509",
        depth=0,
        host="nvd.nist.gov",
        page_role="advisory_page",
        fetch_status="fetched",
    )
    queued_node = CVESearchNode(
        run_id=run.run_id,
        url="https://security-tracker.debian.org/tracker/CVE-2022-2509",
        depth=1,
        host="security-tracker.debian.org",
        page_role="tracker_page",
        fetch_status="queued",
    )

    report = _build_scenario_report(
        scenario=type("_Scenario", (), {"cve_id": "CVE-2022-2509", "description": "test"})(),
        run=run,
        final_state={},
        nodes=[fetched_node, queued_node],
        edges=[],
        decisions=[],
        candidates=[],
        patches=[],
        llm_logs=[],
        duration_seconds=1.0,
        memory_peak_mb=1.0,
        runtime_error=None,
    )

    assert report["page_roles_visited"] == ["advisory_page"]
