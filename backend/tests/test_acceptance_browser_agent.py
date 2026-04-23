from __future__ import annotations

import json
import os
import uuid
from types import SimpleNamespace
from pathlib import Path

from app.cve.agent_policy import build_default_budget
from app.models.cve import CVECandidateArtifact
from app.models.cve import CVEPatchArtifact
from app.models.cve import CVESearchDecision
from app.models.cve import CVESearchNode
from scripts import acceptance_browser_agent as acceptance_module
from scripts import acceptance_regression_gate as gate_module
from scripts.acceptance_browser_agent import main
from scripts.acceptance_browser_agent import parse_args
from scripts.acceptance_browser_agent import _build_baseline_sample
from scripts.acceptance_browser_agent import _build_navigation_context_presence
from scripts.acceptance_browser_agent import _compare_acceptance_reports
from scripts.acceptance_browser_agent import _build_effective_budget_report
from scripts.acceptance_browser_agent import _build_scenario_report
from scripts.acceptance_browser_agent import _build_performance_summary
from scripts.acceptance_browser_agent import _determine_verdict
from scripts.acceptance_browser_agent import _temporary_acceptance_env
from scripts.acceptance_regression_gate import _evaluate_gate_result
from scripts.acceptance_regression_gate import _load_baseline_report


def test_parse_args_accepts_runtime_budget_overrides() -> None:
    args = parse_args(
        [
            "--cve",
            "CVE-2022-2509",
            "--llm-wall-clock-timeout-seconds",
            "75",
            "--diagnostic-timeout-seconds",
            "240",
            "--max-llm-calls",
            "3",
            "--max-pages-total",
            "12",
        ]
    )

    assert args.llm_wall_clock_timeout_seconds == 75
    assert args.diagnostic_timeout_seconds == 240
    assert args.max_llm_calls == 3
    assert args.max_pages_total == 12


def test_parse_args_accepts_profile_and_mock_mode() -> None:
    args = parse_args(
        [
            "--cve",
            "CVE-2022-2509",
            "--profile",
            "dashscope-stable",
            "--mock-mode",
            "llm-timeout-forced",
        ]
    )

    assert args.profile == "dashscope-stable"
    assert args.mock_mode == "llm-timeout-forced"


def test_parse_args_accepts_compare_report_inputs() -> None:
    args = parse_args(
        [
            "--baseline-report",
            "baseline.json",
            "--candidate-report",
            "candidate.json",
        ]
    )

    assert args.baseline_report == "baseline.json"
    assert args.candidate_report == "candidate.json"


def test_build_default_budget_allows_environment_overrides(monkeypatch) -> None:
    monkeypatch.setenv("AETHERFLOW_CVE_MAX_PAGES_TOTAL", "9")
    monkeypatch.setenv("AETHERFLOW_CVE_MAX_LLM_CALLS", "2")
    monkeypatch.setenv("AETHERFLOW_CVE_MAX_CHILDREN_PER_NODE", "4")

    budget = build_default_budget()

    assert budget["max_pages_total"] == 9
    assert budget["max_llm_calls"] == 2
    assert budget["max_children_per_node"] == 4


def test_build_default_budget_uses_defaults_when_env_missing(monkeypatch) -> None:
    monkeypatch.delenv("AETHERFLOW_CVE_MAX_PAGES_TOTAL", raising=False)
    monkeypatch.delenv("AETHERFLOW_CVE_MAX_LLM_CALLS", raising=False)
    monkeypatch.delenv("AETHERFLOW_CVE_MAX_CHILDREN_PER_NODE", raising=False)

    budget = build_default_budget()

    assert budget["max_pages_total"] == 20
    assert budget["max_llm_calls"] == 15
    assert budget["max_children_per_node"] == 5


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
        profile_name=None,
        mock_mode=None,
    )

    assert report["page_roles_visited"] == ["advisory_page"]


def test_temporary_acceptance_env_applies_profile_defaults_and_allows_cli_override(
    monkeypatch,
) -> None:
    monkeypatch.setenv("LLM_WALL_CLOCK_TIMEOUT_SECONDS", "44")
    monkeypatch.setenv("AETHERFLOW_CVE_MAX_LLM_CALLS", "5")

    args = SimpleNamespace(
        profile="dashscope-stable",
        llm_wall_clock_timeout_seconds=75,
        diagnostic_timeout_seconds=None,
        max_llm_calls=None,
        max_pages_total=None,
        mock_mode=None,
    )

    with _temporary_acceptance_env(args):
        assert os.getenv("LLM_WALL_CLOCK_TIMEOUT_SECONDS") == "75"
        assert os.getenv("AETHERFLOW_CVE_MAX_LLM_CALLS") == "4"

    assert os.getenv("LLM_WALL_CLOCK_TIMEOUT_SECONDS") == "44"
    assert os.getenv("AETHERFLOW_CVE_MAX_LLM_CALLS") == "5"


def test_temporary_acceptance_env_rule_fallback_profile_forces_llm_timeout_controls(
    monkeypatch,
) -> None:
    monkeypatch.delenv("LLM_WALL_CLOCK_TIMEOUT_SECONDS", raising=False)
    monkeypatch.delenv("AETHERFLOW_CVE_MAX_LLM_CALLS", raising=False)

    args = SimpleNamespace(
        profile="rule-fallback-only",
        llm_wall_clock_timeout_seconds=None,
        diagnostic_timeout_seconds=None,
        max_llm_calls=None,
        max_pages_total=None,
        mock_mode=None,
    )

    with _temporary_acceptance_env(args):
        assert os.getenv("LLM_WALL_CLOCK_TIMEOUT_SECONDS") == "1"
        assert os.getenv("AETHERFLOW_CVE_MAX_LLM_CALLS") == "1"


def test_build_effective_budget_report_includes_profile_and_mock_mode() -> None:
    report = _build_effective_budget_report(
        {
            "budget": {
                "max_pages_total": 9,
                "max_llm_calls": 2,
            }
        },
        profile_name="dashscope-stable",
        mock_mode="llm-timeout-forced",
    )

    assert report["profile"] == "dashscope-stable"
    assert report["mock_mode"] == "llm-timeout-forced"
    assert report["max_pages_total"] == 9
    assert report["max_llm_calls"] == 2


def test_build_scenario_report_records_effective_runtime_budget() -> None:
    previous_values = {
        "LLM_WALL_CLOCK_TIMEOUT_SECONDS": os.getenv("LLM_WALL_CLOCK_TIMEOUT_SECONDS"),
        "AETHERFLOW_CVE_RUNTIME_DIAGNOSTIC_TIMEOUT_SECONDS": os.getenv(
            "AETHERFLOW_CVE_RUNTIME_DIAGNOSTIC_TIMEOUT_SECONDS"
        ),
    }
    try:
        os.environ["LLM_WALL_CLOCK_TIMEOUT_SECONDS"] = "75"
        os.environ["AETHERFLOW_CVE_RUNTIME_DIAGNOSTIC_TIMEOUT_SECONDS"] = "240"
        run = type(
            "_Run",
            (),
            {
                "run_id": uuid.uuid4(),
                "status": "failed",
                "stop_reason": "diagnostic_timeout",
                "summary_json": {
                    "patch_found": False,
                    "chain_summary": [],
                },
            },
        )()
        final_state = {
            "budget": {
                "max_pages_total": 9,
                "max_llm_calls": 2,
            }
        }

        report = _build_scenario_report(
            scenario=type("_Scenario", (), {"cve_id": "CVE-2022-2509", "description": "test"})(),
            run=run,
            final_state=final_state,
            nodes=[],
            edges=[],
            decisions=[],
            candidates=[],
            patches=[],
            llm_logs=[],
            duration_seconds=1.0,
            memory_peak_mb=1.0,
            runtime_error=None,
            profile_name="dashscope-stable",
            mock_mode=None,
        )

        assert report["effective_budget"] == {
            "profile": "dashscope-stable",
            "mock_mode": None,
            "max_pages_total": 9,
            "max_llm_calls": 2,
            "llm_wall_clock_timeout_seconds": 75,
            "diagnostic_timeout_seconds": 240,
        }
    finally:
        for key, value in previous_values.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_build_scenario_report_includes_acceptance_matrix_metrics() -> None:
    run_id = uuid.uuid4()
    run = type(
        "_Run",
        (),
        {
            "run_id": run_id,
            "status": "succeeded",
            "stop_reason": "patches_downloaded",
            "summary_json": {
                "patch_found": True,
                "chain_summary": [],
            },
        },
    )()
    nodes = [
        CVESearchNode(
            run_id=run_id,
            url="https://lists.example.org/post",
            depth=0,
            host="lists.example.org",
            page_role="mailing_list_page",
            fetch_status="fetched",
        ),
        CVESearchNode(
            run_id=run_id,
            url="https://github.com/acme/project/pull/42",
            depth=1,
            host="github.com",
            page_role="pull_request_page",
            fetch_status="fetched",
        ),
    ]
    decisions = [
        type(
            "_Decision",
            (),
            {
                "decision_type": "rule_fallback",
                "input_json": {
                    "current_page": {"url": "https://lists.example.org/post"},
                    "navigation_path": [
                        "mailing_list_page: https://lists.example.org/post",
                        "pull_request_page: https://github.com/acme/project/pull/42",
                    ],
                },
            },
        )(),
        type(
            "_Decision",
            (),
            {
                "decision_type": "expand_frontier",
                "input_json": {
                    "current_page": {"url": "https://github.com/acme/project/pull/42"},
                    "navigation_path": [
                        "mailing_list_page: https://lists.example.org/post",
                        "pull_request_page: https://github.com/acme/project/pull/42",
                    ],
                },
            },
        )(),
    ]
    candidates = [
        CVECandidateArtifact(
            run_id=run_id,
            candidate_url="https://github.com/acme/project/pull/42.patch",
            candidate_type="github_pull_patch",
            canonical_key="github-pull-42",
            download_status="discovered",
            validation_status="pending",
            evidence_json={
                "discovery_rule": "url_fallback",
            },
        )
    ]
    patches = [
        CVEPatchArtifact(
            run_id=run_id,
            candidate_url="https://github.com/acme/project/pull/42.patch",
            patch_type="github_pull_patch",
            download_status="downloaded",
            patch_meta_json={},
        )
    ]
    llm_logs = [
        {"action": "llm_call_failed", "latency_ms": 900},
        {"action": "expand_frontier", "latency_ms": 1200},
    ]
    final_state = {
        "budget": {"max_pages_total": 12, "max_llm_calls": 4},
        "page_role_history": [
            {"url": "https://lists.example.org/post", "role": "mailing_list_page"},
            {
                "url": "https://github.com/acme/project/pull/42",
                "role": "pull_request_page",
            },
        ],
    }

    report = _build_scenario_report(
        scenario=type("_Scenario", (), {"cve_id": "CVE-2024-0001", "description": "test"})(),
        run=run,
        final_state=final_state,
        nodes=nodes,
        edges=[],
        decisions=decisions,
        candidates=candidates,
        patches=patches,
        llm_logs=llm_logs,
        duration_seconds=1.0,
        memory_peak_mb=1.0,
        runtime_error=None,
        profile_name="rule-fallback-only",
        mock_mode="llm-timeout-forced",
    )

    assert report["llm_call_count"] == 2
    assert report["llm_failure_count"] == 1
    assert report["rule_fallback_count"] == 1
    assert report["url_fallback_candidate_count"] == 1
    assert report["visited_page_roles"] == ["mailing_list_page", "pull_request_page"]
    assert report["selected_patch_types"] == ["github_pull_patch"]
    assert report["navigation_path"] == [
        "mailing_list_page: https://lists.example.org/post",
        "pull_request_page: https://github.com/acme/project/pull/42",
    ]
    assert report["final_patch_urls"] == ["https://github.com/acme/project/pull/42.patch"]
    assert "hosted_fix_navigation" in report["baseline_sample"]["sample_types"]


def test_build_baseline_sample_marks_tracker_commit_patch_contract() -> None:
    report = {
        "stop_reason": "patches_downloaded",
        "llm_call_count": 2,
        "llm_failure_count": 0,
        "rule_fallback_count": 0,
        "url_fallback_candidate_count": 0,
        "visited_page_roles": ["tracker_page", "commit_page"],
        "selected_patch_types": ["gitlab_commit_patch"],
        "navigation_path": [
            "tracker_page: https://security-tracker.example.org/CVE-2022-2509",
            "commit_page: https://gitlab.example.org/group/project/-/commit/abc1234",
        ],
        "final_patch_urls": ["https://gitlab.example.org/group/project/-/commit/abc1234.patch"],
    }

    baseline = _build_baseline_sample(report)

    assert "tracker_commit_patch" in baseline["sample_types"]
    assert "final_patch_urls" in baseline["stable_fields"]
    assert "duration_seconds" in baseline["volatile_fields"]


def test_build_baseline_sample_marks_rule_fallback_timeout_contract() -> None:
    report = {
        "stop_reason": "no_patch_candidates",
        "llm_call_count": 1,
        "llm_failure_count": 1,
        "rule_fallback_count": 2,
        "url_fallback_candidate_count": 0,
        "visited_page_roles": ["mailing_list_page", "tracker_page"],
        "selected_patch_types": [],
        "navigation_path": [
            "mailing_list_page: https://lists.example.org/post",
            "tracker_page: https://security-tracker.example.org/CVE-2022-2509",
        ],
        "final_patch_urls": [],
        "effective_budget": {
            "mock_mode": "llm-timeout-forced",
        },
    }

    baseline = _build_baseline_sample(report)

    assert "rule_fallback_timeout_chain" in baseline["sample_types"]
    assert "rule_fallback_count" in baseline["stable_fields"]
    assert "llm_failure_count" in baseline["stable_fields"]


def test_compare_acceptance_reports_marks_patch_and_path_changes() -> None:
    baseline_report = {
        "timestamp": "2026-04-23T00:00:00+00:00",
        "scenarios": [
            {
                "cve_id": "CVE-2022-2509",
                "stop_reason": "patches_downloaded",
                "llm_call_count": 2,
                "llm_failure_count": 0,
                "rule_fallback_count": 0,
                "url_fallback_candidate_count": 0,
                "visited_page_roles": ["tracker_page", "commit_page"],
                "selected_patch_types": ["gitlab_commit_patch"],
                "navigation_path": [
                    "tracker_page: https://security-tracker.example.org/CVE-2022-2509",
                    "commit_page: https://gitlab.example.org/group/project/-/commit/abc1234",
                ],
                "final_patch_urls": ["https://gitlab.example.org/group/project/-/commit/abc1234.patch"],
            }
        ],
    }
    candidate_report = {
        "timestamp": "2026-04-24T00:00:00+00:00",
        "scenarios": [
            {
                "cve_id": "CVE-2022-2509",
                "stop_reason": "patches_downloaded",
                "llm_call_count": 2,
                "llm_failure_count": 0,
                "rule_fallback_count": 0,
                "url_fallback_candidate_count": 0,
                "visited_page_roles": ["tracker_page", "pull_request_page"],
                "selected_patch_types": ["github_pull_patch"],
                "navigation_path": [
                    "tracker_page: https://security-tracker.example.org/CVE-2022-2509",
                    "pull_request_page: https://github.com/acme/project/pull/42",
                ],
                "final_patch_urls": ["https://github.com/acme/project/pull/42.patch"],
            }
        ],
    }

    diff = _compare_acceptance_reports(baseline_report, candidate_report)

    scenario_diff = diff["scenario_diffs"][0]
    assert scenario_diff["signals"]["patch_url_changed"] is True
    assert scenario_diff["signals"]["navigation_path_changed"] is True
    assert scenario_diff["signals"]["high_value_path_regressed"] is False


def test_compare_acceptance_reports_marks_rule_fallback_increase_and_new_page_roles() -> None:
    baseline_report = {
        "scenarios": [
            {
                "cve_id": "CVE-2024-3094",
                "stop_reason": "no_remaining_frontier_or_candidates",
                "llm_call_count": 1,
                "llm_failure_count": 0,
                "rule_fallback_count": 1,
                "url_fallback_candidate_count": 0,
                "visited_page_roles": ["mailing_list_page", "tracker_page"],
                "selected_patch_types": [],
                "navigation_path": ["mailing_list_page: https://lists.example.org/post"],
                "final_patch_urls": [],
            }
        ],
    }
    candidate_report = {
        "scenarios": [
            {
                "cve_id": "CVE-2024-3094",
                "stop_reason": "no_patch_candidates",
                "llm_call_count": 1,
                "llm_failure_count": 1,
                "rule_fallback_count": 3,
                "url_fallback_candidate_count": 0,
                "visited_page_roles": ["mailing_list_page", "tracker_page", "repository_page"],
                "selected_patch_types": [],
                "navigation_path": ["mailing_list_page: https://lists.example.org/post"],
                "final_patch_urls": [],
            }
        ],
    }

    diff = _compare_acceptance_reports(baseline_report, candidate_report)

    scenario_diff = diff["scenario_diffs"][0]
    assert scenario_diff["signals"]["more_rule_fallback"] is True
    assert scenario_diff["signals"]["new_page_roles"] == ["repository_page"]
    assert scenario_diff["field_diffs"]["stop_reason"]["changed"] is True


def test_compare_acceptance_reports_marks_patch_quality_degradation() -> None:
    baseline_report = {
        "scenarios": [
            {
                "cve_id": "CVE-2022-2509",
                "stop_reason": "patches_downloaded",
                "llm_call_count": 2,
                "llm_failure_count": 0,
                "rule_fallback_count": 0,
                "url_fallback_candidate_count": 0,
                "visited_page_roles": ["tracker_page", "commit_page"],
                "selected_patch_types": ["gitlab_commit_patch"],
                "navigation_path": [
                    "tracker_page: https://security-tracker.example.org/CVE-2022-2509",
                    "commit_page: https://gitlab.example.org/group/project/-/commit/abc1234",
                ],
                "final_patch_urls": ["https://gitlab.example.org/group/project/-/commit/abc1234.patch"],
            }
        ],
    }
    candidate_report = {
        "scenarios": [
            {
                "cve_id": "CVE-2022-2509",
                "stop_reason": "patches_downloaded",
                "llm_call_count": 2,
                "llm_failure_count": 0,
                "rule_fallback_count": 0,
                "url_fallback_candidate_count": 0,
                "visited_page_roles": ["tracker_page", "download_page"],
                "selected_patch_types": ["patch"],
                "navigation_path": [
                    "tracker_page: https://security-tracker.example.org/CVE-2022-2509",
                    "download_page: https://patches.ubuntu.com/example.patch",
                ],
                "final_patch_urls": ["https://patches.ubuntu.com/example.patch"],
            }
        ],
    }

    diff = _compare_acceptance_reports(baseline_report, candidate_report)

    scenario_diff = diff["scenario_diffs"][0]
    assert scenario_diff["signals"]["patch_quality_degraded"] is True
    assert scenario_diff["signals"]["baseline_patch_quality"]["best_patch_type"] == "gitlab_commit_patch"
    assert scenario_diff["signals"]["candidate_patch_quality"]["best_patch_type"] == "patch"


def test_main_compare_mode_writes_structured_json_diff(
    tmp_path: Path,
    capsys,
) -> None:
    baseline_path = tmp_path / "baseline.json"
    candidate_path = tmp_path / "candidate.json"
    baseline_path.write_text(
        json.dumps(
            {
                "timestamp": "2026-04-23T00:00:00+00:00",
                "scenarios": [
                    {
                        "cve_id": "CVE-2022-2509",
                        "stop_reason": "patches_downloaded",
                        "llm_call_count": 2,
                        "llm_failure_count": 0,
                        "rule_fallback_count": 0,
                        "url_fallback_candidate_count": 0,
                        "visited_page_roles": ["tracker_page", "commit_page"],
                        "selected_patch_types": ["gitlab_commit_patch"],
                        "navigation_path": ["tracker_page: a", "commit_page: b"],
                        "final_patch_urls": ["https://gitlab.example.org/group/project/-/commit/abc1234.patch"],
                    }
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    candidate_path.write_text(
        json.dumps(
            {
                "timestamp": "2026-04-24T00:00:00+00:00",
                "scenarios": [
                    {
                        "cve_id": "CVE-2022-2509",
                        "stop_reason": "patches_downloaded",
                        "llm_call_count": 2,
                        "llm_failure_count": 1,
                        "rule_fallback_count": 2,
                        "url_fallback_candidate_count": 0,
                        "visited_page_roles": ["tracker_page", "download_page"],
                        "selected_patch_types": ["patch"],
                        "navigation_path": ["tracker_page: a", "download_page: c"],
                        "final_patch_urls": ["https://patches.ubuntu.com/example.patch"],
                    }
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "--baseline-report",
            str(baseline_path),
            "--candidate-report",
            str(candidate_path),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    payload = json.loads(captured.out)
    assert payload["scenario_diffs"][0]["signals"]["patch_quality_degraded"] is True


def test_acceptance_gate_baseline_fixture_contains_required_sample_types() -> None:
    baseline = _load_baseline_report(gate_module.DEFAULT_BASELINE_REPORT_PATH)

    sample_types = {
        sample_type
        for scenario in baseline["scenarios"]
        for sample_type in scenario["baseline_sample"]["sample_types"]
    }

    assert {"tracker_commit_patch", "hosted_fix_navigation", "rule_fallback_timeout_chain"}.issubset(
        sample_types
    )


def test_acceptance_gate_fails_on_high_value_regression() -> None:
    comparison = {
        "scenario_diffs": [
            {
                "cve_id": "CVE-2022-2509",
                "signals": {
                    "patch_quality_degraded": True,
                    "high_value_path_regressed": False,
                    "patch_url_changed": True,
                    "navigation_path_changed": True,
                    "more_rule_fallback": False,
                    "new_page_roles": [],
                },
            }
        ]
    }

    result = _evaluate_gate_result(comparison)

    assert result["passed"] is False
    assert result["exit_code"] == 1
    assert result["failures"] == [
        {
            "cve_id": "CVE-2022-2509",
            "signal": "patch_quality_degraded",
        }
    ]


def test_acceptance_gate_warns_but_passes_on_path_or_fallback_changes() -> None:
    comparison = {
        "scenario_diffs": [
            {
                "cve_id": "CVE-2024-3094",
                "signals": {
                    "patch_quality_degraded": False,
                    "high_value_path_regressed": False,
                    "patch_url_changed": False,
                    "navigation_path_changed": True,
                    "more_rule_fallback": True,
                    "new_page_roles": ["repository_page"],
                },
            }
        ]
    }

    result = _evaluate_gate_result(comparison)

    assert result["passed"] is True
    assert result["exit_code"] == 0
    assert result["warnings"] == [
        {
            "cve_id": "CVE-2024-3094",
            "signal": "navigation_path_changed",
        },
        {
            "cve_id": "CVE-2024-3094",
            "signal": "more_rule_fallback",
        },
        {
            "cve_id": "CVE-2024-3094",
            "signal": "new_page_roles",
            "roles": ["repository_page"],
        },
    ]


def test_acceptance_gate_main_writes_json_and_returns_failure_on_regression(
    tmp_path: Path,
    monkeypatch,
    capsys,
) -> None:
    baseline_report = {
        "timestamp": "2026-04-23T00:00:00+00:00",
        "scenarios": [
            {
                "cve_id": "CVE-2022-2509",
                "baseline_sample": {
                    "sample_types": ["tracker_commit_patch"],
                    "stable_fields": ["stop_reason", "final_patch_urls"],
                    "volatile_fields": ["duration_seconds"],
                },
                "stop_reason": "patches_downloaded",
                "llm_call_count": 1,
                "llm_failure_count": 0,
                "rule_fallback_count": 0,
                "url_fallback_candidate_count": 0,
                "visited_page_roles": ["tracker_page", "commit_page"],
                "selected_patch_types": ["gitlab_commit_patch"],
                "navigation_path": ["tracker_page: a", "commit_page: b"],
                "final_patch_urls": ["https://gitlab.example.org/group/project/-/commit/abc1234.patch"],
            }
        ],
    }
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(json.dumps(baseline_report, ensure_ascii=False), encoding="utf-8")

    candidate_report = {
        "timestamp": "2026-04-24T00:00:00+00:00",
        "scenarios": [
            {
                "cve_id": "CVE-2022-2509",
                "stop_reason": "patches_downloaded",
                "llm_call_count": 1,
                "llm_failure_count": 0,
                "rule_fallback_count": 0,
                "url_fallback_candidate_count": 0,
                "visited_page_roles": ["tracker_page", "download_page"],
                "selected_patch_types": ["patch"],
                "navigation_path": ["tracker_page: a", "download_page: c"],
                "final_patch_urls": ["https://patches.ubuntu.com/example.patch"],
            }
        ],
    }
    candidate_path = tmp_path / "candidate.json"
    output_path = tmp_path / "gate_result.json"
    candidate_path.write_text(json.dumps(candidate_report, ensure_ascii=False), encoding="utf-8")

    monkeypatch.setattr(gate_module, "_generate_candidate_report", lambda args: candidate_path)

    exit_code = gate_module.main(
        [
            "--baseline-report",
            str(baseline_path),
            "--candidate-report",
            str(candidate_path),
            "--output",
            str(output_path),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 1
    payload = json.loads(captured.out)
    assert payload["passed"] is False
    assert output_path.exists()
    written = json.loads(output_path.read_text(encoding="utf-8"))
    assert written["failures"][0]["signal"] == "patch_quality_degraded"


def test_main_mock_mode_writes_stable_acceptance_report_json(
    tmp_path: Path,
    monkeypatch,
) -> None:
    fake_report = {
        "cve_id": "CVE-2022-2509",
        "description": "mock regression",
        "run_id": "run-1",
        "status": "failed",
        "stop_reason": "no_patch_candidates",
        "patch_found": False,
        "patch_urls": [],
        "llm_call_count": 1,
        "llm_failure_count": 1,
        "rule_fallback_count": 1,
        "url_fallback_candidate_count": 0,
        "visited_page_roles": ["mailing_list_page", "tracker_page"],
        "selected_patch_types": [],
        "navigation_path": [
            "mailing_list_page: https://lists.example.org/post",
            "tracker_page: https://security-tracker.example.org/CVE-2022-2509",
        ],
        "final_patch_urls": [],
        "effective_budget": {
            "profile": "rule-fallback-only",
            "mock_mode": "llm-timeout-forced",
        },
        "verdict": "FAIL",
    }
    fake_llm_logs = [{"action": "llm_call_failed", "latency_ms": 1000}]

    class _FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def commit(self) -> None:
            return None

    class _FakeSessionFactory:
        def __call__(self):
            return _FakeSession()

    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://demo:demo@127.0.0.1:5432/demo")
    monkeypatch.setattr(acceptance_module, "create_engine_from_url", lambda url: object())
    monkeypatch.setattr(acceptance_module, "_prepare_database", lambda engine: None)
    monkeypatch.setattr(acceptance_module, "create_session_factory", lambda url: _FakeSessionFactory())
    monkeypatch.setattr(
        acceptance_module,
        "_run_mock_scenario",
        lambda session, *, scenario, mock_mode, profile_name: (dict(fake_report), list(fake_llm_logs)),
    )

    exit_code = main(
        [
            "--cve",
            "CVE-2022-2509",
            "--profile",
            "rule-fallback-only",
            "--mock-mode",
            "llm-timeout-forced",
            "--results-dir",
            str(tmp_path),
        ]
    )

    assert exit_code == 0
    report_path = tmp_path / "acceptance_report.json"
    llm_log_path = tmp_path / "llm_decisions_log.jsonl"
    assert report_path.exists()
    assert llm_log_path.exists()

    written_report = json.loads(report_path.read_text(encoding="utf-8"))
    assert written_report["scenarios"][0]["effective_budget"]["profile"] == "rule-fallback-only"
    assert written_report["scenarios"][0]["effective_budget"]["mock_mode"] == "llm-timeout-forced"
    assert written_report["scenarios"][0]["llm_failure_count"] == 1
    assert written_report["scenarios"][0]["rule_fallback_count"] == 1
    assert written_report["scenarios"][0]["navigation_path"] == fake_report["navigation_path"]
