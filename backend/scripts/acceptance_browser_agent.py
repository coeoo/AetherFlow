from __future__ import annotations

import argparse
from contextlib import contextmanager
import json
import os
import tracemalloc
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Any
from unittest.mock import patch

from sqlalchemy import text
from sqlalchemy import select

from app.config import load_settings
from app.cve.runtime import execute_cve_run
from app.cve.service import create_cve_run
from app.db.base import Base
from app.db.session import create_engine_from_url
from app.db.session import create_session_factory
from app.models import CVERun
from app.models.cve import CVECandidateArtifact
from app.models.cve import CVEPatchArtifact
from app.models.cve import CVESearchDecision
from app.models.cve import CVESearchEdge
from app.models.cve import CVESearchNode


@dataclass(frozen=True)
class AcceptanceScenario:
    cve_id: str
    description: str


@dataclass(frozen=True)
class AcceptanceProfile:
    name: str
    llm_wall_clock_timeout_seconds: int | None = None
    diagnostic_timeout_seconds: int | None = None
    max_llm_calls: int | None = None
    max_pages_total: int | None = None


SCENARIOS = {
    "CVE-2022-2509": AcceptanceScenario(
        cve_id="CVE-2022-2509",
        description="GnuTLS Double Free 真实链路验收",
    ),
    "CVE-2024-3094": AcceptanceScenario(
        cve_id="CVE-2024-3094",
        description="xz-utils 多链路跨域验收",
    ),
}
_NETWORK_ERROR_MARKERS = (
    "ERR_NAME_NOT_RESOLVED",
    "ERR_CONNECTION",
    "ERR_TIMED_OUT",
    "ERR_HTTP2_PROTOCOL_ERROR",
    "Name or service not known",
    "Temporary failure in name resolution",
    "Connection refused",
    "Connection reset",
    "timed out",
    "Timeout",
    "net::",
)
_COMPARE_FIELDS = (
    "stop_reason",
    "llm_call_count",
    "llm_failure_count",
    "rule_fallback_count",
    "url_fallback_candidate_count",
    "visited_page_roles",
    "selected_patch_types",
    "navigation_path",
    "final_patch_urls",
)
_PATCH_TYPE_PRIORITY = {
    "github_commit_patch": 100,
    "gitlab_commit_patch": 100,
    "kernel_commit_patch": 100,
    "github_pull_patch": 90,
    "gitlab_merge_request_patch": 90,
    "patch": 50,
    "diff": 50,
    "debdiff": 20,
}
ACCEPTANCE_PROFILES = {
    "dashscope-stable": AcceptanceProfile(
        name="dashscope-stable",
        llm_wall_clock_timeout_seconds=90,
        diagnostic_timeout_seconds=360,
        max_llm_calls=4,
        max_pages_total=12,
    ),
    "dashscope-fast": AcceptanceProfile(
        name="dashscope-fast",
        llm_wall_clock_timeout_seconds=45,
        diagnostic_timeout_seconds=240,
        max_llm_calls=2,
        max_pages_total=10,
    ),
    "rule-fallback-only": AcceptanceProfile(
        name="rule-fallback-only",
        llm_wall_clock_timeout_seconds=1,
        diagnostic_timeout_seconds=180,
        max_llm_calls=1,
        max_pages_total=12,
    ),
}
MOCK_MODES = {
    "none",
    "llm-timeout-forced",
}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m scripts.acceptance_browser_agent",
        description="运行 CVE Patch 浏览器 Agent Phase 5A 验收脚本。",
    )
    parser.add_argument(
        "--cve",
        action="append",
        choices=sorted(SCENARIOS),
        help="仅运行指定 CVE，可重复传入多次。",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="运行全部验收场景。",
    )
    parser.add_argument(
        "--results-dir",
        default="results",
        help="报告输出目录，默认相对当前工作目录的 results。",
    )
    parser.add_argument(
        "--baseline-report",
        default=None,
        help="与 --candidate-report 一起使用，比较两份 acceptance_report.json。",
    )
    parser.add_argument(
        "--candidate-report",
        default=None,
        help="与 --baseline-report 一起使用，比较两份 acceptance_report.json。",
    )
    parser.add_argument(
        "--profile",
        choices=sorted(ACCEPTANCE_PROFILES),
        default=None,
        help="使用预设预算 profile。",
    )
    parser.add_argument(
        "--mock-mode",
        choices=sorted(MOCK_MODES - {"none"}),
        default=None,
        help="启用本地 mock 验收模式，不依赖真实供应商。",
    )
    parser.add_argument(
        "--llm-wall-clock-timeout-seconds",
        type=int,
        default=None,
        help="覆盖 LLM 总时限预算（秒）。",
    )
    parser.add_argument(
        "--diagnostic-timeout-seconds",
        type=int,
        default=None,
        help="覆盖诊断模式总时限预算（秒）。",
    )
    parser.add_argument(
        "--max-llm-calls",
        type=int,
        default=None,
        help="覆盖单次 run 的 LLM 调用上限。",
    )
    parser.add_argument(
        "--max-pages-total",
        type=int,
        default=None,
        help="覆盖单次 run 的页面抓取总上限。",
    )
    args = parser.parse_args(argv)
    if bool(args.baseline_report) ^ bool(args.candidate_report):
        parser.error("--baseline-report 和 --candidate-report 必须同时提供。")
    if args.baseline_report and args.cve:
        parser.error("compare 模式下不能同时提供 --cve/--all。")
    if args.baseline_report and args.all:
        parser.error("compare 模式下不能同时提供 --cve/--all。")
    if not args.all and not args.cve:
        if not args.baseline_report:
            parser.error("必须提供 --all 或至少一个 --cve。")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.baseline_report and args.candidate_report:
        baseline_report = json.loads(Path(args.baseline_report).read_text(encoding="utf-8"))
        candidate_report = json.loads(Path(args.candidate_report).read_text(encoding="utf-8"))
        comparison = _compare_acceptance_reports(baseline_report, candidate_report)
        print(json.dumps(comparison, ensure_ascii=False, indent=2))
        return 0

    scenario_ids = sorted(SCENARIOS) if args.all else list(dict.fromkeys(args.cve or []))
    settings = load_settings()
    if not settings.database_url:
        raise RuntimeError("缺少 DATABASE_URL/AETHERFLOW_DATABASE_URL，无法执行验收。")

    results_dir = Path(args.results_dir).resolve()
    results_dir.mkdir(parents=True, exist_ok=True)
    llm_log_path = results_dir / "llm_decisions_log.jsonl"
    report_path = results_dir / "acceptance_report.json"

    engine = create_engine_from_url(settings.database_url)
    _prepare_database(engine)
    session_factory = create_session_factory(settings.database_url)

    scenario_reports: list[dict[str, object]] = []
    llm_logs: list[dict[str, object]] = []
    with _temporary_acceptance_env(args):
        for scenario_id in scenario_ids:
            with session_factory() as session:
                if args.mock_mode:
                    report, scenario_llm_logs = _run_mock_scenario(
                        session,
                        scenario=SCENARIOS[scenario_id],
                        mock_mode=args.mock_mode,
                        profile_name=args.profile,
                    )
                else:
                    report, scenario_llm_logs = _run_scenario(
                        session,
                        scenario=SCENARIOS[scenario_id],
                        profile_name=args.profile,
                        mock_mode=args.mock_mode,
                    )
                session.commit()
            scenario_reports.append(report)
            llm_logs.extend(scenario_llm_logs)

    _write_jsonl(llm_log_path, llm_logs)
    final_report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "scenarios": scenario_reports,
        "performance_summary": _build_performance_summary(scenario_reports),
    }
    report_path.write_text(
        json.dumps(final_report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(final_report, ensure_ascii=False, indent=2))
    return 0


def _prepare_database(engine) -> None:
    with engine.begin() as connection:
        connection.execute(text("CREATE EXTENSION IF NOT EXISTS pgcrypto"))
    Base.metadata.create_all(engine)


def _run_scenario(
    session,
    *,
    scenario: AcceptanceScenario,
    profile_name: str | None,
    mock_mode: str | None,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    run = create_cve_run(session, cve_id=scenario.cve_id)
    session.commit()

    tracemalloc.start()
    started_at = perf_counter()
    final_state: dict[str, object] = {}
    runtime_error: str | None = None
    try:
        final_state = execute_cve_run(session, run_id=run.run_id) or {}
        session.commit()
    except Exception as exc:
        session.rollback()
        runtime_error = str(exc)
    current_peak, _ = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    reloaded_run = session.get(CVERun, run.run_id)
    if reloaded_run is None:
        raise RuntimeError(f"验收 run 丢失: {run.run_id}")

    nodes = _load_nodes(session, run_id=run.run_id)
    edges = _load_edges(session, run_id=run.run_id)
    decisions = _load_decisions(session, run_id=run.run_id)
    candidates = _load_candidates(session, run_id=run.run_id)
    patches = _load_patches(session, run_id=run.run_id)

    llm_logs = _normalize_llm_logs(
        list(final_state.get("_llm_decision_log") or []),
        cve_id=scenario.cve_id,
    )
    report = _build_scenario_report(
        scenario=scenario,
        run=reloaded_run,
        final_state=final_state,
        nodes=nodes,
        edges=edges,
        decisions=decisions,
        candidates=candidates,
        patches=patches,
        llm_logs=llm_logs,
        duration_seconds=round(perf_counter() - started_at, 2),
        memory_peak_mb=round(current_peak / (1024 * 1024), 2),
        runtime_error=runtime_error,
        profile_name=profile_name,
        mock_mode=mock_mode,
    )
    verdict, verdict_reason = _determine_verdict(report)
    report["verdict"] = verdict
    if verdict_reason:
        report["verdict_reason"] = verdict_reason
    return report, llm_logs


def _run_mock_scenario(
    session,
    *,
    scenario: AcceptanceScenario,
    mock_mode: str,
    profile_name: str | None,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    if mock_mode != "llm-timeout-forced":
        raise ValueError(f"未知 mock_mode: {mock_mode}")

    def _raise_timeout(*args, **kwargs):
        raise TimeoutError("forced llm timeout for acceptance regression")

    with patch("app.cve.agent_nodes.call_browser_agent_navigation", _raise_timeout):
        return _run_scenario(
            session,
            scenario=scenario,
            profile_name=profile_name,
            mock_mode=mock_mode,
        )


def _build_scenario_report(
    *,
    scenario: AcceptanceScenario,
    run: CVERun,
    final_state: dict[str, object],
    nodes: list[CVESearchNode],
    edges: list[CVESearchEdge],
    decisions: list[CVESearchDecision],
    candidates: list[CVECandidateArtifact],
    patches: list[CVEPatchArtifact],
    llm_logs: list[dict[str, object]],
    duration_seconds: float,
    memory_peak_mb: float,
    runtime_error: str | None,
    profile_name: str | None,
    mock_mode: str | None,
) -> dict[str, object]:
    summary = dict(run.summary_json or {})
    chain_summary = [
        dict(item)
        for item in list(summary.get("chain_summary") or [])
        if isinstance(item, dict)
    ]
    completed_chains = sum(1 for chain in chain_summary if str(chain.get("status")) == "completed")
    dead_end_chains = sum(1 for chain in chain_summary if str(chain.get("status")) == "dead_end")
    page_roles_visited = list(
        dict.fromkeys(
            str(node.page_role)
            for node in nodes
            if str(node.page_role).strip() and str(node.fetch_status) == "fetched"
        )
    )
    patch_urls = [
        patch.candidate_url
        for patch in patches
        if patch.download_status == "downloaded"
    ]
    selected_patch_types = list(
        dict.fromkeys(
            str(patch.patch_type)
            for patch in patches
            if str(patch.patch_type).strip()
        )
    )
    navigation_path = _build_navigation_path(final_state, decisions)
    browser_snapshots = dict(final_state.get("browser_snapshots") or {})
    page_fetch_durations = [
        int(snapshot.get("fetch_duration_ms") or 0)
        for snapshot in browser_snapshots.values()
        if isinstance(snapshot, dict)
    ]
    cross_domain_edges_count = sum(1 for edge in edges if "cross_domain" in edge.edge_type)
    llm_failure_count = sum(1 for item in llm_logs if str(item.get("action") or "") == "llm_call_failed")
    rule_fallback_count = sum(
        1 for decision in decisions if str(decision.decision_type or "") == "rule_fallback"
    )
    url_fallback_candidate_count = sum(
        1
        for candidate in candidates
        if str(dict(candidate.evidence_json or {}).get("discovery_rule") or "") == "url_fallback"
    )
    report = {
        "cve_id": scenario.cve_id,
        "description": scenario.description,
        "run_id": str(run.run_id),
        "status": run.status,
        "stop_reason": run.stop_reason,
        "duration_seconds": duration_seconds,
        "memory_peak_mb": memory_peak_mb,
        "patch_found": bool(summary.get("patch_found")),
        "patch_urls": patch_urls,
        "chain_count": len(chain_summary),
        "completed_chains": completed_chains,
        "dead_end_chains": dead_end_chains,
        "search_nodes_count": len(nodes),
        "search_edges_count": len(edges),
        "cross_domain_edges_count": cross_domain_edges_count,
        "cross_domain_hops": int(
            summary.get("cross_domain_hops")
            or final_state.get("cross_domain_hops")
            or 0
        ),
        "llm_call_count": len(llm_logs),
        "llm_failure_count": llm_failure_count,
        "rule_fallback_count": rule_fallback_count,
        "url_fallback_candidate_count": url_fallback_candidate_count,
        "llm_calls_count": len(llm_logs),
        "avg_llm_latency_ms": _average(
            [int(item.get("latency_ms") or 0) for item in llm_logs]
        ),
        "avg_page_load_ms": _average(page_fetch_durations),
        "effective_budget": _build_effective_budget_report(
            final_state,
            profile_name=profile_name,
            mock_mode=mock_mode,
        ),
        "page_roles_visited": page_roles_visited,
        "visited_page_roles": page_roles_visited,
        "selected_patch_types": selected_patch_types,
        "navigation_path": navigation_path,
        "final_patch_urls": patch_urls,
        "baseline_sample": _build_baseline_sample(
            {
                "stop_reason": run.stop_reason,
                "llm_call_count": len(llm_logs),
                "llm_failure_count": llm_failure_count,
                "rule_fallback_count": rule_fallback_count,
                "url_fallback_candidate_count": url_fallback_candidate_count,
                "visited_page_roles": page_roles_visited,
                "selected_patch_types": selected_patch_types,
                "navigation_path": navigation_path,
                "final_patch_urls": patch_urls,
                "effective_budget": {
                    "mock_mode": mock_mode,
                },
            }
        ),
        "db_validation": _validate_database_records(
            run=run,
            nodes=nodes,
            edges=edges,
            decisions=decisions,
            candidates=candidates,
        ),
        "error": runtime_error or summary.get("error"),
    }
    return report


def _validate_database_records(
    *,
    run: CVERun,
    nodes: list[CVESearchNode],
    edges: list[CVESearchEdge],
    decisions: list[CVESearchDecision],
    candidates: list[CVECandidateArtifact],
) -> dict[str, bool]:
    return {
        "run_summary_present": bool(run.summary_json) and run.stop_reason is not None,
        "nodes_have_page_role": bool(nodes) and all(bool(node.page_role) for node in nodes),
        "edges_recorded": bool(edges),
        "decisions_include_navigation_context": _build_navigation_context_presence(
            [
                {
                    "decision_type": decision.decision_type,
                    "input_json": dict(decision.input_json or {}),
                }
                for decision in decisions
            ]
        ),
        "candidates_recorded": bool(candidates),
    }


def _normalize_llm_logs(raw_logs: list[dict[str, object]], *, cve_id: str) -> list[dict[str, object]]:
    normalized: list[dict[str, object]] = []
    for index, log in enumerate(raw_logs, start=1):
        entry = dict(log)
        entry["cve_id"] = str(entry.get("cve_id") or cve_id)
        entry["step_index"] = int(entry.get("step_index") or index)
        entry["selected_urls"] = [
            str(url)
            for url in list(entry.get("selected_urls") or [])
            if str(url).strip()
        ]
        entry["selected_candidate_keys"] = [
            str(key)
            for key in list(entry.get("selected_candidate_keys") or [])
            if str(key).strip()
        ]
        normalized.append(entry)
    return normalized


def _build_navigation_context_presence(decisions: list[dict[str, object]]) -> bool:
    for decision in decisions:
        if not isinstance(decision, dict):
            continue
        input_json = decision.get("input_json")
        if not isinstance(input_json, dict):
            continue
        if "current_page" in input_json and isinstance(input_json.get("current_page"), dict):
            return True
    return False


def _load_nodes(session, *, run_id) -> list[CVESearchNode]:
    return session.execute(
        select(CVESearchNode)
        .where(CVESearchNode.run_id == run_id)
        .order_by(CVESearchNode.depth, CVESearchNode.created_at, CVESearchNode.node_id)
    ).scalars().all()


def _load_edges(session, *, run_id) -> list[CVESearchEdge]:
    return session.execute(
        select(CVESearchEdge)
        .where(CVESearchEdge.run_id == run_id)
        .order_by(CVESearchEdge.created_at, CVESearchEdge.edge_id)
    ).scalars().all()


def _load_decisions(session, *, run_id) -> list[CVESearchDecision]:
    return session.execute(
        select(CVESearchDecision)
        .where(CVESearchDecision.run_id == run_id)
        .order_by(CVESearchDecision.created_at, CVESearchDecision.decision_id)
    ).scalars().all()


def _load_candidates(session, *, run_id) -> list[CVECandidateArtifact]:
    return session.execute(
        select(CVECandidateArtifact)
        .where(CVECandidateArtifact.run_id == run_id)
        .order_by(CVECandidateArtifact.created_at, CVECandidateArtifact.candidate_id)
    ).scalars().all()


def _load_patches(session, *, run_id) -> list[CVEPatchArtifact]:
    return session.execute(
        select(CVEPatchArtifact)
        .where(CVEPatchArtifact.run_id == run_id)
        .order_by(CVEPatchArtifact.created_at, CVEPatchArtifact.patch_id)
    ).scalars().all()


def _looks_like_external_access_issue(error: object) -> bool:
    if error is None:
        return False
    normalized = str(error)
    return any(marker in normalized for marker in _NETWORK_ERROR_MARKERS)


def _determine_verdict(report: dict[str, object]) -> tuple[str, str | None]:
    error = report.get("error")
    if _looks_like_external_access_issue(error):
        return "SKIP", str(error)

    db_validation = dict(report.get("db_validation") or {})
    required_db_keys = [
        "run_summary_present",
        "nodes_have_page_role",
        "edges_recorded",
        "decisions_include_navigation_context",
    ]
    if bool(report.get("patch_found")):
        required_db_keys.append("candidates_recorded")
    if not all(bool(db_validation.get(key)) for key in required_db_keys):
        missing = [
            key
            for key in required_db_keys
            if not bool(db_validation.get(key))
        ]
        return "FAIL", f"数据库校验未通过: {', '.join(missing)}"

    cve_id = str(report.get("cve_id") or "")
    if cve_id == "CVE-2022-2509":
        conditions = [
            bool(report.get("patch_found")),
            bool(report.get("patch_urls")),
            "tracker_page" in list(report.get("page_roles_visited") or []),
            "commit_page" in list(report.get("page_roles_visited") or []),
            int(report.get("completed_chains") or 0) >= 1,
            str(report.get("stop_reason") or "") == "patches_downloaded",
        ]
        if all(conditions):
            return "PASS", None
        return "FAIL", "CVE-2022-2509 未满足完整 patch 链路验收条件"

    if cve_id == "CVE-2024-3094":
        conditions = [
            int(report.get("chain_count") or 0) >= 2,
            int(report.get("cross_domain_edges_count") or 0) >= 1,
            int(report.get("completed_chains") or 0) >= 1,
        ]
        if all(conditions):
            return "PASS", None
        return "FAIL", "CVE-2024-3094 未满足多链路跨域验收条件"

    return "PASS", None


def _build_performance_summary(scenarios: list[dict[str, object]]) -> dict[str, object]:
    if not scenarios:
        return {
            "total_duration_seconds": 0.0,
            "max_single_run_seconds": 0.0,
            "all_under_3_minutes": True,
            "chain_completion_rate": 0.0,
        }

    durations = [float(item.get("duration_seconds") or 0.0) for item in scenarios]
    total_chains = sum(int(item.get("chain_count") or 0) for item in scenarios)
    completed_chains = sum(int(item.get("completed_chains") or 0) for item in scenarios)
    rate = round((completed_chains / total_chains), 2) if total_chains else 0.0
    return {
        "total_duration_seconds": round(sum(durations), 2),
        "max_single_run_seconds": round(max(durations), 2),
        "all_under_3_minutes": all(duration <= 180 for duration in durations),
        "chain_completion_rate": rate,
    }


def _average(values: list[int]) -> float:
    if not values:
        return 0.0
    return round(sum(values) / len(values), 2)


def _build_effective_budget_report(
    final_state: dict[str, object],
    *,
    profile_name: str | None,
    mock_mode: str | None,
) -> dict[str, int | str | None]:
    settings = load_settings()
    state_budget = dict(final_state.get("budget") or {})
    effective_budget: dict[str, int | str | None] = {
        "profile": profile_name,
        "mock_mode": mock_mode,
    }
    for key in ("max_pages_total", "max_llm_calls"):
        value = state_budget.get(key)
        if value is None:
            continue
        effective_budget[key] = int(value)
    effective_budget["llm_wall_clock_timeout_seconds"] = int(
        settings.llm_wall_clock_timeout_seconds
    )
    effective_budget["diagnostic_timeout_seconds"] = int(
        settings.cve_runtime_diagnostic_timeout_seconds
    )
    return effective_budget


def _build_baseline_sample(report: dict[str, object]) -> dict[str, object]:
    sample_types: list[str] = []
    visited_page_roles = [str(role) for role in list(report.get("visited_page_roles") or [])]
    selected_patch_types = [str(patch_type) for patch_type in list(report.get("selected_patch_types") or [])]
    mock_mode = str(dict(report.get("effective_budget") or {}).get("mock_mode") or "")

    if "tracker_page" in visited_page_roles and "commit_page" in visited_page_roles and bool(
        report.get("final_patch_urls")
    ):
        sample_types.append("tracker_commit_patch")
    if {
        "tracker_page",
        "mailing_list_page",
        "commit_page",
    }.issubset(visited_page_roles) and any(
        patch_type in {"github_commit_patch", "gitlab_commit_patch", "kernel_commit_patch"}
        for patch_type in selected_patch_types
    ):
        sample_types.append("tracker_mailing_list_commit_patch")
    if "bugtracker_page" in visited_page_roles and "commit_page" in visited_page_roles and any(
        patch_type in {"github_commit_patch", "gitlab_commit_patch", "kernel_commit_patch"}
        for patch_type in selected_patch_types
    ):
        sample_types.append("bugtracker_commit_patch")
    if any(role in visited_page_roles for role in ("tracker_page", "mailing_list_page", "bugtracker_page")) and any(
        role in visited_page_roles for role in ("commit_page", "pull_request_page", "merge_request_page")
    ):
        sample_types.append("hosted_fix_navigation")
    if int(report.get("url_fallback_candidate_count") or 0) > 0 and bool(report.get("final_patch_urls")):
        sample_types.append("deterministic_url_fallback_patch")
    if mock_mode == "llm-timeout-forced" and int(report.get("rule_fallback_count") or 0) > 0:
        sample_types.append("rule_fallback_timeout_chain")
        if any(
            role in {"commit_page", "pull_request_page", "merge_request_page", "download_page"}
            for role in visited_page_roles
        ) and bool(report.get("final_patch_urls")):
            sample_types.append("rule_fallback_timeout_high_value_patch")

    stable_fields = [
        "stop_reason",
        "llm_call_count",
        "llm_failure_count",
        "rule_fallback_count",
        "url_fallback_candidate_count",
        "visited_page_roles",
        "selected_patch_types",
        "navigation_path",
        "final_patch_urls",
    ]
    volatile_fields = [
        "run_id",
        "duration_seconds",
        "memory_peak_mb",
        "timestamp",
    ]
    return {
        "sample_types": sample_types,
        "stable_fields": stable_fields,
        "volatile_fields": volatile_fields,
    }


def _compare_acceptance_reports(
    baseline_report: dict[str, object],
    candidate_report: dict[str, object],
) -> dict[str, object]:
    baseline_scenarios = {
        str(scenario.get("cve_id") or ""): dict(scenario)
        for scenario in list(baseline_report.get("scenarios") or [])
        if isinstance(scenario, dict) and str(scenario.get("cve_id") or "").strip()
    }
    candidate_scenarios = {
        str(scenario.get("cve_id") or ""): dict(scenario)
        for scenario in list(candidate_report.get("scenarios") or [])
        if isinstance(scenario, dict) and str(scenario.get("cve_id") or "").strip()
    }
    all_cve_ids = sorted(set(baseline_scenarios) | set(candidate_scenarios))
    scenario_diffs = [
        _compare_scenario_reports(
            cve_id,
            baseline_scenarios.get(cve_id),
            candidate_scenarios.get(cve_id),
        )
        for cve_id in all_cve_ids
    ]
    return {
        "baseline_timestamp": baseline_report.get("timestamp"),
        "candidate_timestamp": candidate_report.get("timestamp"),
        "scenario_diffs": scenario_diffs,
    }


def _compare_scenario_reports(
    cve_id: str,
    baseline: dict[str, object] | None,
    candidate: dict[str, object] | None,
) -> dict[str, object]:
    field_diffs: dict[str, dict[str, object]] = {}
    baseline = dict(baseline or {})
    candidate = dict(candidate or {})
    for field_name in _COMPARE_FIELDS:
        baseline_value = baseline.get(field_name)
        candidate_value = candidate.get(field_name)
        field_diffs[field_name] = {
            "baseline": baseline_value,
            "candidate": candidate_value,
            "changed": baseline_value != candidate_value,
        }

    baseline_roles = [str(role) for role in list(baseline.get("visited_page_roles") or [])]
    candidate_roles = [str(role) for role in list(candidate.get("visited_page_roles") or [])]
    baseline_patch_quality = _build_patch_quality_summary(
        list(baseline.get("selected_patch_types") or [])
    )
    candidate_patch_quality = _build_patch_quality_summary(
        list(candidate.get("selected_patch_types") or [])
    )
    baseline_path = [str(item) for item in list(baseline.get("navigation_path") or [])]
    candidate_path = [str(item) for item in list(candidate.get("navigation_path") or [])]
    signals = {
        "patch_url_changed": list(baseline.get("final_patch_urls") or []) != list(candidate.get("final_patch_urls") or []),
        "navigation_path_changed": baseline_path != candidate_path,
        "more_rule_fallback": int(candidate.get("rule_fallback_count") or 0)
        > int(baseline.get("rule_fallback_count") or 0),
        "new_page_roles": sorted(set(candidate_roles) - set(baseline_roles)),
        "patch_quality_degraded": candidate_patch_quality["best_priority"]
        < baseline_patch_quality["best_priority"],
        "baseline_patch_quality": baseline_patch_quality,
        "candidate_patch_quality": candidate_patch_quality,
        "high_value_path_regressed": _has_high_value_fix_host(baseline_roles)
        and not _has_high_value_fix_host(candidate_roles),
    }
    return {
        "cve_id": cve_id,
        "baseline_present": bool(baseline),
        "candidate_present": bool(candidate),
        "field_diffs": field_diffs,
        "signals": signals,
    }


def _build_patch_quality_summary(patch_types: list[object]) -> dict[str, object]:
    normalized_types = [str(patch_type) for patch_type in patch_types if str(patch_type).strip()]
    if not normalized_types:
        return {
            "best_patch_type": None,
            "best_priority": 0,
        }
    prioritized = sorted(
        normalized_types,
        key=lambda patch_type: _PATCH_TYPE_PRIORITY.get(patch_type, 0),
        reverse=True,
    )
    best_patch_type = prioritized[0]
    return {
        "best_patch_type": best_patch_type,
        "best_priority": _PATCH_TYPE_PRIORITY.get(best_patch_type, 0),
    }


def _has_high_value_fix_host(page_roles: list[str]) -> bool:
    return any(
        role in {"commit_page", "pull_request_page", "merge_request_page", "download_page"}
        for role in page_roles
    )


def _build_navigation_path(
    final_state: dict[str, object],
    decisions: list[CVESearchDecision],
) -> list[str]:
    page_role_history = [
        item
        for item in list(final_state.get("page_role_history") or [])
        if isinstance(item, dict)
    ]
    path_from_state = [
        f"{str(item.get('role') or '').strip()}: {str(item.get('url') or '').strip()}"
        for item in page_role_history
        if str(item.get("role") or "").strip() and str(item.get("url") or "").strip()
    ]
    if path_from_state:
        return path_from_state

    for decision in decisions:
        input_json = dict(decision.input_json or {})
        raw_path = input_json.get("navigation_path")
        if not isinstance(raw_path, list):
            continue
        normalized_path = [
            str(item).strip()
            for item in raw_path
            if str(item).strip()
        ]
        if normalized_path:
            return normalized_path
    return []


@contextmanager
def _temporary_acceptance_env(args: argparse.Namespace):
    profile = ACCEPTANCE_PROFILES.get(str(args.profile or "").strip())
    overrides = {
        "LLM_WALL_CLOCK_TIMEOUT_SECONDS": (
            args.llm_wall_clock_timeout_seconds
            if args.llm_wall_clock_timeout_seconds is not None
            else (profile.llm_wall_clock_timeout_seconds if profile else None)
        ),
        "AETHERFLOW_CVE_RUNTIME_DIAGNOSTIC_TIMEOUT_SECONDS": (
            args.diagnostic_timeout_seconds
            if args.diagnostic_timeout_seconds is not None
            else (profile.diagnostic_timeout_seconds if profile else None)
        ),
        "AETHERFLOW_CVE_MAX_LLM_CALLS": (
            args.max_llm_calls
            if args.max_llm_calls is not None
            else (profile.max_llm_calls if profile else None)
        ),
        "AETHERFLOW_CVE_MAX_PAGES_TOTAL": (
            args.max_pages_total
            if args.max_pages_total is not None
            else (profile.max_pages_total if profile else None)
        ),
    }
    previous_values = {key: os.getenv(key) for key in overrides}
    try:
        for key, value in overrides.items():
            if value is None:
                continue
            os.environ[key] = str(value)
        yield
    finally:
        for key, previous_value in previous_values.items():
            if previous_value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = previous_value


def _write_jsonl(path: Path, rows: list[dict[str, object]]) -> None:
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
