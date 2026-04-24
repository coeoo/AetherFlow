from __future__ import annotations

import logging
import os
from time import monotonic
from uuid import UUID

from sqlalchemy.orm import Session

from app.config import load_settings
from app.cve.agent_graph import build_cve_patch_graph
from app.cve.agent_nodes import agent_decide_node
from app.cve.agent_nodes import build_initial_frontier_node
from app.cve.agent_nodes import download_and_validate_node
from app.cve.agent_nodes import extract_links_and_candidates_node
from app.cve.agent_nodes import fetch_next_batch_node
from app.cve.agent_nodes import finalize_run_node
from app.cve.agent_nodes import resolve_seeds_node
from app.cve.agent_state import build_initial_agent_state
from app.cve.browser.playwright_backend import PlaywrightBackend
from app.cve.browser.sync_bridge import SyncBrowserBridge
from app.models import CVERun

_logger = logging.getLogger(__name__)
_DIAGNOSTIC_MODE_ENV = "AETHERFLOW_CVE_RUNTIME_DIAGNOSTIC_MODE"
_MAX_DIAGNOSTIC_ROUNDS = 5
_GRAPH_RECURSION_LIMIT = 64

_EXCEPTION_STOP_REASONS = {
    "resolve_seeds": "resolve_seeds_failed",
    "build_initial_frontier": "build_initial_frontier_failed",
    "fetch_next_batch": "fetch_next_batch_failed",
    "extract_links_and_candidates": "extract_links_and_candidates_failed",
    "agent_decide": "agent_decide_failed",
    "download_and_validate": "download_and_validate_failed",
    "finalize_run": "finalize_run_failed",
}


def _finalize_failure(run: CVERun, *, stop_reason: str, summary: dict[str, object]) -> None:
    run.status = "failed"
    run.stop_reason = stop_reason
    run.summary_json = summary


def _build_failure_summary(*, error: str | None = None) -> dict[str, object]:
    summary: dict[str, object] = {
        "runtime_kind": "patch_agent_graph",
        "patch_found": False,
        "patch_count": 0,
    }
    if error:
        summary["error"] = error
    return summary


def _diagnostic_mode_enabled() -> bool:
    return str(os.getenv(_DIAGNOSTIC_MODE_ENV, "")).strip().lower() in {"1", "true", "yes", "on"}


def _diagnostic_state_summary(state: dict[str, object]) -> dict[str, object]:
    return {
        "next_action": state.get("next_action"),
        "stop_reason": state.get("stop_reason"),
        "frontier_count": len(list(state.get("frontier") or [])),
        "direct_candidate_count": len(list(state.get("direct_candidates") or [])),
        "selected_candidate_keys_count": len(list(state.get("selected_candidate_keys") or [])),
    }


def _run_diagnostic_node(
    *,
    session: Session,
    run: CVERun,
    state: dict[str, object],
    node_name: str,
    node_func,
    round_index: int | None = None,
) -> dict[str, object]:
    label = f"诊断第 {round_index} 轮节点 {node_name}" if round_index is not None else f"诊断节点 {node_name}"
    started_at = monotonic()
    _logger.info(
        "[CVE:%s] 进入%s, context=%s",
        run.cve_id,
        label,
        _diagnostic_state_summary(state),
    )
    try:
        next_state = node_func(state)
        session.flush()
        session.commit()
    except Exception:
        _logger.exception(
            "[CVE:%s] %s 失败, elapsed=%.2fs, context=%s",
            run.cve_id,
            label,
            monotonic() - started_at,
            _diagnostic_state_summary(state),
        )
        raise
    _logger.info(
        "[CVE:%s] %s 完成, elapsed=%.2fs, phase=%s, context=%s",
        run.cve_id,
        label,
        monotonic() - started_at,
        run.phase,
        _diagnostic_state_summary(next_state),
    )
    return next_state


def _execute_diagnostic_run(
    *,
    session: Session,
    run: CVERun,
    state: dict[str, object],
) -> dict[str, object]:
    settings = load_settings()
    current_state = state
    budget = dict(current_state.get("budget") or {})
    budget["max_parallel_frontier"] = 1
    current_state["budget"] = budget
    diagnostic_timeout_seconds = max(
        1,
        int(settings.cve_runtime_diagnostic_timeout_seconds or 180),
    )

    setup_sequence = [
        ("resolve_seeds", resolve_seeds_node),
        ("build_initial_frontier", build_initial_frontier_node),
    ]

    for node_name, node_func in setup_sequence:
        current_state = _run_diagnostic_node(
            session=session,
            run=run,
            state=current_state,
            node_name=node_name,
            node_func=node_func,
        )
        if current_state.get("stop_reason"):
            break

    if not current_state.get("stop_reason"):
        diagnostic_started_at = monotonic()
        for round_index in range(1, _MAX_DIAGNOSTIC_ROUNDS + 1):
            elapsed = monotonic() - diagnostic_started_at
            if elapsed > diagnostic_timeout_seconds:
                _logger.warning(
                    "[CVE:%s] 诊断模式超过总时限 %ds（已用 %.1fs），强制终止循环",
                    run.cve_id,
                    diagnostic_timeout_seconds,
                    elapsed,
                )
                if not current_state.get("stop_reason"):
                    current_state["stop_reason"] = "diagnostic_timeout"
                break
            for node_name, node_func in [
                ("fetch_next_batch", fetch_next_batch_node),
                ("extract_links_and_candidates", extract_links_and_candidates_node),
                ("agent_decide", agent_decide_node),
            ]:
                current_state = _run_diagnostic_node(
                    session=session,
                    run=run,
                    state=current_state,
                    node_name=node_name,
                    node_func=node_func,
                    round_index=round_index,
                )

            next_action = str(current_state.get("next_action") or "")
            if next_action == "try_candidate_download":
                current_state = _run_diagnostic_node(
                    session=session,
                    run=run,
                    state=current_state,
                    node_name="download_and_validate",
                    node_func=download_and_validate_node,
                    round_index=round_index,
                )
                next_action = str(current_state.get("next_action") or "")

            if current_state.get("stop_reason"):
                break
            if next_action not in {"expand_frontier", "fetch_next_batch"}:
                break

    current_state = _run_diagnostic_node(
        session=session,
        run=run,
        state=current_state,
        node_name="finalize_run",
        node_func=finalize_run_node,
    )
    return current_state


def execute_cve_run(session: Session, *, run_id: UUID) -> dict[str, object]:
    run = session.get(CVERun, run_id)
    if run is None:
        raise ValueError(f"CVE run 不存在: {run_id}")

    _logger.info("[CVE:%s] 开始执行 run=%s", run.cve_id, run_id)
    settings = load_settings()
    bridge = SyncBrowserBridge(
        PlaywrightBackend(
            pool_size=settings.cve_browser_pool_size,
            headless=settings.cve_browser_headless,
            cdp_endpoint=settings.cve_browser_cdp_endpoint,
        )
    )
    bridge.start()
    _logger.info("[CVE:%s] bridge.start() 完成", run.cve_id)
    state: dict[str, object] = {}
    try:
        state = build_initial_agent_state(run_id=str(run.run_id), cve_id=run.cve_id)
        budget = dict(state.get("budget") or {})
        budget["max_parallel_frontier"] = 1
        state["budget"] = budget
        state["session"] = session
        state["_browser_bridge"] = bridge
        if _diagnostic_mode_enabled():
            _logger.info("[CVE:%s] 诊断模式开启，使用逐节点执行", run.cve_id)
            state = _execute_diagnostic_run(session=session, run=run, state=state)
        else:
            graph = build_cve_patch_graph()
            _logger.info("[CVE:%s] graph.invoke() 开始", run.cve_id)
            state = graph.invoke(
                state,
                config={"recursion_limit": _GRAPH_RECURSION_LIMIT},
            )
            _logger.info(
                "[CVE:%s] graph.invoke() 完成, stop_reason=%s",
                run.cve_id,
                state.get("stop_reason"),
            )
    except Exception as exc:
        _finalize_failure(
            run,
            stop_reason=_EXCEPTION_STOP_REASONS.get(run.phase, "run_failed"),
            summary=_build_failure_summary(error=str(exc)),
        )
        _logger.exception("[CVE:%s] graph.invoke() 失败", run.cve_id)
    finally:
        bridge.stop()
        session.flush()
    return state
