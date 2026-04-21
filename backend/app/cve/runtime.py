from __future__ import annotations

from uuid import UUID

from sqlalchemy.orm import Session

from app.config import load_settings
from app.cve.agent_graph import build_cve_patch_graph
from app.cve.agent_state import build_initial_agent_state
from app.cve.browser.playwright_backend import PlaywrightBackend
from app.cve.browser.sync_bridge import SyncBrowserBridge
from app.models import CVERun


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


def execute_cve_run(session: Session, *, run_id: UUID) -> None:
    run = session.get(CVERun, run_id)
    if run is None:
        raise ValueError(f"CVE run 不存在: {run_id}")

    settings = load_settings()
    bridge = SyncBrowserBridge(
        PlaywrightBackend(
            pool_size=settings.cve_browser_pool_size,
            headless=settings.cve_browser_headless,
            cdp_endpoint=settings.cve_browser_cdp_endpoint,
        )
    )
    bridge.start()
    try:
        graph = build_cve_patch_graph()
        state = build_initial_agent_state(run_id=str(run.run_id), cve_id=run.cve_id)
        state["session"] = session
        state["_browser_bridge"] = bridge
        graph.invoke(state)
    except Exception as exc:
        _finalize_failure(
            run,
            stop_reason=_EXCEPTION_STOP_REASONS.get(run.phase, "run_failed"),
            summary=_build_failure_summary(error=str(exc)),
        )
    finally:
        bridge.stop()
        session.flush()
