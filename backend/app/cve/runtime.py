from __future__ import annotations

from uuid import UUID

from sqlalchemy.orm import Session

from app.cve.page_analyzer import analyze_page
from app.cve.page_fetcher import fetch_page
from app.cve.patch_downloader import download_patch_candidate
from app.cve.seed_resolver import resolve_seed_references
from app.models import CVERun


def plan_frontier(seed_references: list[str]) -> list[str]:
    return list(seed_references)


def _update_phase(run: CVERun, phase: str) -> None:
    run.status = "running"
    run.phase = phase


def _finalize_failure(run: CVERun, *, stop_reason: str, summary: dict[str, object]) -> None:
    run.status = "failed"
    run.phase = "finalize_run"
    run.stop_reason = stop_reason
    run.summary_json = summary


def _finalize_success(run: CVERun, *, stop_reason: str, summary: dict[str, object]) -> None:
    run.status = "succeeded"
    run.phase = "finalize_run"
    run.stop_reason = stop_reason
    run.summary_json = summary


def execute_cve_run(session: Session, *, run_id: UUID) -> None:
    run = session.get(CVERun, run_id)
    if run is None:
        raise ValueError(f"CVE run 不存在: {run_id}")

    _update_phase(run, "resolve_seeds")
    session.flush()
    seed_references = resolve_seed_references(run.cve_id)
    if not seed_references:
        _finalize_failure(
            run,
            stop_reason="no_seed_references",
            summary={"patch_found": False, "patch_count": 0},
        )
        session.flush()
        return

    _update_phase(run, "plan_frontier")
    session.flush()
    frontier = plan_frontier(seed_references)

    _update_phase(run, "fetch_page")
    session.flush()
    snapshots = []
    try:
        for url in frontier:
            snapshots.append(fetch_page(url))
    except Exception as exc:
        _finalize_failure(
            run,
            stop_reason="fetch_failed",
            summary={"patch_found": False, "patch_count": 0, "error": str(exc)},
        )
        session.flush()
        return

    _update_phase(run, "analyze_page")
    session.flush()
    patch_candidates: list[dict[str, str]] = []
    for snapshot in snapshots:
        patch_candidates.extend(analyze_page(snapshot))

    if not patch_candidates:
        _finalize_failure(
            run,
            stop_reason="no_patch_candidates",
            summary={"patch_found": False, "patch_count": 0},
        )
        session.flush()
        return

    _update_phase(run, "download_patches")
    session.flush()
    patches = [
        download_patch_candidate(session, run=run, candidate=candidate)
        for candidate in patch_candidates
    ]
    downloaded = [patch for patch in patches if patch.download_status == "downloaded"]
    if not downloaded:
        _finalize_failure(
            run,
            stop_reason="patch_download_failed",
            summary={"patch_found": False, "patch_count": 0},
        )
        session.flush()
        return

    _finalize_success(
        run,
        stop_reason="patches_downloaded",
        summary={
            "patch_found": True,
            "patch_count": len(downloaded),
            "primary_patch_url": downloaded[0].candidate_url,
        },
    )
    session.flush()
