from __future__ import annotations

from urllib.parse import urldefrag
from urllib.parse import urlparse
from uuid import UUID

from sqlalchemy.orm import Session

from app.cve.page_analyzer import analyze_page
from app.cve.page_fetcher import fetch_page
from app.cve.patch_downloader import download_patch_candidate
from app.cve.reference_matcher import match_reference_url
from app.cve.seed_resolver import resolve_seed_references
from app.models import CVERun


_EXCEPTION_STOP_REASONS = {
    "resolve_seeds": "resolve_seeds_failed",
    "plan_frontier": "plan_frontier_failed",
    "fetch_page": "fetch_failed",
    "analyze_page": "analyze_page_failed",
    "download_patches": "download_patches_failed",
}

_MAX_FRONTIER_PAGES = 10


def plan_frontier(seed_references: list[str]) -> list[str]:
    frontier: list[str] = []
    seen_urls: set[str] = set()

    for reference in seed_references:
        normalized = _normalize_frontier_url(reference)
        if normalized is None or normalized in seen_urls:
            continue
        if match_reference_url(normalized) is not None:
            continue
        seen_urls.add(normalized)
        frontier.append(normalized)
        if len(frontier) >= _MAX_FRONTIER_PAGES:
            break

    return frontier


def _normalize_frontier_url(url: str) -> str | None:
    normalized = url.strip()
    if not normalized:
        return None
    return urldefrag(normalized).url


def _update_phase(run: CVERun, phase: str) -> None:
    run.status = "running"
    run.phase = phase


def _finalize_failure(run: CVERun, *, stop_reason: str, summary: dict[str, object]) -> None:
    run.status = "failed"
    run.stop_reason = stop_reason
    run.summary_json = summary


def _finalize_success(run: CVERun, *, stop_reason: str, summary: dict[str, object]) -> None:
    run.status = "succeeded"
    run.phase = "finalize_run"
    run.stop_reason = stop_reason
    run.summary_json = summary


def _build_failure_summary(*, error: str | None = None) -> dict[str, object]:
    summary: dict[str, object] = {
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
    try:
        _update_phase(run, "resolve_seeds")
        session.flush()
        seed_references = resolve_seed_references(session, run=run, cve_id=run.cve_id)
        if not seed_references:
            _finalize_failure(
                run,
                stop_reason="no_seed_references",
                summary=_build_failure_summary(),
            )
            return

        _update_phase(run, "plan_frontier")
        session.flush()
        frontier = plan_frontier(seed_references)
        patch_candidates = _build_direct_patch_candidates(seed_references)
        seen_candidate_urls = {candidate["candidate_url"] for candidate in patch_candidates}

        _update_phase(run, "fetch_page")
        session.flush()
        snapshots, failed_fetch_count = _fetch_frontier_snapshots(
            session, run=run, frontier=frontier
        )

        _update_phase(run, "analyze_page")
        session.flush()
        for snapshot in snapshots:
            for candidate in analyze_page(snapshot):
                enriched_candidate = _enrich_patch_candidate(snapshot, candidate)
                candidate_url = enriched_candidate["candidate_url"]
                if candidate_url in seen_candidate_urls:
                    continue
                seen_candidate_urls.add(candidate_url)
                patch_candidates.append(enriched_candidate)

        if not patch_candidates:
            if failed_fetch_count > 0 and not snapshots:
                stop_reason = "fetch_failed"
            else:
                stop_reason = "no_patch_candidates"
            _finalize_failure(
                run,
                stop_reason=stop_reason,
                summary=_build_failure_summary(),
            )
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
                summary=_build_failure_summary(),
            )
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
    except Exception as exc:
        _finalize_failure(
            run,
            stop_reason=_EXCEPTION_STOP_REASONS.get(run.phase, "run_failed"),
            summary=_build_failure_summary(error=str(exc)),
        )
    finally:
        session.flush()


def _build_direct_patch_candidates(seed_references: list[str]) -> list[dict[str, str]]:
    direct_candidates: list[dict[str, str]] = []
    seen_candidate_urls: set[str] = set()

    for reference in seed_references:
        normalized_reference = _normalize_frontier_url(reference)
        if normalized_reference is None:
            continue
        matched_candidate = match_reference_url(normalized_reference)
        if matched_candidate is None:
            continue
        normalized_candidate_url = _normalize_frontier_url(
            matched_candidate["candidate_url"]
        )
        if normalized_candidate_url is None or normalized_candidate_url in seen_candidate_urls:
            continue
        seen_candidate_urls.add(normalized_candidate_url)
        direct_candidates.append(
            _enrich_patch_candidate(
                {"url": normalized_reference},
                {
                    **matched_candidate,
                    "candidate_url": normalized_candidate_url,
                },
            )
        )

    return direct_candidates


def _fetch_frontier_snapshots(
    session: Session, *, run: CVERun, frontier: list[str]
) -> tuple[list[dict[str, str]], int]:
    snapshots: list[dict[str, str]] = []
    failed_fetch_count = 0

    for url in frontier:
        try:
            snapshots.append(fetch_page(session, run=run, url=url))
        except Exception:
            failed_fetch_count += 1

    return snapshots, failed_fetch_count


def _enrich_patch_candidate(snapshot: dict[str, str], candidate: dict[str, str]) -> dict[str, str]:
    discovered_from_url = str(snapshot.get("url") or candidate["candidate_url"])
    discovered_from_host = urlparse(discovered_from_url).hostname or discovered_from_url
    discovery_rule = (
        "bugzilla_attachment"
        if candidate.get("patch_type") == "bugzilla_attachment_patch"
        else "matcher"
    )
    return {
        **candidate,
        "discovered_from_url": discovered_from_url,
        "discovered_from_host": discovered_from_host,
        "discovery_rule": discovery_rule,
    }
