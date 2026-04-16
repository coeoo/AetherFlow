from __future__ import annotations

import re
from urllib.parse import urldefrag
from urllib.parse import urlparse
from urllib.parse import urlunparse
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
_GITHUB_COMMIT_OR_PULL_RE = re.compile(
    r"^/[^/]+/[^/]+/(?:commit/[0-9a-f]{7,40}|pull/\d+)$",
    re.IGNORECASE,
)
_GITLAB_COMMIT_OR_MR_RE = re.compile(
    r"^/(?:[^/]+/)+[^/]+/-/(?:commit/[0-9a-f]{7,40}|merge_requests/\d+)$",
    re.IGNORECASE,
)


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
        candidates_by_key = {
            str(candidate["canonical_candidate_key"]): candidate for candidate in patch_candidates
        }

        _update_phase(run, "fetch_page")
        session.flush()
        snapshots, failed_fetch_count = _fetch_frontier_snapshots(
            session, run=run, frontier=frontier
        )

        _update_phase(run, "analyze_page")
        session.flush()
        for snapshot in snapshots:
            for candidate in analyze_page(snapshot):
                enriched_candidate = _enrich_patch_candidate(
                    snapshot,
                    candidate,
                    source_kind="page",
                )
                _merge_or_append_candidate(
                    patch_candidates,
                    candidates_by_key=candidates_by_key,
                    candidate=enriched_candidate,
                )

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
                **_build_primary_family_summary(patches),
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


def _build_direct_patch_candidates(seed_references: list[str]) -> list[dict[str, object]]:
    direct_candidates: list[dict[str, object]] = []
    seen_candidate_keys: set[str] = set()

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
        if normalized_candidate_url is None:
            continue
        enriched_candidate = _enrich_patch_candidate(
            {"url": normalized_reference},
            {
                **matched_candidate,
                "candidate_url": normalized_candidate_url,
            },
            source_kind="seed",
        )
        candidate_key = str(enriched_candidate["canonical_candidate_key"])
        if candidate_key in seen_candidate_keys:
            continue
        seen_candidate_keys.add(candidate_key)
        direct_candidates.append(enriched_candidate)

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


def _enrich_patch_candidate(
    snapshot: dict[str, str],
    candidate: dict[str, str],
    *,
    source_kind: str,
) -> dict[str, object]:
    discovered_from_url = str(snapshot.get("url") or candidate["candidate_url"])
    discovered_from_host = urlparse(discovered_from_url).hostname or discovered_from_url
    discovery_rule = (
        "bugzilla_attachment"
        if candidate.get("patch_type") == "bugzilla_attachment_patch"
        else "matcher"
    )
    canonical_candidate_key = _build_canonical_candidate_key(candidate["candidate_url"])
    discovery_source = {
        "source_url": discovered_from_url,
        "source_host": discovered_from_host,
        "discovery_rule": discovery_rule,
        "source_kind": source_kind,
        "order": 0,
    }
    return {
        **candidate,
        "discovered_from_url": discovered_from_url,
        "discovered_from_host": discovered_from_host,
        "discovery_rule": discovery_rule,
        "canonical_candidate_key": canonical_candidate_key,
        "discovery_sources": [discovery_source],
        "evidence_source_count": 1,
    }


def _merge_or_append_candidate(
    patch_candidates: list[dict[str, object]],
    *,
    candidates_by_key: dict[str, dict[str, object]],
    candidate: dict[str, object],
) -> None:
    candidate_key = str(candidate["canonical_candidate_key"])
    existing_candidate = candidates_by_key.get(candidate_key)
    if existing_candidate is None:
        candidates_by_key[candidate_key] = candidate
        patch_candidates.append(candidate)
        return

    existing_sources = _normalize_discovery_sources(existing_candidate.get("discovery_sources"))
    merged_sources = list(existing_sources)
    seen_source_keys = {
        (
            str(source["source_url"]),
            str(source["discovery_rule"]),
            str(source["source_kind"]),
        )
        for source in existing_sources
    }
    for incoming_source in _normalize_discovery_sources(candidate.get("discovery_sources")):
        source_key = (
            str(incoming_source["source_url"]),
            str(incoming_source["discovery_rule"]),
            str(incoming_source["source_kind"]),
        )
        if source_key in seen_source_keys:
            continue
        merged_sources.append(
            {
                **incoming_source,
                "order": len(merged_sources),
            }
        )
        seen_source_keys.add(source_key)

    primary_source = merged_sources[0]
    existing_candidate["discovered_from_url"] = primary_source["source_url"]
    existing_candidate["discovered_from_host"] = primary_source["source_host"]
    existing_candidate["discovery_rule"] = primary_source["discovery_rule"]
    existing_candidate["discovery_sources"] = merged_sources
    existing_candidate["evidence_source_count"] = len(merged_sources)


def _normalize_discovery_sources(raw_sources: object) -> list[dict[str, object]]:
    if not isinstance(raw_sources, list):
        return []
    normalized_sources: list[dict[str, object]] = []
    for index, raw_source in enumerate(raw_sources):
        if not isinstance(raw_source, dict):
            continue
        source_url = str(raw_source.get("source_url") or "").strip()
        if not source_url:
            continue
        source_host = str(
            raw_source.get("source_host") or urlparse(source_url).hostname or source_url
        )
        normalized_sources.append(
            {
                "source_url": source_url,
                "source_host": source_host,
                "discovery_rule": str(raw_source.get("discovery_rule") or "unknown"),
                "source_kind": str(raw_source.get("source_kind") or "page"),
                "order": index,
            }
        )
    return normalized_sources


def _build_canonical_candidate_key(candidate_url: str) -> str:
    normalized_candidate_url = _normalize_frontier_url(candidate_url) or candidate_url.strip()
    parsed = urlparse(normalized_candidate_url)
    lower_path = parsed.path.lower()
    if lower_path.endswith((".patch", ".diff")):
        if parsed.netloc == "github.com":
            base_path = parsed.path.rsplit(".", 1)[0]
            if _GITHUB_COMMIT_OR_PULL_RE.match(base_path):
                return urlunparse((parsed.scheme, parsed.netloc, base_path, "", "", ""))
        if _GITLAB_COMMIT_OR_MR_RE.match(parsed.path.rsplit(".", 1)[0]):
            base_path = parsed.path.rsplit(".", 1)[0]
            return urlunparse((parsed.scheme, parsed.netloc, base_path, "", "", ""))
    return normalized_candidate_url


def _build_primary_family_summary(patches: list[object]) -> dict[str, object]:
    grouped_families: dict[str, dict[str, object]] = {}
    family_order: list[str] = []

    for patch in patches:
        meta = dict(getattr(patch, "patch_meta_json", {}) or {})
        candidate_url = str(getattr(patch, "candidate_url"))
        source_url = str(meta.get("discovered_from_url") or candidate_url)
        source_host = str(meta.get("discovered_from_host") or urlparse(source_url).hostname or source_url)
        family_key = f"family:{source_url}"
        if family_key not in grouped_families:
            family_order.append(family_key)
            grouped_families[family_key] = {
                "source_url": source_url,
                "source_host": source_host,
                "patch_count": 0,
                "downloaded_patch_count": 0,
                "related_source_hosts": [],
            }
        family = grouped_families[family_key]
        family["patch_count"] = int(family["patch_count"]) + 1
        if str(getattr(patch, "download_status")) == "downloaded":
            family["downloaded_patch_count"] = int(family["downloaded_patch_count"]) + 1
        family["related_source_hosts"] = _dedupe_strings(
            [
                *list(family["related_source_hosts"]),
                *[
                    str(source["source_host"])
                    for source in _build_summary_evidence_sources(
                        meta,
                        candidate_url=candidate_url,
                    )
                ],
            ]
        )

    if not family_order:
        return {}

    primary_family = sorted(
        (grouped_families[family_key] for family_key in family_order),
        key=lambda family: (
            -int(family["downloaded_patch_count"]),
            -int(family["patch_count"]),
            family_order.index(f"family:{family['source_url']}"),
        ),
    )[0]

    related_source_hosts = list(primary_family["related_source_hosts"])[:3]
    return {
        "primary_family_source_url": primary_family["source_url"],
        "primary_family_source_host": primary_family["source_host"],
        "primary_family_evidence_source_count": len(primary_family["related_source_hosts"]),
        "primary_family_related_source_hosts": related_source_hosts,
    }


def _build_summary_evidence_sources(
    meta: dict[str, object],
    *,
    candidate_url: str,
) -> list[dict[str, str]]:
    raw_sources = meta.get("discovery_sources")
    if isinstance(raw_sources, list) and raw_sources:
        normalized_sources: list[dict[str, str]] = []
        for raw_source in raw_sources:
            if not isinstance(raw_source, dict):
                continue
            source_url = str(raw_source.get("source_url") or "").strip()
            if not source_url:
                continue
            normalized_sources.append(
                {
                    "source_url": source_url,
                    "source_host": str(
                        raw_source.get("source_host")
                        or urlparse(source_url).hostname
                        or source_url
                    ),
                }
            )
        if normalized_sources:
            return normalized_sources

    fallback_source_url = str(meta.get("discovered_from_url") or candidate_url)
    return [
        {
            "source_url": fallback_source_url,
            "source_host": str(
                meta.get("discovered_from_host")
                or urlparse(fallback_source_url).hostname
                or fallback_source_url
            ),
        }
    ]


def _dedupe_strings(values: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped
