from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Artifact, CVEPatchArtifact, CVERun, SourceFetchRecord

_PHASES = [
    "resolve_seeds",
    "plan_frontier",
    "fetch_page",
    "analyze_page",
    "download_patches",
    "finalize_run",
]

_TRACE_LABELS = {
    "cve_seed_resolve": "Seed 解析",
    "cve_page_fetch": "页面抓取",
    "cve_patch_download": "Patch 下载",
}


@dataclass(frozen=True)
class _PatchEntry:
    patch: CVEPatchArtifact
    artifact: Artifact | None
    content_available: bool
    content_type: str | None
    download_url: str | None
    duplicate_count: int = 1


def get_cve_run_detail(session: Session, *, run_id: UUID) -> dict[str, object] | None:
    run = session.get(CVERun, run_id)
    if run is None:
        return None

    traces = _load_source_traces(session, run_id=run_id)
    patch_entries = _load_patch_representatives(session, run_id=run_id)
    return {
        "run_id": str(run.run_id),
        "cve_id": run.cve_id,
        "status": run.status,
        "phase": run.phase,
        "stop_reason": run.stop_reason,
        "summary": run.summary_json,
        "progress": _build_progress(run),
        "recent_progress": _build_recent_progress(traces),
        "source_traces": traces,
        "fix_families": _build_fix_families(patch_entries),
        "patches": _serialize_patches(patch_entries),
    }


def get_patch_content(
    session: Session,
    *,
    run_id: UUID,
    patch_id: UUID | None = None,
    candidate_url: str | None = None,
) -> dict[str, str] | None:
    if patch_id is not None:
        entries = _load_patch_entries(session, run_id=run_id, patch_id=patch_id)
    elif candidate_url is not None:
        entries = _select_patch_representatives(
            _load_patch_entries(session, run_id=run_id, candidate_url=candidate_url)
        )
    else:
        return None
    if not entries:
        return None

    entry = entries[0]
    if entry.artifact is None or not entry.content_available:
        return None

    return {
        "patch_id": str(entry.patch.patch_id),
        "candidate_url": entry.patch.candidate_url,
        "content": Path(entry.artifact.storage_path).read_text(encoding="utf-8"),
    }


def _build_progress(run: CVERun) -> dict[str, object]:
    if run.phase in _PHASES:
        completed_steps = _PHASES.index(run.phase) + 1
    else:
        completed_steps = 0

    if run.status == "succeeded":
        completed_steps = len(_PHASES)
    elif run.status == "failed":
        completed_steps = _failed_completed_steps(run)

    return {
        "current_phase": run.phase,
        "completed_steps": completed_steps,
        "total_steps": len(_PHASES),
        "terminal": run.status in {"succeeded", "failed"},
    }


def _build_recent_progress(
    traces: list[dict[str, object]],
) -> list[dict[str, object]]:
    recent: list[dict[str, object]] = []
    for trace in traces[-3:]:
        recent.append(
            {
                "step": trace["step"],
                "label": trace["label"],
                "status": trace["status"],
                "detail": trace["url"] or trace["source_ref"],
            }
        )
    return recent


def _load_source_traces(session: Session, *, run_id: UUID) -> list[dict[str, object]]:
    records = session.execute(
        select(SourceFetchRecord)
        .where(
            SourceFetchRecord.scene_name == "cve",
            SourceFetchRecord.source_id == run_id,
        )
        .order_by(SourceFetchRecord.created_at, SourceFetchRecord.fetch_id)
    ).scalars()

    return [_serialize_trace(record) for record in records]


def _serialize_trace(record: SourceFetchRecord) -> dict[str, object]:
    request_snapshot = dict(record.request_snapshot_json or {})
    response_meta = dict(record.response_meta_json or {})
    return {
        "fetch_id": str(record.fetch_id),
        "step": record.source_type,
        "label": _TRACE_LABELS.get(record.source_type, record.source_type),
        "status": record.status,
        "source_ref": record.source_ref,
        "url": _pick_trace_url(record),
        "request_snapshot": request_snapshot,
        "response_meta": response_meta,
        "error_message": record.error_message,
    }


def _pick_trace_url(record: SourceFetchRecord) -> str | None:
    response_meta = dict(record.response_meta_json or {})
    request_snapshot = dict(record.request_snapshot_json or {})
    return (
        response_meta.get("final_url")
        or response_meta.get("download_url")
        or request_snapshot.get("url")
        or request_snapshot.get("candidate_url")
        or record.source_ref
    )


def _load_patch_representatives(session: Session, *, run_id: UUID) -> list[_PatchEntry]:
    return _select_patch_representatives(_load_patch_entries(session, run_id=run_id))


def _serialize_patches(entries: list[_PatchEntry]) -> list[dict[str, object]]:
    patches: list[dict[str, object]] = []
    for entry in entries:
        patch = entry.patch
        patches.append(
            {
                "patch_id": str(patch.patch_id),
                "candidate_url": patch.candidate_url,
                "patch_type": patch.patch_type,
                "download_status": patch.download_status,
                "artifact_id": str(patch.artifact_id) if patch.artifact_id else None,
                "duplicate_count": entry.duplicate_count,
                "content_available": entry.content_available,
                "content_type": entry.content_type,
                "download_url": entry.download_url,
            }
        )
    return patches


def _build_fix_families(entries: list[_PatchEntry]) -> list[dict[str, object]]:
    grouped_entries: dict[str, list[_PatchEntry]] = {}
    family_metadata: dict[str, dict[str, object]] = {}
    family_order: list[str] = []

    for entry in entries:
        meta = dict(entry.patch.patch_meta_json or {})
        source_url = str(meta.get("discovered_from_url") or entry.patch.candidate_url)
        source_host = str(meta.get("discovered_from_host") or urlparse(source_url).hostname or source_url)
        discovery_rule = str(meta.get("discovery_rule") or "unknown")
        family_key = f"family:{source_url}"
        if family_key not in grouped_entries:
            family_order.append(family_key)
            grouped_entries[family_key] = []
            family_metadata[family_key] = {
                "source_url": source_url,
                "source_host": source_host,
                "discovery_rule": discovery_rule,
                "evidence_sources": _build_evidence_sources(
                    meta,
                    source_url=source_url,
                    source_host=source_host,
                    discovery_rule=discovery_rule,
                    candidate_url=entry.patch.candidate_url,
                ),
            }
        grouped_entries[family_key].append(entry)

    families: list[dict[str, object]] = []
    for family_key in family_order:
        family_entries = grouped_entries[family_key]
        representative = max(family_entries, key=_patch_entry_priority)
        patch_types = _dedupe_patch_types(family_entries)
        downloaded_patch_count = sum(
            1 for entry in family_entries if entry.patch.download_status == "downloaded"
        )
        metadata = family_metadata[family_key]
        evidence_sources = _merge_evidence_sources(
            metadata.get("evidence_sources"),
            [
                _build_evidence_sources(
                    dict(entry.patch.patch_meta_json or {}),
                    source_url=str(
                        dict(entry.patch.patch_meta_json or {}).get("discovered_from_url")
                        or entry.patch.candidate_url
                    ),
                    source_host=str(
                        dict(entry.patch.patch_meta_json or {}).get("discovered_from_host")
                        or urlparse(
                            str(
                                dict(entry.patch.patch_meta_json or {}).get("discovered_from_url")
                                or entry.patch.candidate_url
                            )
                        ).hostname
                        or entry.patch.candidate_url
                    ),
                    discovery_rule=str(
                        dict(entry.patch.patch_meta_json or {}).get("discovery_rule") or "unknown"
                    ),
                    candidate_url=entry.patch.candidate_url,
                )
                for entry in family_entries
            ],
        )
        related_source_hosts = _dedupe_strings(
            [str(source["source_host"]) for source in evidence_sources]
        )
        families.append(
            {
                "family_key": family_key,
                "title": metadata["source_host"],
                "source_url": metadata["source_url"],
                "source_host": metadata["source_host"],
                "discovery_rule": metadata["discovery_rule"],
                "patch_count": len(family_entries),
                "downloaded_patch_count": downloaded_patch_count,
                "primary_patch_id": str(representative.patch.patch_id),
                "patch_ids": [str(entry.patch.patch_id) for entry in family_entries],
                "patch_types": patch_types,
                "evidence_source_count": len(evidence_sources),
                "related_source_hosts": related_source_hosts,
                "evidence_sources": evidence_sources,
            }
        )

    return sorted(
        families,
        key=lambda family: (
            -int(family["downloaded_patch_count"]),
            -int(family["patch_count"]),
            family_order.index(str(family["family_key"])),
        ),
    )


def _build_evidence_sources(
    meta: dict[str, object],
    *,
    source_url: str,
    source_host: str,
    discovery_rule: str,
    candidate_url: str,
) -> list[dict[str, object]]:
    raw_sources = meta.get("discovery_sources")
    if isinstance(raw_sources, list) and raw_sources:
        normalized_sources: list[dict[str, object]] = []
        for index, raw_source in enumerate(raw_sources):
            if not isinstance(raw_source, dict):
                continue
            normalized_source_url = str(raw_source.get("source_url") or "").strip()
            if not normalized_source_url:
                continue
            normalized_sources.append(
                {
                    "source_url": normalized_source_url,
                    "source_host": str(
                        raw_source.get("source_host")
                        or urlparse(normalized_source_url).hostname
                        or normalized_source_url
                    ),
                    "discovery_rule": str(raw_source.get("discovery_rule") or "unknown"),
                    "source_kind": str(raw_source.get("source_kind") or "page"),
                    "order": index,
                }
            )
        if normalized_sources:
            return normalized_sources

    return [
        {
            "source_url": source_url,
            "source_host": source_host,
            "discovery_rule": discovery_rule,
            "source_kind": "candidate" if source_url == candidate_url else "page",
            "order": 0,
        }
    ]


def _merge_evidence_sources(
    primary_sources: object,
    nested_sources: list[list[dict[str, object]]],
) -> list[dict[str, object]]:
    merged_sources: list[dict[str, object]] = []
    seen_source_keys: set[tuple[str, str, str]] = set()

    for source_group in [primary_sources, *nested_sources]:
        if not isinstance(source_group, list):
            continue
        for raw_source in source_group:
            if not isinstance(raw_source, dict):
                continue
            source_url = str(raw_source.get("source_url") or "").strip()
            if not source_url:
                continue
            normalized_source = {
                "source_url": source_url,
                "source_host": str(
                    raw_source.get("source_host")
                    or urlparse(source_url).hostname
                    or source_url
                ),
                "discovery_rule": str(raw_source.get("discovery_rule") or "unknown"),
                "source_kind": str(raw_source.get("source_kind") or "candidate"),
                "order": len(merged_sources),
            }
            source_key = (
                str(normalized_source["source_url"]),
                str(normalized_source["discovery_rule"]),
                str(normalized_source["source_kind"]),
            )
            if source_key in seen_source_keys:
                continue
            seen_source_keys.add(source_key)
            merged_sources.append(normalized_source)

    return merged_sources


def _dedupe_strings(values: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        deduped.append(value)
    return deduped


_STOP_REASON_COMPLETED_STEPS = {
    "no_seed_references": 1,
    "no_patch_candidates": 4,
    "patch_download_failed": 5,
}


def _failed_completed_steps(run: CVERun) -> int:
    if run.stop_reason in _STOP_REASON_COMPLETED_STEPS:
        return _STOP_REASON_COMPLETED_STEPS[run.stop_reason]
    if run.phase in _PHASES:
        return _PHASES.index(run.phase)
    return 0


def _artifact_content_available(artifact: Artifact | None) -> bool:
    if artifact is None:
        return False
    return Path(artifact.storage_path).exists()


def _load_patch_entries(
    session: Session,
    *,
    run_id: UUID,
    patch_id: UUID | None = None,
    candidate_url: str | None = None,
) -> list[_PatchEntry]:
    statement = (
        select(CVEPatchArtifact)
        .where(CVEPatchArtifact.run_id == run_id)
        .order_by(CVEPatchArtifact.created_at, CVEPatchArtifact.patch_id)
    )
    if patch_id is not None:
        statement = statement.where(CVEPatchArtifact.patch_id == patch_id)
    if candidate_url is not None:
        statement = statement.where(CVEPatchArtifact.candidate_url == candidate_url)

    patch_rows = session.execute(statement).scalars().all()
    return [_build_patch_entry(session, patch) for patch in patch_rows]


def _build_patch_entry(session: Session, patch: CVEPatchArtifact) -> _PatchEntry:
    artifact = session.get(Artifact, patch.artifact_id) if patch.artifact_id else None
    meta = dict(patch.patch_meta_json or {})
    return _PatchEntry(
        patch=patch,
        artifact=artifact,
        content_available=_artifact_content_available(artifact),
        content_type=artifact.content_type if artifact is not None else meta.get("content_type"),
        download_url=meta.get("download_url"),
    )


def _select_patch_representatives(entries: list[_PatchEntry]) -> list[_PatchEntry]:
    representatives: dict[str, _PatchEntry] = {}
    counts_by_candidate_url: dict[str, int] = {}
    ordered_candidate_urls: list[str] = []

    for entry in entries:
        candidate_url = entry.patch.candidate_url
        counts_by_candidate_url[candidate_url] = counts_by_candidate_url.get(candidate_url, 0) + 1
        current = representatives.get(candidate_url)
        if current is None:
            ordered_candidate_urls.append(candidate_url)
            representatives[candidate_url] = entry
            continue

        if _patch_entry_priority(entry) > _patch_entry_priority(current):
            representatives[candidate_url] = entry

    return [
        _with_duplicate_count(
            representatives[candidate_url],
            duplicate_count=counts_by_candidate_url[candidate_url],
        )
        for candidate_url in ordered_candidate_urls
    ]


def _patch_entry_priority(entry: _PatchEntry) -> tuple[int, int, int, str, str]:
    patch = entry.patch
    return (
        1 if entry.content_available else 0,
        1 if patch.download_status == "downloaded" else 0,
        1 if entry.artifact is not None else 0,
        entry.content_type or "",
        str(patch.patch_id),
    )


def _dedupe_patch_types(entries: list[_PatchEntry]) -> list[str]:
    patch_types: list[str] = []
    seen_patch_types: set[str] = set()
    for entry in entries:
        patch_type = entry.patch.patch_type
        if patch_type in seen_patch_types:
            continue
        seen_patch_types.add(patch_type)
        patch_types.append(patch_type)
    return patch_types


def _with_duplicate_count(entry: _PatchEntry, *, duplicate_count: int) -> _PatchEntry:
    return _PatchEntry(
        patch=entry.patch,
        artifact=entry.artifact,
        content_available=entry.content_available,
        content_type=entry.content_type,
        download_url=entry.download_url,
        duplicate_count=duplicate_count,
    )
