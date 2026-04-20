from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Artifact, CVEPatchArtifact, CVERun, SourceFetchRecord, TaskJob
from app.models.cve import CVESearchDecision, CVESearchEdge, CVESearchNode

_LEGACY_PHASES = [
    "resolve_seeds",
    "plan_frontier",
    "fetch_page",
    "analyze_page",
    "download_patches",
    "finalize_run",
]

_AGENT_PHASES = [
    "resolve_seeds",
    "build_initial_frontier",
    "fetch_next_batch",
    "extract_links_and_candidates",
    "agent_decide",
    "download_and_validate",
    "finalize_run",
]

_AGENT_ONLY_PHASES = {
    "build_initial_frontier",
    "fetch_next_batch",
    "extract_links_and_candidates",
    "agent_decide",
    "download_and_validate",
}

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
    patches = _serialize_patches(patch_entries)
    search_nodes = _load_search_nodes(session, run_id=run_id)
    search_edges = _load_search_edges(session, run_id=run_id)
    decision_history = _load_decision_history(session, run_id=run_id)
    job = session.get(TaskJob, run.job_id)
    return {
        "run_id": str(run.run_id),
        "cve_id": run.cve_id,
        "status": run.status,
        "phase": run.phase,
        "stop_reason": run.stop_reason,
        "summary": run.summary_json,
        "progress": _build_progress(
            run,
            traces=traces,
            patches=patches,
            job_type=job.job_type if job is not None else None,
            search_nodes=search_nodes,
            search_edges=search_edges,
            decision_history=decision_history,
        ),
        "recent_progress": _build_recent_progress(traces),
        "source_traces": traces,
        "search_graph": {
            "nodes": search_nodes,
            "edges": search_edges,
        },
        "frontier_status": _build_frontier_status(search_nodes),
        "decision_history": decision_history,
        "fix_families": _build_fix_families(patch_entries),
        "patches": patches,
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


def _build_progress(
    run: CVERun,
    *,
    traces: list[dict[str, object]],
    patches: list[dict[str, object]],
    job_type: str | None,
    search_nodes: list[dict[str, object]],
    search_edges: list[dict[str, object]],
    decision_history: list[dict[str, object]],
) -> dict[str, object]:
    phase_sequence = _resolve_phase_sequence(
        run,
        job_type=job_type,
        search_nodes=search_nodes,
        search_edges=search_edges,
        decision_history=decision_history,
    )
    if run.phase in phase_sequence:
        completed_steps = phase_sequence.index(run.phase) + 1
    else:
        completed_steps = 0

    if run.status == "succeeded":
        completed_steps = len(phase_sequence)
    elif run.status == "failed":
        completed_steps = _failed_completed_steps(run, phase_sequence=phase_sequence)

    downloaded_patch_count = sum(
        1 for patch in patches if patch.get("download_status") == "downloaded"
    )
    failed_trace_count = sum(1 for trace in traces if trace.get("status") == "failed")
    latest_signal = _build_latest_signal(
        run,
        traces=traces,
        downloaded_patch_count=downloaded_patch_count,
    )
    last_meaningful_update_at = _pick_last_meaningful_update_at(
        run,
        traces=traces,
    )
    return {
        "current_phase": run.phase,
        "completed_steps": completed_steps,
        "total_steps": len(phase_sequence),
        "terminal": run.status in {"succeeded", "failed"},
        "percent": _estimate_progress_percent(
            run,
            completed_steps=completed_steps,
            trace_count=len(traces),
            downloaded_patch_count=downloaded_patch_count,
        ),
        "status_label": _build_status_label(run),
        "latest_signal": latest_signal,
        "last_updated_at": run.updated_at.isoformat(),
        "last_meaningful_update_at": (
            last_meaningful_update_at.isoformat()
            if last_meaningful_update_at is not None
            else None
        ),
        "visited_trace_count": len(traces),
        "downloaded_patch_count": downloaded_patch_count,
        "failed_trace_count": failed_trace_count,
        "active_url": _pick_active_url(run, traces=traces, patches=patches),
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
                "error_message": trace["error_message"],
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
        "created_at": record.created_at.isoformat(),
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


def _load_search_nodes(session: Session, *, run_id: UUID) -> list[dict[str, object]]:
    nodes = session.execute(
        select(CVESearchNode)
        .where(CVESearchNode.run_id == run_id)
        .order_by(CVESearchNode.depth, CVESearchNode.created_at, CVESearchNode.node_id)
    ).scalars()
    return [
        {
            "node_id": str(node.node_id),
            "url": node.url,
            "depth": node.depth,
            "host": node.host,
            "page_role": node.page_role,
            "fetch_status": node.fetch_status,
        }
        for node in nodes
    ]


def _load_search_edges(session: Session, *, run_id: UUID) -> list[dict[str, object]]:
    edges = session.execute(
        select(CVESearchEdge)
        .where(CVESearchEdge.run_id == run_id)
        .order_by(CVESearchEdge.created_at, CVESearchEdge.edge_id)
    ).scalars()
    return [
        {
            "from_node_id": str(edge.from_node_id),
            "to_node_id": str(edge.to_node_id),
            "edge_type": edge.edge_type,
            "selected_by": edge.selected_by,
        }
        for edge in edges
    ]


def _load_decision_history(session: Session, *, run_id: UUID) -> list[dict[str, object]]:
    decisions = session.execute(
        select(CVESearchDecision)
        .where(CVESearchDecision.run_id == run_id)
        .order_by(CVESearchDecision.created_at, CVESearchDecision.decision_id)
    ).scalars()
    return [
        {
            "decision_type": decision.decision_type,
            "validated": decision.validated,
            "model_name": decision.model_name,
            "node_id": str(decision.node_id) if decision.node_id else None,
        }
        for decision in decisions
    ]


def _build_frontier_status(search_nodes: list[dict[str, object]]) -> dict[str, int]:
    if not search_nodes:
        return {
            "total_nodes": 0,
            "max_depth": 0,
            "active_node_count": 0,
        }
    return {
        "total_nodes": len(search_nodes),
        "max_depth": max(int(node["depth"]) for node in search_nodes),
        "active_node_count": sum(
            1 for node in search_nodes if str(node["fetch_status"]) != "fetched"
        ),
    }


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

_PHASE_PROGRESS_PERCENT = {
    "resolve_seeds": 12,
    "plan_frontier": 24,
    "fetch_page": 40,
    "analyze_page": 56,
    "download_patches": 76,
    "build_initial_frontier": 24,
    "fetch_next_batch": 40,
    "extract_links_and_candidates": 56,
    "agent_decide": 72,
    "download_and_validate": 84,
    "finalize_run": 92,
}


def _failed_completed_steps(run: CVERun, *, phase_sequence: list[str]) -> int:
    if run.stop_reason in _STOP_REASON_COMPLETED_STEPS:
        return _STOP_REASON_COMPLETED_STEPS[run.stop_reason]
    if run.phase in phase_sequence:
        return phase_sequence.index(run.phase)
    return 0


def _resolve_phase_sequence(
    run: CVERun,
    *,
    job_type: str | None,
    search_nodes: list[dict[str, object]],
    search_edges: list[dict[str, object]],
    decision_history: list[dict[str, object]],
) -> list[str]:
    if _is_agent_run(
        run,
        job_type=job_type,
        search_nodes=search_nodes,
        search_edges=search_edges,
        decision_history=decision_history,
    ):
        return _AGENT_PHASES
    return _LEGACY_PHASES


def _is_agent_run(
    run: CVERun,
    *,
    job_type: str | None,
    search_nodes: list[dict[str, object]],
    search_edges: list[dict[str, object]],
    decision_history: list[dict[str, object]],
) -> bool:
    summary = dict(run.summary_json or {})
    runtime_kind = str(summary.get("runtime_kind") or "").strip().lower()
    if runtime_kind in {"patch_agent", "patch_agent_graph"}:
        return True
    if job_type == "cve_patch_agent_graph":
        return True
    if run.phase in _AGENT_ONLY_PHASES:
        return True
    return bool(search_nodes or search_edges or decision_history)


def _estimate_progress_percent(
    run: CVERun,
    *,
    completed_steps: int,
    trace_count: int,
    downloaded_patch_count: int,
) -> int:
    if run.status == "succeeded":
        return 100
    if run.status == "failed":
        return _PHASE_PROGRESS_PERCENT.get(run.phase, max(completed_steps * 16, 12))
    if run.status == "queued":
        return 6

    base_percent = _PHASE_PROGRESS_PERCENT.get(run.phase, max(completed_steps * 14, 10))
    extra_percent = min(trace_count * 3, 12) + min(downloaded_patch_count * 4, 8)
    percent_ceiling = 98 if run.phase == "finalize_run" else 96
    return min(base_percent + extra_percent, percent_ceiling)


def _build_status_label(run: CVERun) -> str:
    if run.status == "succeeded":
        return "已完成"
    if run.status == "failed":
        return "已失败"
    if run.status == "queued":
        return "等待执行"
    if run.phase == "agent_decide":
        return "Agent 决策中"
    if run.phase == "build_initial_frontier":
        return "构建搜索前沿"
    if run.phase == "fetch_next_batch":
        return "抓取前沿页面"
    if run.phase == "extract_links_and_candidates":
        return "提取链接与候选"
    if run.phase == "download_and_validate":
        return "候选下载校验中"
    if run.phase == "download_patches":
        return "补丁下载中"
    if run.phase == "finalize_run":
        return "结果归并中"
    return "图谱扩展中"


def _build_latest_signal(
    run: CVERun,
    *,
    traces: list[dict[str, object]],
    downloaded_patch_count: int,
) -> str:
    if run.status == "succeeded":
        if downloaded_patch_count > 0:
            return "已完成补丁下载，结果可以开始复查。"
        return "运行已完成，结果可以开始复查。"
    if run.status == "failed":
        return f"运行在{_phase_label(run.phase)}阶段失败。"
    if traces:
        latest_trace = traces[-1]
        latest_url = latest_trace.get("url") or latest_trace.get("source_ref")
        latest_status = latest_trace.get("status")
        latest_label = str(latest_trace.get("label") or latest_trace.get("step") or "关键步骤")
        if latest_status == "failed":
            return f"最近{latest_label}失败，建议先检查最新抓取错误。"
        if latest_url:
            return f"最近{latest_label}已推进到 {latest_url}。"
        return f"最近{latest_label}仍在持续推进。"
    return f"当前正在{_phase_label(run.phase)}。"


def _pick_last_meaningful_update_at(
    run: CVERun,
    *,
    traces: list[dict[str, object]],
) -> datetime | None:
    if traces:
        trace_created_at = traces[-1].get("created_at")
        if isinstance(trace_created_at, str) and trace_created_at:
            return datetime.fromisoformat(trace_created_at)
    return run.updated_at


def _pick_active_url(
    run: CVERun,
    *,
    traces: list[dict[str, object]],
    patches: list[dict[str, object]],
) -> str | None:
    if run.status == "succeeded":
        for patch in patches:
            download_url = patch.get("download_url")
            if isinstance(download_url, str) and download_url:
                return download_url
    for trace in reversed(traces):
        trace_url = trace.get("url") or trace.get("source_ref")
        if isinstance(trace_url, str) and trace_url:
            return trace_url
    summary = dict(run.summary_json or {})
    primary_patch_url = summary.get("primary_patch_url")
    if isinstance(primary_patch_url, str) and primary_patch_url:
        return primary_patch_url
    return None


def _phase_label(phase: str) -> str:
    return {
        "resolve_seeds": "解析参考链接",
        "plan_frontier": "规划探索页面",
        "fetch_page": "抓取页面",
        "analyze_page": "分析页面",
        "build_initial_frontier": "构建搜索前沿",
        "fetch_next_batch": "抓取前沿页面",
        "extract_links_and_candidates": "提取链接与候选",
        "agent_decide": "Agent 决策",
        "download_and_validate": "下载并校验候选",
        "download_patches": "下载补丁",
        "finalize_run": "收敛结果",
    }.get(phase, phase)


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
