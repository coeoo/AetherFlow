from __future__ import annotations

import json
from typing import Mapping
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.cve import (
    CVECandidateArtifact,
    CVESearchDecision,
    CVESearchEdge,
    CVESearchNode,
)


def _normalize_json_payload(
    payload: Mapping[str, object] | None,
    *,
    field_name: str,
) -> dict[str, object]:
    normalized_payload = dict(payload or {})
    try:
        json.dumps(normalized_payload)
    except (TypeError, ValueError) as exc:
        raise TypeError(f"{field_name} 包含不可 JSON 序列化的数据: {exc}") from exc
    return normalized_payload


def _assert_node_belongs_to_run(
    session: Session,
    *,
    run_id: UUID,
    node_id: UUID,
    field_name: str,
) -> None:
    with session.no_autoflush:
        node = session.get(CVESearchNode, node_id)
    if node is None:
        raise ValueError(f"{field_name} 指向的搜索节点不存在: {node_id}")
    if node.run_id != run_id:
        raise ValueError(
            f"{field_name}={node_id} 不属于 run_id={run_id}，实际 run_id={node.run_id}"
        )


def _flush_if_requested(session: Session, *, flush: bool) -> None:
    if flush:
        session.flush()


def record_search_node(
    session: Session,
    *,
    run_id: UUID,
    url: str,
    depth: int,
    host: str,
    page_role: str,
    fetch_status: str,
    content_excerpt: str | None = None,
    heuristic_features: Mapping[str, object] | None = None,
    flush: bool = False,
) -> CVESearchNode:
    node = CVESearchNode(
        run_id=run_id,
        url=url,
        depth=depth,
        host=host,
        page_role=page_role,
        fetch_status=fetch_status,
        content_excerpt=content_excerpt,
        heuristic_features_json=_normalize_json_payload(
            heuristic_features,
            field_name="heuristic_features",
        ),
    )
    session.add(node)
    _flush_if_requested(session, flush=flush)
    return node


def record_search_edge(
    session: Session,
    *,
    run_id: UUID,
    from_node_id: UUID,
    to_node_id: UUID,
    edge_type: str,
    selected_by: str,
    anchor_text: str | None = None,
    link_context: str | None = None,
    flush: bool = False,
) -> CVESearchEdge:
    _assert_node_belongs_to_run(
        session,
        run_id=run_id,
        node_id=from_node_id,
        field_name="from_node_id",
    )
    _assert_node_belongs_to_run(
        session,
        run_id=run_id,
        node_id=to_node_id,
        field_name="to_node_id",
    )
    edge = CVESearchEdge(
        run_id=run_id,
        from_node_id=from_node_id,
        to_node_id=to_node_id,
        edge_type=edge_type,
        anchor_text=anchor_text,
        link_context=link_context,
        selected_by=selected_by,
    )
    session.add(edge)
    _flush_if_requested(session, flush=flush)
    return edge


def record_search_decision(
    session: Session,
    *,
    run_id: UUID,
    decision_type: str,
    input_payload: Mapping[str, object] | None = None,
    output_payload: Mapping[str, object] | None = None,
    validated: bool = False,
    node_id: UUID | None = None,
    model_name: str | None = None,
    rejection_reason: str | None = None,
    flush: bool = False,
) -> CVESearchDecision:
    if node_id is not None:
        _assert_node_belongs_to_run(
            session,
            run_id=run_id,
            node_id=node_id,
            field_name="node_id",
        )
    decision = CVESearchDecision(
        run_id=run_id,
        node_id=node_id,
        decision_type=decision_type,
        model_name=model_name,
        input_json=_normalize_json_payload(input_payload, field_name="input_payload"),
        output_json=_normalize_json_payload(output_payload, field_name="output_payload"),
        validated=validated,
        rejection_reason=rejection_reason,
    )
    session.add(decision)
    _flush_if_requested(session, flush=flush)
    return decision


def record_candidate_artifact(
    session: Session,
    *,
    run_id: UUID,
    candidate_url: str,
    candidate_type: str,
    canonical_key: str,
    download_status: str,
    validation_status: str,
    source_node_id: UUID | None = None,
    artifact_id: UUID | None = None,
    evidence: Mapping[str, object] | None = None,
    flush: bool = False,
) -> CVECandidateArtifact:
    if source_node_id is not None:
        _assert_node_belongs_to_run(
            session,
            run_id=run_id,
            node_id=source_node_id,
            field_name="source_node_id",
        )
    candidate = CVECandidateArtifact(
        run_id=run_id,
        source_node_id=source_node_id,
        candidate_url=candidate_url,
        candidate_type=candidate_type,
        canonical_key=canonical_key,
        download_status=download_status,
        validation_status=validation_status,
        artifact_id=artifact_id,
        evidence_json=_normalize_json_payload(evidence, field_name="evidence"),
    )
    session.add(candidate)
    _flush_if_requested(session, flush=flush)
    return candidate
