from __future__ import annotations

from urllib.parse import urlparse
from uuid import UUID

from sqlalchemy import select

from app.cve.agent_policy import count_consumed_pages
from app.cve.agent_state import AgentState
from app.cve.browser.page_role_classifier import classify_page_role
from app.cve.canonical import canonicalize_candidate_url
from app.cve.search_graph_service import record_candidate_artifact
from app.cve.search_graph_service import record_search_node
from app.models.cve import CVECandidateArtifact
from app.models.cve import CVEPatchArtifact
from app.models.cve import CVESearchNode


def normalize_discovery_sources(raw_sources: object) -> list[dict[str, object]]:
    if not isinstance(raw_sources, list):
        return []
    normalized_sources: list[dict[str, object]] = []
    for index, raw_source in enumerate(raw_sources):
        if not isinstance(raw_source, dict):
            continue
        source_url = str(
            raw_source.get("source_url")
            or raw_source.get("discovered_from_url")
            or ""
        ).strip()
        if not source_url:
            continue
        normalized_sources.append(
            {
                "source_url": source_url,
                "source_host": str(
                    raw_source.get("source_host") or urlparse(source_url).hostname or source_url
                ),
                "discovery_rule": str(raw_source.get("discovery_rule") or "matcher"),
                "source_kind": str(raw_source.get("source_kind") or "page"),
                "order": index,
            }
        )
    return normalized_sources


def build_candidate_record(
    *,
    snapshot_url: str,
    candidate: dict[str, str],
    source_kind: str,
) -> dict[str, object]:
    canonical_key = canonicalize_candidate_url(candidate["candidate_url"])
    discovery_rule = (
        "bugzilla_attachment"
        if candidate.get("patch_type") == "bugzilla_attachment_patch"
        else "matcher"
    )
    source_host = urlparse(snapshot_url).hostname or snapshot_url
    return {
        "candidate_url": candidate["candidate_url"],
        "candidate_type": candidate["patch_type"],
        "patch_type": candidate["patch_type"],
        "canonical_key": canonical_key,
        "canonical_candidate_key": canonical_key,
        "discovered_from_url": snapshot_url,
        "discovered_from_host": source_host,
        "discovery_rule": discovery_rule,
        "discovery_sources": [
            {
                "source_url": snapshot_url,
                "source_host": source_host,
                "discovery_rule": discovery_rule,
                "source_kind": source_kind,
                "order": 0,
            }
        ],
        "evidence_source_count": 1,
    }


def merge_evidence(
    *,
    existing: dict[str, object] | None,
    incoming: dict[str, object],
) -> dict[str, object]:
    merged_sources = normalize_discovery_sources((existing or {}).get("discovery_sources"))
    seen_source_keys = {
        (
            str(source["source_url"]),
            str(source["discovery_rule"]),
            str(source["source_kind"]),
        )
        for source in merged_sources
    }
    for source in normalize_discovery_sources(incoming.get("discovery_sources")):
        source_key = (
            str(source["source_url"]),
            str(source["discovery_rule"]),
            str(source["source_kind"]),
        )
        if source_key in seen_source_keys:
            continue
        merged_sources.append({**source, "order": len(merged_sources)})
        seen_source_keys.add(source_key)

    primary_source = merged_sources[0] if merged_sources else {
        "source_url": str(incoming.get("discovered_from_url") or incoming["candidate_url"]),
        "source_host": str(
            incoming.get("discovered_from_host")
            or urlparse(str(incoming.get("discovered_from_url") or incoming["candidate_url"])).hostname
            or incoming["candidate_url"]
        ),
        "discovery_rule": str(incoming.get("discovery_rule") or "matcher"),
        "source_kind": "page",
        "order": 0,
    }
    return {
        "source_kind": primary_source["source_kind"],
        "discovered_from_url": primary_source["source_url"],
        "discovery_sources": merged_sources or [primary_source],
        "evidence_source_count": len(merged_sources or [primary_source]),
    }


def merge_candidate_into_state(state: AgentState, candidate_record: dict[str, object]) -> None:
    direct_candidates = list(state.get("direct_candidates", []))
    canonical_key = str(candidate_record["canonical_key"])
    for existing in direct_candidates:
        if str(existing.get("canonical_key")) != canonical_key:
            continue
        merged_evidence = merge_evidence(existing=existing, incoming=candidate_record)
        existing.update(merged_evidence)
        existing["discovered_from_url"] = merged_evidence["discovered_from_url"]
        existing["evidence_source_count"] = merged_evidence["evidence_source_count"]
        state["direct_candidates"] = direct_candidates
        return
    direct_candidates.append(candidate_record)
    state["direct_candidates"] = direct_candidates


def upsert_candidate_artifact(
    session,
    *,
    run_id: UUID,
    candidate_record: dict[str, object],
    source_node_id: UUID | None,
):
    statement = select(CVECandidateArtifact).where(
        CVECandidateArtifact.run_id == run_id,
        CVECandidateArtifact.canonical_key == str(candidate_record["canonical_key"]),
    )
    existing = session.execute(statement).scalar_one_or_none()
    merged_evidence = merge_evidence(
        existing=dict(existing.evidence_json or {}) if existing is not None else None,
        incoming=candidate_record,
    )
    if existing is None:
        return record_candidate_artifact(
            session,
            run_id=run_id,
            candidate_url=str(candidate_record["candidate_url"]),
            candidate_type=str(candidate_record["candidate_type"]),
            canonical_key=str(candidate_record["canonical_key"]),
            download_status="discovered",
            validation_status="pending",
            source_node_id=source_node_id,
            evidence=merged_evidence,
            flush=True,
        )

    existing.evidence_json = merged_evidence
    if existing.source_node_id is None and source_node_id is not None:
        existing.source_node_id = source_node_id
    session.flush()
    return existing


def upsert_page_node_state(state: AgentState, node: CVESearchNode) -> None:
    page_nodes = list(state.get("page_nodes", []))
    node_id = str(node.node_id)
    serialized = {
        "node_id": node_id,
        "url": node.url,
        "depth": node.depth,
        "host": node.host,
        "fetch_status": node.fetch_status,
        "page_role": node.page_role,
    }
    for item in page_nodes:
        if str(item.get("node_id")) == node_id:
            item.update(serialized)
            state["page_nodes"] = page_nodes
            return
    page_nodes.append(serialized)
    state["page_nodes"] = page_nodes


def ensure_search_node(session, *, run_id: UUID, frontier_item: dict[str, object]) -> CVESearchNode:
    source_node_id = frontier_item.get("source_node_id")
    if source_node_id:
        node = session.get(CVESearchNode, UUID(str(source_node_id)))
        if node is not None:
            return node
    parsed = urlparse(str(frontier_item["url"]))
    node = record_search_node(
        session,
        run_id=run_id,
        url=str(frontier_item["url"]),
        depth=int(frontier_item.get("depth", 0)),
        host=parsed.hostname or parsed.netloc or str(frontier_item["url"]),
        page_role=str(frontier_item.get("page_role") or classify_page_role(str(frontier_item["url"]))),
        fetch_status=str(frontier_item.get("fetch_status") or "queued"),
        heuristic_features={"frontier_score": frontier_item.get("score", 0)},
        flush=True,
    )
    frontier_item["source_node_id"] = str(node.node_id)
    return node


def append_decision_history(
    state: AgentState,
    *,
    decision_type: str,
    reason_summary: str,
    selected_urls: list[str],
    selected_candidate_keys: list[str],
    validated: bool,
    rejection_reason: str | None,
) -> None:
    decision_history = list(state.get("decision_history", []))
    decision_history.append(
        {
            "decision_type": decision_type,
            "reason_summary": reason_summary,
            "selected_urls": selected_urls,
            "selected_candidate_keys": selected_candidate_keys,
            "validated": validated,
            "rejection_reason": rejection_reason,
        }
    )
    state["decision_history"] = decision_history


def serialize_patch(patch: CVEPatchArtifact) -> dict[str, object]:
    return {
        "patch_id": str(patch.patch_id),
        "candidate_url": patch.candidate_url,
        "patch_type": patch.patch_type,
        "download_status": patch.download_status,
        "patch_meta_json": dict(patch.patch_meta_json or {}),
    }


def build_primary_family_summary(patches: list[CVEPatchArtifact]) -> dict[str, object]:
    if not patches:
        return {}
    grouped: dict[str, dict[str, object]] = {}
    order: list[str] = []
    for patch in patches:
        meta = dict(patch.patch_meta_json or {})
        source_url = str(meta.get("discovered_from_url") or patch.candidate_url)
        source_host = str(meta.get("discovered_from_host") or urlparse(source_url).hostname or source_url)
        family_key = f"family:{source_url}"
        if family_key not in grouped:
            order.append(family_key)
            grouped[family_key] = {
                "source_url": source_url,
                "source_host": source_host,
                "patch_count": 0,
                "downloaded_patch_count": 0,
                "related_source_hosts": [],
            }
        family = grouped[family_key]
        family["patch_count"] = int(family["patch_count"]) + 1
        if patch.download_status == "downloaded":
            family["downloaded_patch_count"] = int(family["downloaded_patch_count"]) + 1
        hosts = [
            str(source["source_host"])
            for source in normalize_discovery_sources(meta.get("discovery_sources"))
        ]
        family["related_source_hosts"] = [
            host
            for host in [*list(family["related_source_hosts"]), *hosts]
            if host
        ]

    order_index = {key: idx for idx, key in enumerate(order)}
    primary_family = sorted(
        (grouped[key] for key in order),
        key=lambda family: (
            -int(family["downloaded_patch_count"]),
            -int(family["patch_count"]),
            order_index.get(f"family:{family['source_url']}", len(order)),
        ),
    )[0]
    dedup_hosts = list(dict.fromkeys(primary_family["related_source_hosts"]))[:3]
    return {
        "primary_family_source_url": primary_family["source_url"],
        "primary_family_source_host": primary_family["source_host"],
        "primary_family_evidence_source_count": len(
            list(dict.fromkeys(primary_family["related_source_hosts"]))
        ),
        "primary_family_related_source_hosts": dedup_hosts,
    }


def count_page_roles(state: AgentState) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in list(state.get("page_role_history", [])):
        if not isinstance(item, dict):
            continue
        role = str(item.get("role") or "").strip()
        if not role:
            continue
        counts[role] = counts.get(role, 0) + 1
    return counts


def build_budget_usage_summary(state: AgentState) -> dict[str, dict[str, int]]:
    budget = dict(state.get("budget") or {})
    initial_budget = dict(state.get("initial_budget") or {})
    cross_domain_used = int(state.get("cross_domain_hops", 0) or 0)
    cross_domain_remaining = int(budget.get("max_cross_domain_expansions", 0) or 0)
    cross_domain_max = int(
        initial_budget.get(
            "max_cross_domain_expansions",
            cross_domain_remaining + cross_domain_used,
        )
        or 0
    )
    return {
        "pages": {
            "used": count_consumed_pages(state),
            "max": int(budget.get("max_pages_total", 0) or 0),
        },
        "llm_calls": {
            "used": len(list(state.get("_llm_decision_log") or [])),
            "max": int(budget.get("max_llm_calls", 0) or 0),
        },
        "cross_domain": {
            "used": cross_domain_used,
            "max": max(cross_domain_max, cross_domain_used),
        },
    }
