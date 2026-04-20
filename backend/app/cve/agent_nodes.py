from __future__ import annotations

from uuid import UUID
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from app.cve.agent_state import AgentState
from app.cve.reference_matcher import match_reference_url
from app.cve.search_graph_service import (
    record_candidate_artifact,
    record_search_decision,
    record_search_node,
)
from app.cve.seed_resolver import resolve_seed_references
from app.cve.runtime import plan_frontier
from app.models import CVERun


def _require_session(state: AgentState):
    session = state.get("session")
    if session is None:
        raise ValueError("Patch Agent state 缺少 session。")
    return session


def _require_run(session, *, run_id: str) -> CVERun:
    run = session.get(CVERun, UUID(run_id))
    if run is None:
        raise ValueError(f"CVE run 不存在: {run_id}")
    return run


def _build_seed_evidence(reference: str, *, existing: dict[str, object] | None = None) -> dict[str, object]:
    evidence = dict(existing or {})
    discovery_sources = list(evidence.get("discovery_sources") or [])
    existing_urls = {
        str(source.get("discovered_from_url"))
        for source in discovery_sources
        if source.get("discovered_from_url")
    }
    if reference not in existing_urls:
        discovery_sources.append(
            {
                "source_kind": "seed",
                "discovered_from_url": reference,
                "order": len(discovery_sources),
            }
        )
    evidence["source_kind"] = "seed"
    evidence["discovered_from_url"] = discovery_sources[0]["discovered_from_url"]
    evidence["discovery_sources"] = discovery_sources
    evidence["evidence_source_count"] = len(discovery_sources)
    return evidence


def _canonicalize_candidate_key(candidate_url: str) -> str:
    parsed = urlparse(candidate_url)
    normalized_query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)), doseq=True)
    return urlunparse(
        (
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            parsed.path,
            parsed.params,
            normalized_query,
            "",
        )
    )


def resolve_seeds_node(state: AgentState) -> AgentState:
    session = _require_session(state)
    run = _require_run(session, run_id=state["run_id"])
    seed_references = resolve_seed_references(session, run=run, cve_id=state["cve_id"])
    state["seed_references"] = seed_references
    return state


def build_initial_frontier_node(state: AgentState) -> AgentState:
    session = _require_session(state)
    run_id = UUID(state["run_id"])
    direct_candidates = []
    seen_candidate_keys: set[str] = set()
    persisted_candidates_by_key: dict[str, object] = {}
    direct_candidates_by_key: dict[str, dict[str, object]] = {}
    for reference in state.get("seed_references", []):
        matched_candidate = match_reference_url(reference)
        if matched_candidate is None:
            continue
        canonical_key = _canonicalize_candidate_key(matched_candidate["candidate_url"])
        if canonical_key in seen_candidate_keys:
            persisted_candidate = persisted_candidates_by_key[canonical_key]
            persisted_candidate.evidence_json = _build_seed_evidence(  # type: ignore[attr-defined]
                reference,
                existing=dict(getattr(persisted_candidate, "evidence_json", {}) or {}),
            )
            direct_candidates_by_key[canonical_key]["evidence_source_count"] = persisted_candidate.evidence_json[
                "evidence_source_count"
            ]
            continue
        seen_candidate_keys.add(canonical_key)
        candidate = record_candidate_artifact(
            session,
            run_id=run_id,
            candidate_url=matched_candidate["candidate_url"],
            candidate_type=matched_candidate["patch_type"],
            canonical_key=canonical_key,
            download_status="discovered",
            validation_status="pending",
            evidence=_build_seed_evidence(reference),
            flush=True,
        )
        persisted_candidates_by_key[canonical_key] = candidate
        candidate_record = {
            "candidate_url": candidate.candidate_url,
            "candidate_type": candidate.candidate_type,
            "canonical_key": candidate.canonical_key,
            "evidence_source_count": candidate.evidence_json["evidence_source_count"],
        }
        direct_candidates_by_key[canonical_key] = candidate_record
        direct_candidates.append(candidate_record)

    state["direct_candidates"] = direct_candidates
    state["frontier"] = [
        {
            "url": url,
            "depth": 0,
            "score": 0,
        }
        for url in plan_frontier(state.get("seed_references", []))
    ]
    return state


def fetch_next_batch_node(state: AgentState) -> AgentState:
    session = _require_session(state)
    run_id = UUID(state["run_id"])
    for frontier_item in state.get("frontier", []):
        if frontier_item.get("source_node_id"):
            continue
        parsed = urlparse(frontier_item["url"])
        node = record_search_node(
            session,
            run_id=run_id,
            url=frontier_item["url"],
            depth=int(frontier_item.get("depth", 0)),
            host=parsed.hostname or parsed.netloc or frontier_item["url"],
            page_role="frontier_page",
            fetch_status="queued",
            heuristic_features={"frontier_score": frontier_item.get("score", 0)},
            flush=True,
        )
        frontier_item["source_node_id"] = str(node.node_id)
    return state


def extract_links_and_candidates_node(state: AgentState) -> AgentState:
    return state


def agent_decide_node(state: AgentState) -> AgentState:
    session = _require_session(state)
    run_id = UUID(state["run_id"])
    direct_candidates = state.get("direct_candidates", [])
    frontier = state.get("frontier", [])
    frontier_ready_to_expand = [
        item for item in frontier if not item.get("source_node_id")
    ]
    if direct_candidates:
        decision_type = "try_candidate_download"
        selected_urls = []
        selected_candidate_keys = [
            str(candidate["canonical_key"]) for candidate in direct_candidates
        ]
        reason_summary = "seed 中已经发现直达 patch 候选，优先进入下载校验。"
    elif frontier_ready_to_expand:
        decision_type = "expand_frontier"
        selected_urls = [str(item["url"]) for item in frontier_ready_to_expand]
        selected_candidate_keys = []
        reason_summary = "当前没有直达 patch，继续扩展首轮 frontier。"
    else:
        decision_type = "stop_search"
        selected_urls = []
        selected_candidate_keys = []
        reason_summary = "既没有直达 patch，也没有可扩展 frontier。"

    persisted_decision = record_search_decision(
        session,
        run_id=run_id,
        decision_type=decision_type,
        input_payload={
            "seed_reference_count": len(state.get("seed_references", [])),
            "frontier_count": len(frontier),
            "direct_candidate_count": len(direct_candidates),
        },
        output_payload={
            "selected_urls": selected_urls,
            "selected_candidate_keys": selected_candidate_keys,
        },
        validated=True,
        flush=True,
    )
    decision_history = list(state.get("decision_history", []))
    decision_history.append(
        {
            "decision_type": persisted_decision.decision_type,
            "reason_summary": reason_summary,
            "selected_urls": selected_urls,
            "selected_candidate_keys": selected_candidate_keys,
            "validated": True,
            "rejection_reason": None,
        }
    )
    state["decision_history"] = decision_history
    state["next_action"] = decision_type
    state["stop_reason"] = None if decision_type != "stop_search" else "no_frontier_or_candidates"
    return state


def download_and_validate_node(state: AgentState) -> AgentState:
    return state


def finalize_run_node(state: AgentState) -> AgentState:
    return state
