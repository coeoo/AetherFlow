from __future__ import annotations

from typing import Any, TypedDict

from app.cve.agent_policy import build_default_budget
from app.cve.candidate_generator import PatchCandidate
from app.cve.patch_evidence import PatchEvidence
from app.cve.seed_resolver import SeedReference


class AgentFrontierItem(TypedDict, total=False):
    url: str
    depth: int
    source_node_id: str | None
    score: int
    expanded: bool
    fetch_status: str
    anchor_text: str
    link_context: str
    page_role: str
    chain_id: str | None


class AgentDecisionRecord(TypedDict, total=False):
    decision_type: str
    reason_summary: str
    selected_urls: list[str]
    selected_candidate_keys: list[str]
    validated: bool
    rejection_reason: str | None


class AgentCandidateRecord(TypedDict, total=False):
    candidate_url: str
    candidate_type: str
    canonical_key: str
    discovered_from_url: str
    discovered_from_host: str
    discovery_rule: str
    evidence_source_count: int
    discovery_sources: list[dict[str, object]]


class AgentPageNodeRecord(TypedDict, total=False):
    node_id: str
    url: str
    depth: int
    host: str
    fetch_status: str
    page_role: str


class AgentPageObservation(TypedDict, total=False):
    source_node_id: str
    url: str
    depth: int
    fetch_status: str
    final_url: str
    content_type: str
    content: str
    error: str | None
    extracted_links: list[str]
    frontier_candidates: list[dict[str, object]]
    candidates: list[dict[str, str]]
    extracted: bool


class AgentState(TypedDict, total=False):
    session: Any
    _browser_bridge: Any
    run_id: str
    cve_id: str
    budget: dict[str, int]
    initial_budget: dict[str, int]
    seed_references: list[SeedReference]
    patch_evidence: list[PatchEvidence]
    patch_candidates: list[PatchCandidate]
    frontier: list[AgentFrontierItem]
    direct_candidates: list[AgentCandidateRecord]
    page_nodes: list[AgentPageNodeRecord]
    page_observations: dict[str, AgentPageObservation]
    visited_urls: list[str]
    current_page_url: str | None
    current_node_id: str | None
    selected_frontier_urls: list[str]
    selected_candidate_keys: list[str]
    iteration_count: int
    decision_history: list[AgentDecisionRecord]
    navigation_chains: list[dict[str, object]]
    current_chain_id: str | None
    page_role_history: list[dict[str, str]]
    cross_domain_hops: int
    browser_snapshots: dict[str, dict]
    next_action: str | None
    patches: list[dict[str, object]]
    stop_reason: str | None
    _llm_decision_log: list[dict[str, object]]


def build_initial_agent_state(*, run_id: str, cve_id: str) -> AgentState:
    budget = build_default_budget()
    return {
        "run_id": run_id,
        "cve_id": cve_id,
        "budget": dict(budget),
        "initial_budget": dict(budget),
        "seed_references": [],
        "patch_evidence": [],
        "patch_candidates": [],
        "frontier": [],
        "direct_candidates": [],
        "page_nodes": [],
        "page_observations": {},
        "visited_urls": [],
        "current_page_url": None,
        "current_node_id": None,
        "selected_frontier_urls": [],
        "selected_candidate_keys": [],
        "iteration_count": 0,
        "decision_history": [],
        "navigation_chains": [],
        "current_chain_id": None,
        "page_role_history": [],
        "cross_domain_hops": 0,
        "browser_snapshots": {},
        "next_action": None,
        "patches": [],
        "stop_reason": None,
        "_llm_decision_log": [],
    }
