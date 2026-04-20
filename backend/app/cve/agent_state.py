from __future__ import annotations

from typing import Any, TypedDict

from app.cve.agent_policy import build_default_budget


class AgentFrontierItem(TypedDict, total=False):
    url: str
    depth: int
    source_node_id: str | None
    score: int


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


class AgentState(TypedDict, total=False):
    session: Any
    run_id: str
    cve_id: str
    budget: dict[str, int]
    seed_references: list[str]
    frontier: list[AgentFrontierItem]
    direct_candidates: list[AgentCandidateRecord]
    decision_history: list[AgentDecisionRecord]
    next_action: str | None
    patches: list[dict[str, object]]
    stop_reason: str | None


def build_initial_agent_state(*, run_id: str, cve_id: str) -> AgentState:
    return {
        "run_id": run_id,
        "cve_id": cve_id,
        "budget": build_default_budget(),
        "seed_references": [],
        "frontier": [],
        "direct_candidates": [],
        "decision_history": [],
        "next_action": None,
        "patches": [],
        "stop_reason": None,
    }
