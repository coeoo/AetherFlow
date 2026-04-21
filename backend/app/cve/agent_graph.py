from __future__ import annotations

from langgraph.graph import END, START, StateGraph

from app.cve.agent_nodes import (
    agent_decide_node,
    build_initial_frontier_node,
    download_and_validate_node,
    extract_links_and_candidates_node,
    fetch_next_batch_node,
    finalize_run_node,
    resolve_seeds_node,
)
from app.cve.agent_state import AgentState


def _route_after_decide(state: AgentState) -> str:
    next_action = state.get("next_action")
    if next_action == "expand_frontier":
        return "fetch_next_batch"
    if next_action == "try_candidate_download":
        return "download_and_validate"
    return "finalize_run"


def _route_after_download(state: AgentState) -> str:
    if state.get("next_action") == "fetch_next_batch":
        return "fetch_next_batch"
    return "finalize_run"


def build_cve_patch_graph():
    graph = StateGraph(AgentState)
    graph.add_node("resolve_seeds", resolve_seeds_node)
    graph.add_node("build_initial_frontier", build_initial_frontier_node)
    graph.add_node("fetch_next_batch", fetch_next_batch_node)
    graph.add_node("extract_links_and_candidates", extract_links_and_candidates_node)
    graph.add_node("agent_decide", agent_decide_node)
    graph.add_node("download_and_validate", download_and_validate_node)
    graph.add_node("finalize_run", finalize_run_node)

    graph.add_edge(START, "resolve_seeds")
    graph.add_edge("resolve_seeds", "build_initial_frontier")
    graph.add_edge("build_initial_frontier", "fetch_next_batch")
    graph.add_edge("fetch_next_batch", "extract_links_and_candidates")
    graph.add_edge("extract_links_and_candidates", "agent_decide")
    graph.add_conditional_edges(
        "agent_decide",
        _route_after_decide,
        {
            "fetch_next_batch": "fetch_next_batch",
            "download_and_validate": "download_and_validate",
            "finalize_run": "finalize_run",
        },
    )
    graph.add_conditional_edges(
        "download_and_validate",
        _route_after_download,
        {
            "fetch_next_batch": "fetch_next_batch",
            "finalize_run": "finalize_run",
        },
    )
    graph.add_edge("finalize_run", END)

    return graph.compile()
