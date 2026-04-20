import app.cve.agent_graph as agent_graph_module
from app.cve.agent_graph import build_cve_patch_graph
from app.cve.agent_state import build_initial_agent_state
from app.cve.agent_nodes import (
    agent_decide_node,
    build_initial_frontier_node,
    fetch_next_batch_node,
)
from app.models.cve import CVECandidateArtifact, CVESearchDecision, CVESearchNode
from sqlalchemy import select


def test_build_initial_agent_state_starts_with_seed_budget() -> None:
    state = build_initial_agent_state(run_id="run-1", cve_id="CVE-2024-3094")

    assert state["run_id"] == "run-1"
    assert state["cve_id"] == "CVE-2024-3094"
    assert state["budget"]["max_pages_total"] > 0
    assert state["frontier"] == []
    assert state["decision_history"] == []


def test_build_cve_patch_graph_exposes_finalize_node() -> None:
    graph = build_cve_patch_graph()

    assert "finalize_run" in graph.nodes


def test_patch_agent_graph_records_seed_candidates_frontier_and_decision(
    seeded_cve_run,
    db_session,
    monkeypatch,
) -> None:
    def _fake_resolve_seed_references(session, *, run, cve_id: str) -> list[str]:
        assert run.run_id == seeded_cve_run.run_id
        assert cve_id == "CVE-2024-3094"
        return [
            "https://example.com/fix.patch",
            "https://security-tracker.debian.org/tracker/CVE-2024-3094",
        ]

    monkeypatch.setattr(
        "app.cve.agent_nodes.resolve_seed_references",
        _fake_resolve_seed_references,
    )

    state = build_initial_agent_state(
        run_id=str(seeded_cve_run.run_id),
        cve_id=seeded_cve_run.cve_id,
    )
    state["session"] = db_session

    result = build_cve_patch_graph().invoke(state)
    db_session.commit()

    assert result["seed_references"] == [
        "https://example.com/fix.patch",
        "https://security-tracker.debian.org/tracker/CVE-2024-3094",
    ]
    assert result["frontier"][0]["url"] == "https://security-tracker.debian.org/tracker/CVE-2024-3094"
    assert result["direct_candidates"][0]["candidate_url"] == "https://example.com/fix.patch"
    assert result["decision_history"][0]["decision_type"] == "try_candidate_download"

    candidate_count = db_session.execute(
        select(CVECandidateArtifact).where(CVECandidateArtifact.run_id == seeded_cve_run.run_id)
    ).scalars().all()
    decision_count = db_session.execute(
        select(CVESearchDecision).where(CVESearchDecision.run_id == seeded_cve_run.run_id)
    ).scalars().all()
    node_count = db_session.execute(
        select(CVESearchNode).where(CVESearchNode.run_id == seeded_cve_run.run_id)
    ).scalars().all()

    assert len(candidate_count) == 1
    assert len(decision_count) == 1
    assert len(node_count) == 1


def test_build_initial_frontier_node_deduplicates_candidates_with_same_canonical_key(
    seeded_cve_run,
    db_session,
) -> None:
    state = build_initial_agent_state(
        run_id=str(seeded_cve_run.run_id),
        cve_id=seeded_cve_run.cve_id,
    )
    state["session"] = db_session
    state["seed_references"] = [
        "https://github.com/example/repo/commit/abcdef1",
        "https://github.com/example/repo/commit/abcdef1.patch",
    ]

    result = build_initial_frontier_node(state)
    db_session.commit()

    assert [candidate["candidate_url"] for candidate in result["direct_candidates"]] == [
        "https://github.com/example/repo/commit/abcdef1.patch"
    ]
    persisted_candidates = db_session.execute(
        select(CVECandidateArtifact).where(CVECandidateArtifact.run_id == seeded_cve_run.run_id)
    ).scalars().all()
    assert len(persisted_candidates) == 1
    assert persisted_candidates[0].evidence_json["evidence_source_count"] == 2
    assert [
        source["discovered_from_url"]
        for source in persisted_candidates[0].evidence_json["discovery_sources"]
    ] == [
        "https://github.com/example/repo/commit/abcdef1",
        "https://github.com/example/repo/commit/abcdef1.patch",
    ]


def test_build_initial_frontier_node_merges_equivalent_patch_urls_after_normalization(
    seeded_cve_run,
    db_session,
) -> None:
    state = build_initial_agent_state(
        run_id=str(seeded_cve_run.run_id),
        cve_id=seeded_cve_run.cve_id,
    )
    state["session"] = db_session
    state["seed_references"] = [
        "https://example.com/download?patch=1&file=fix.patch",
        "https://example.com/download?file=fix.patch&patch=1",
    ]

    result = build_initial_frontier_node(state)
    db_session.commit()

    assert [candidate["candidate_url"] for candidate in result["direct_candidates"]] == [
        "https://example.com/download?patch=1&file=fix.patch"
    ]
    persisted_candidates = db_session.execute(
        select(CVECandidateArtifact).where(CVECandidateArtifact.run_id == seeded_cve_run.run_id)
    ).scalars().all()
    assert len(persisted_candidates) == 1
    assert persisted_candidates[0].evidence_json["evidence_source_count"] == 2
    assert [
        source["discovered_from_url"]
        for source in persisted_candidates[0].evidence_json["discovery_sources"]
    ] == [
        "https://example.com/download?patch=1&file=fix.patch",
        "https://example.com/download?file=fix.patch&patch=1",
    ]


def test_agent_decide_node_appends_decision_history(seeded_cve_run, db_session) -> None:
    state = build_initial_agent_state(
        run_id=str(seeded_cve_run.run_id),
        cve_id=seeded_cve_run.cve_id,
    )
    state["session"] = db_session
    state["direct_candidates"] = [
        {
            "candidate_url": "https://example.com/fix.patch",
            "candidate_type": "patch",
            "canonical_key": "https://example.com/fix.patch",
        }
    ]

    first = agent_decide_node(state)
    first["direct_candidates"] = []
    first["frontier"] = [{"url": "https://example.com/advisory", "depth": 1, "score": 5}]
    second = agent_decide_node(first)
    db_session.commit()

    assert [item["decision_type"] for item in second["decision_history"]] == [
        "try_candidate_download",
        "expand_frontier",
    ]


def test_agent_decide_node_expands_only_frontier_items_without_source_node_id(
    seeded_cve_run, db_session
) -> None:
    state = build_initial_agent_state(
        run_id=str(seeded_cve_run.run_id),
        cve_id=seeded_cve_run.cve_id,
    )
    state["session"] = db_session
    state["frontier"] = [
        {
            "url": "https://example.com/already-materialized",
            "depth": 0,
            "score": 8,
            "source_node_id": "node-1",
        },
        {
            "url": "https://example.com/next-hop",
            "depth": 1,
            "score": 5,
        },
    ]

    result = agent_decide_node(state)
    db_session.commit()

    assert result["next_action"] == "expand_frontier"
    assert result["decision_history"][-1]["selected_urls"] == [
        "https://example.com/next-hop"
    ]


def test_fetch_next_batch_node_materializes_frontier_before_agent_decide(
    seeded_cve_run, db_session
) -> None:
    state = build_initial_agent_state(
        run_id=str(seeded_cve_run.run_id),
        cve_id=seeded_cve_run.cve_id,
    )
    state["session"] = db_session
    state["frontier"] = [
        {
            "url": "https://example.com/queued-frontier",
            "depth": 0,
            "score": 9,
        }
    ]

    fetched_state = fetch_next_batch_node(state)
    result = agent_decide_node(fetched_state)
    db_session.commit()

    assert fetched_state["frontier"][0]["source_node_id"] is not None
    assert result["next_action"] == "stop_search"
    assert result["decision_history"][-1]["selected_urls"] == []
    persisted_nodes = db_session.execute(
        select(CVESearchNode).where(CVESearchNode.run_id == seeded_cve_run.run_id)
    ).scalars().all()
    assert len(persisted_nodes) == 1


def test_patch_agent_graph_routes_expand_frontier_back_to_fetch_batch(monkeypatch) -> None:
    call_log: list[str] = []
    decide_call_count = 0

    def _resolve(state):
        call_log.append("resolve")
        return state

    def _build(state):
        call_log.append("build")
        return state

    def _fetch(state):
        call_log.append("fetch")
        state["fetch_count"] = int(state.get("fetch_count", 0)) + 1
        return state

    def _extract(state):
        call_log.append("extract")
        return state

    def _decide(state):
        nonlocal decide_call_count
        call_log.append("decide")
        decide_call_count += 1
        state["next_action"] = "expand_frontier" if decide_call_count == 1 else "stop_search"
        return state

    def _download(state):
        call_log.append("download")
        return state

    def _finalize(state):
        call_log.append("finalize")
        return state

    monkeypatch.setattr(agent_graph_module, "resolve_seeds_node", _resolve)
    monkeypatch.setattr(agent_graph_module, "build_initial_frontier_node", _build)
    monkeypatch.setattr(agent_graph_module, "fetch_next_batch_node", _fetch)
    monkeypatch.setattr(agent_graph_module, "extract_links_and_candidates_node", _extract)
    monkeypatch.setattr(agent_graph_module, "agent_decide_node", _decide)
    monkeypatch.setattr(agent_graph_module, "download_and_validate_node", _download)
    monkeypatch.setattr(agent_graph_module, "finalize_run_node", _finalize)

    agent_graph_module.build_cve_patch_graph().invoke({"run_id": "run-1", "cve_id": "CVE-2024-3094"})

    assert call_log == [
        "resolve",
        "build",
        "fetch",
        "extract",
        "decide",
        "fetch",
        "extract",
        "decide",
        "finalize",
    ]
