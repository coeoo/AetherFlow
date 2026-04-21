import uuid
from types import SimpleNamespace

from dataclasses import asdict

import app.cve.agent_graph as agent_graph_module
from app.cve.agent_graph import build_cve_patch_graph
from app.cve.agent_state import build_initial_agent_state
from app.cve.agent_nodes import (
    _filter_frontier_links,
    _select_fallback_frontier_urls,
    agent_decide_node,
    build_initial_frontier_node,
    download_and_validate_node,
    extract_links_and_candidates_node,
    finalize_run_node,
    fetch_next_batch_node,
)
from app.cve.browser.base import BrowserPageSnapshot, PageLink
from app.models import CVERun
from app.models.cve import (
    CVECandidateArtifact,
    CVEPatchArtifact,
    CVESearchDecision,
    CVESearchNode,
)
from sqlalchemy import select


def _make_snapshot(
    url: str,
    *,
    links: list[PageLink] | None = None,
    page_role_hint: str = "frontier_page",
    title: str = "fake",
) -> BrowserPageSnapshot:
    return BrowserPageSnapshot(
        url=url,
        final_url=url,
        status_code=200,
        title=title,
        raw_html="<html><body>fake</body></html>",
        accessibility_tree="heading 'fake'",
        markdown_content="fake",
        links=list(links or []),
        page_role_hint=page_role_hint,
        fetch_duration_ms=100,
    )


class _FakeBridge:
    def __init__(self, snapshots: dict[str, BrowserPageSnapshot] | None = None) -> None:
        self._snapshots = dict(snapshots or {})

    def navigate(self, url: str, *, timeout_ms: int = 30000) -> BrowserPageSnapshot:
        return self._snapshots.get(url, _make_snapshot(url))

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass


def test_build_initial_agent_state_starts_with_seed_budget() -> None:
    state = build_initial_agent_state(run_id="run-1", cve_id="CVE-2024-3094")

    assert state["run_id"] == "run-1"
    assert state["cve_id"] == "CVE-2024-3094"
    assert state["budget"]["max_pages_total"] > 0
    assert state["frontier"] == []
    assert state["decision_history"] == []
    assert state["navigation_chains"] == []
    assert state["current_chain_id"] is None
    assert state["page_role_history"] == []
    assert state["cross_domain_hops"] == 0
    assert state["browser_snapshots"] == {}


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
    monkeypatch.setattr("app.cve.agent_nodes.analyze_page", lambda snapshot: [])
    monkeypatch.setattr(
        "app.cve.agent_nodes.call_browser_agent_navigation",
        lambda navigation_context: {
            "action": "try_candidate_download",
            "reason_summary": "直接尝试下载候选 patch",
            "selected_urls": [],
            "selected_candidate_keys": [],
            "chain_updates": [],
            "new_chains": [],
        },
    )

    def _fake_download(session, *, run, candidate):
        patch = CVEPatchArtifact(
            run_id=run.run_id,
            candidate_url=str(candidate["candidate_url"]),
            patch_type=str(candidate["patch_type"]),
            download_status="downloaded",
            patch_meta_json={
                "discovered_from_url": candidate.get("discovered_from_url"),
                "discovery_sources": candidate.get("discovery_sources"),
            },
        )
        session.add(patch)
        session.flush()
        return patch

    monkeypatch.setattr("app.cve.agent_nodes.download_patch_candidate", _fake_download)

    state = build_initial_agent_state(
        run_id=str(seeded_cve_run.run_id),
        cve_id=seeded_cve_run.cve_id,
    )
    state["session"] = db_session
    state["_browser_bridge"] = _FakeBridge(
        {
            "https://security-tracker.debian.org/tracker/CVE-2024-3094": _make_snapshot(
                "https://security-tracker.debian.org/tracker/CVE-2024-3094",
                page_role_hint="tracker_page",
            )
        }
    )

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
        source["source_url"]
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
        source["source_url"]
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


def test_agent_decide_node_expands_only_frontier_items_without_expanded_flag(
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
            "expanded": True,
        },
        {
            "url": "https://example.com/next-hop",
            "depth": 1,
            "score": 5,
            "expanded": False,
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
    state["_browser_bridge"] = _FakeBridge(
        {
            "https://example.com/queued-frontier": _make_snapshot(
                "https://example.com/queued-frontier"
            )
        }
    )
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


def test_fetch_next_batch_node_honors_selected_frontier_urls(
    seeded_cve_run, db_session
) -> None:
    state = build_initial_agent_state(
        run_id=str(seeded_cve_run.run_id),
        cve_id=seeded_cve_run.cve_id,
    )
    state["session"] = db_session
    state["_browser_bridge"] = _FakeBridge(
        {
            "https://example.com/frontier-a": _make_snapshot("https://example.com/frontier-a"),
            "https://example.com/frontier-b": _make_snapshot("https://example.com/frontier-b"),
            "https://example.com/frontier-c": _make_snapshot("https://example.com/frontier-c"),
        }
    )
    state["frontier"] = [
        {
            "url": "https://example.com/frontier-a",
            "depth": 0,
            "score": 9,
            "expanded": False,
        },
        {
            "url": "https://example.com/frontier-b",
            "depth": 0,
            "score": 8,
            "expanded": False,
        },
        {
            "url": "https://example.com/frontier-c",
            "depth": 0,
            "score": 7,
            "expanded": False,
        },
    ]
    state["selected_frontier_urls"] = ["https://example.com/frontier-b"]

    result = fetch_next_batch_node(state)
    db_session.commit()

    expanded_urls = [
        item["url"] for item in result["frontier"] if item.get("expanded")
    ]
    assert expanded_urls == ["https://example.com/frontier-b"]


def test_fetch_next_batch_node_prefers_meaningful_page_as_current_page_when_nvd_shell_is_present(
    seeded_cve_run, db_session
) -> None:
    state = build_initial_agent_state(
        run_id=str(seeded_cve_run.run_id),
        cve_id="CVE-2022-2509",
    )
    state["session"] = db_session
    state["budget"]["max_parallel_frontier"] = 2
    state["_browser_bridge"] = _FakeBridge(
        {
            "https://nvd.nist.gov/vuln/detail/CVE-2022-2509": BrowserPageSnapshot(
                url="https://nvd.nist.gov/vuln/detail/CVE-2022-2509",
                final_url="https://nvd.nist.gov/vuln/detail/CVE-2022-2509",
                status_code=200,
                title="NVD - CVE-2022-2509",
                raw_html="<html><body><h1>You are viewing this page in an unauthorized frame window.</h1></body></html>",
                accessibility_tree='heading "You are viewing this page in an unauthorized frame window."',
                markdown_content=(
                    "# You are viewing this page in an unauthorized frame window.\n"
                    "This site requires JavaScript to be enabled for complete site functionality."
                ),
                links=[
                    PageLink(
                        url="https://nvd.nist.gov/",
                        text="https://nvd.nist.gov",
                        context="redirected to https://nvd.nist.gov",
                        is_cross_domain=False,
                        estimated_target_role="advisory_page",
                    )
                ],
                page_role_hint="advisory_page",
                fetch_duration_ms=300,
            ),
            "https://lists.debian.org/debian-lts-announce/2022/08/msg00002.html": _make_snapshot(
                "https://lists.debian.org/debian-lts-announce/2022/08/msg00002.html",
                page_role_hint="mailing_list_page",
                title="[SECURITY] [DLA 3070-1] gnutls28 security update",
                links=[
                    PageLink(
                        url="https://security-tracker.debian.org/tracker/gnutls28",
                        text="tracker",
                        context="follow tracker",
                        is_cross_domain=True,
                        estimated_target_role="tracker_page",
                    )
                ],
            ),
        }
    )
    state["frontier"] = [
        {
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-2509",
            "depth": 0,
            "score": 10,
            "expanded": False,
            "page_role": "advisory_page",
        },
        {
            "url": "https://lists.debian.org/debian-lts-announce/2022/08/msg00002.html",
            "depth": 0,
            "score": 14,
            "expanded": False,
            "page_role": "mailing_list_page",
        },
    ]

    result = fetch_next_batch_node(state)

    assert (
        result["current_page_url"]
        == "https://lists.debian.org/debian-lts-announce/2022/08/msg00002.html"
    )


def test_fetch_next_batch_node_leaves_current_page_empty_when_only_blocked_shell_page_is_fetched(
    seeded_cve_run, db_session
) -> None:
    state = build_initial_agent_state(
        run_id=str(seeded_cve_run.run_id),
        cve_id="CVE-2022-2509",
    )
    state["session"] = db_session
    state["budget"]["max_parallel_frontier"] = 1
    state["_browser_bridge"] = _FakeBridge(
        {
            "https://nvd.nist.gov/vuln/detail/CVE-2022-2509": BrowserPageSnapshot(
                url="https://nvd.nist.gov/vuln/detail/CVE-2022-2509",
                final_url="https://nvd.nist.gov/vuln/detail/CVE-2022-2509",
                status_code=200,
                title="NVD - CVE-2022-2509",
                raw_html="<html><body><h1>You are viewing this page in an unauthorized frame window.</h1></body></html>",
                accessibility_tree='heading "You are viewing this page in an unauthorized frame window."',
                markdown_content=(
                    "# You are viewing this page in an unauthorized frame window.\n"
                    "This site requires JavaScript to be enabled for complete site functionality."
                ),
                links=[
                    PageLink(
                        url="https://nvd.nist.gov/",
                        text="https://nvd.nist.gov",
                        context="redirected to https://nvd.nist.gov",
                        is_cross_domain=False,
                        estimated_target_role="advisory_page",
                    )
                ],
                page_role_hint="advisory_page",
                fetch_duration_ms=300,
            )
        }
    )
    state["frontier"] = [
        {
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-2509",
            "depth": 0,
            "score": 10,
            "expanded": False,
            "page_role": "advisory_page",
        }
    ]

    result = fetch_next_batch_node(state)

    assert result["current_page_url"] is None


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


def test_patch_agent_graph_routes_download_back_to_fetch_batch_when_requested(monkeypatch) -> None:
    call_log: list[str] = []
    decide_call_count = 0
    download_call_count = 0

    def _resolve(state):
        call_log.append("resolve")
        return state

    def _build(state):
        call_log.append("build")
        return state

    def _fetch(state):
        call_log.append("fetch")
        return state

    def _extract(state):
        call_log.append("extract")
        return state

    def _decide(state):
        nonlocal decide_call_count
        call_log.append("decide")
        decide_call_count += 1
        state["next_action"] = "try_candidate_download" if decide_call_count == 1 else "stop_search"
        return state

    def _download(state):
        nonlocal download_call_count
        call_log.append("download")
        download_call_count += 1
        state["next_action"] = "fetch_next_batch" if download_call_count == 1 else "finalize_run"
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
        "download",
        "fetch",
        "extract",
        "decide",
        "finalize",
    ]


def test_agent_decide_node_uses_fake_llm_expand_frontier(
    seeded_cve_run, db_session, monkeypatch
) -> None:
    frontier_node = CVESearchNode(
        run_id=seeded_cve_run.run_id,
        url="https://example.com/root",
        depth=0,
        host="example.com",
        page_role="frontier_page",
        fetch_status="fetched",
    )
    db_session.add(frontier_node)
    db_session.flush()

    state = build_initial_agent_state(
        run_id=str(seeded_cve_run.run_id),
        cve_id=seeded_cve_run.cve_id,
    )
    state["session"] = db_session
    state["current_page_url"] = "https://example.com/root"
    state["current_node_id"] = str(frontier_node.node_id)
    state["page_nodes"] = [
        {
            "node_id": str(frontier_node.node_id),
            "url": frontier_node.url,
            "depth": 0,
            "host": frontier_node.host,
            "fetch_status": frontier_node.fetch_status,
            "page_role": frontier_node.page_role,
        }
    ]
    state["page_observations"] = {
        "https://example.com/root": {
            "source_node_id": str(frontier_node.node_id),
            "url": "https://example.com/root",
            "depth": 0,
            "fetch_status": "fetched",
            "extracted_links": ["https://example.com/child"],
            "candidates": [],
            "extracted": True,
        }
    }
    state["browser_snapshots"] = {
        "https://example.com/root": asdict(
            _make_snapshot(
                "https://example.com/root",
                links=[
                    PageLink(
                        url="https://example.com/child",
                        text="child",
                        context="follow link",
                        is_cross_domain=False,
                        estimated_target_role="advisory_page",
                    )
                ],
            )
        )
    }
    state["frontier"] = [
        {
            "url": "https://example.com/child",
            "depth": 1,
            "score": 5,
            "expanded": False,
        }
    ]

    monkeypatch.setattr(
        "app.cve.agent_nodes.call_browser_agent_navigation",
        lambda navigation_context: {
            "action": "expand_frontier",
            "reason_summary": "继续扩展",
            "selected_urls": ["https://example.com/child"],
            "selected_candidate_keys": [],
            "model_name": "fake-llm",
            "chain_updates": [],
            "new_chains": [],
        },
    )

    result = agent_decide_node(state)
    db_session.commit()

    assert result["next_action"] == "expand_frontier"
    decision = db_session.execute(
        select(CVESearchDecision).where(CVESearchDecision.run_id == seeded_cve_run.run_id)
    ).scalar_one()
    assert decision.decision_type == "expand_frontier"
    assert decision.validated is True
    assert decision.model_name == "fake-llm"


def test_agent_decide_node_records_rejected_llm_url_and_falls_back(
    seeded_cve_run, db_session, monkeypatch
) -> None:
    state = build_initial_agent_state(
        run_id=str(seeded_cve_run.run_id),
        cve_id=seeded_cve_run.cve_id,
    )
    state["session"] = db_session
    state["current_page_url"] = "https://example.com/root"
    state["page_observations"] = {
        "https://example.com/root": {
            "url": "https://example.com/root",
            "depth": 0,
            "fetch_status": "fetched",
            "extracted_links": [],
            "candidates": [],
            "extracted": True,
        }
    }
    state["browser_snapshots"] = {
        "https://example.com/root": asdict(_make_snapshot("https://example.com/root"))
    }

    monkeypatch.setattr(
        "app.cve.agent_nodes.call_browser_agent_navigation",
        lambda navigation_context: {
            "action": "expand_frontier",
            "reason_summary": "越界 URL",
            "selected_urls": ["https://evil.example.com/out-of-scope"],
            "selected_candidate_keys": [],
            "model_name": "fake-llm",
            "chain_updates": [],
            "new_chains": [],
        },
    )

    result = agent_decide_node(state)
    decisions = db_session.execute(
        select(CVESearchDecision)
        .where(CVESearchDecision.run_id == seeded_cve_run.run_id)
        .order_by(CVESearchDecision.created_at, CVESearchDecision.decision_id)
    ).scalars().all()

    assert result["next_action"] == "stop_search"
    assert any(decision.validated is False for decision in decisions)
    assert any(
        decision.rejection_reason == "selected_url_not_in_frontier_or_page"
        for decision in decisions
    )


def test_agent_decide_node_fallback_limits_cross_domain_expansion(
    seeded_cve_run, db_session, monkeypatch
) -> None:
    state = build_initial_agent_state(
        run_id=str(seeded_cve_run.run_id),
        cve_id=seeded_cve_run.cve_id,
    )
    state["session"] = db_session
    state["budget"]["max_cross_domain_expansions"] = 1
    state["budget"]["max_children_per_node"] = 3
    state["current_page_url"] = "https://lists.example.com/post"
    state["page_observations"] = {
        "https://lists.example.com/post": {
            "url": "https://lists.example.com/post",
            "depth": 0,
            "fetch_status": "fetched",
            "extracted_links": [],
            "candidates": [],
            "extracted": True,
        }
    }
    state["frontier"] = [
        {"url": "https://redhat.example.com/a", "depth": 1, "score": 10, "expanded": False},
        {"url": "https://redhat.example.com/b", "depth": 1, "score": 9, "expanded": False},
        {"url": "https://redhat.example.com/c", "depth": 1, "score": 8, "expanded": False},
    ]

    def _raise_timeout(navigation_context):
        raise TimeoutError("llm timeout")

    monkeypatch.setattr("app.cve.agent_nodes.call_browser_agent_navigation", _raise_timeout)

    result = agent_decide_node(state)

    assert result["next_action"] == "expand_frontier"
    assert result["selected_frontier_urls"] == ["https://redhat.example.com/a"]
    assert result["decision_history"][-1]["validated"] is True


def test_agent_decide_node_invalid_duplicate_llm_result_uses_filtered_fallback(
    seeded_cve_run, db_session, monkeypatch
) -> None:
    state = build_initial_agent_state(
        run_id=str(seeded_cve_run.run_id),
        cve_id=seeded_cve_run.cve_id,
    )
    state["session"] = db_session
    state["current_page_url"] = "https://example.com/root"
    state["visited_urls"] = ["https://example.com/already-visited"]
    state["page_observations"] = {
        "https://example.com/root": {
            "url": "https://example.com/root",
            "depth": 0,
            "fetch_status": "fetched",
            "extracted_links": [],
            "candidates": [],
            "extracted": True,
        }
    }
    state["browser_snapshots"] = {
        "https://example.com/root": asdict(_make_snapshot("https://example.com/root"))
    }
    state["frontier"] = [
        {
            "url": "https://example.com/already-visited",
            "depth": 1,
            "score": 10,
            "expanded": False,
        },
        {
            "url": "https://example.com/fresh-hop",
            "depth": 1,
            "score": 9,
            "expanded": False,
        },
    ]

    monkeypatch.setattr(
        "app.cve.agent_nodes.call_browser_agent_navigation",
        lambda navigation_context: {
            "action": "expand_frontier",
            "reason_summary": "重复 URL",
            "selected_urls": ["https://example.com/already-visited"],
            "selected_candidate_keys": [],
            "model_name": "fake-llm",
            "chain_updates": [],
            "new_chains": [],
        },
    )

    result = agent_decide_node(state)

    assert result["next_action"] == "expand_frontier"
    assert result["selected_frontier_urls"] == ["https://example.com/fresh-hop"]
    assert result["decision_history"][-1]["validated"] is True


def test_agent_decide_node_rule_fallback_skips_site_navigation_noise(
    seeded_cve_run, db_session
) -> None:
    state = build_initial_agent_state(
        run_id=str(seeded_cve_run.run_id),
        cve_id=seeded_cve_run.cve_id,
    )
    state["session"] = db_session
    state["current_page_url"] = "https://nvd.nist.gov/vuln/detail/CVE-2022-2509"
    state["page_observations"] = {
        "https://nvd.nist.gov/vuln/detail/CVE-2022-2509": {
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-2509",
            "depth": 0,
            "fetch_status": "fetched",
            "extracted_links": [
                "https://nvd.nist.gov/general",
                "https://security-tracker.debian.org/tracker/CVE-2022-2509",
                "https://github.com/login?return_to=/advisories/GHSA",
            ],
            "candidates": [],
            "extracted": True,
        }
    }
    state["browser_snapshots"] = {
        "https://nvd.nist.gov/vuln/detail/CVE-2022-2509": {
            "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-2509",
            "final_url": "https://nvd.nist.gov/vuln/detail/CVE-2022-2509",
            "status_code": 200,
            "title": "NVD",
            "raw_html": "<html></html>",
            "accessibility_tree": "heading",
            "markdown_content": "summary",
            "links": [
                {
                    "url": "https://nvd.nist.gov/general",
                    "text": "General",
                    "context": "site navigation",
                    "is_cross_domain": False,
                    "estimated_target_role": "advisory_page",
                },
                {
                    "url": "https://security-tracker.debian.org/tracker/CVE-2022-2509",
                    "text": "Debian tracker",
                    "context": "vendor references",
                    "is_cross_domain": True,
                    "estimated_target_role": "tracker_page",
                },
                {
                    "url": "https://github.com/login?return_to=/advisories/GHSA",
                    "text": "Sign in",
                    "context": "github navigation",
                    "is_cross_domain": True,
                    "estimated_target_role": "unknown_page",
                },
            ],
        }
    }
    state["frontier"] = [
        {"url": "https://nvd.nist.gov/general", "depth": 1, "score": 1, "expanded": False},
        {
            "url": "https://security-tracker.debian.org/tracker/CVE-2022-2509",
            "depth": 1,
            "score": 30,
            "expanded": False,
        },
        {
            "url": "https://github.com/login?return_to=/advisories/GHSA",
            "depth": 1,
            "score": 0,
            "expanded": False,
        },
    ]

    result = agent_decide_node(state)

    assert result["next_action"] == "expand_frontier"
    assert result["selected_frontier_urls"] == [
        "https://security-tracker.debian.org/tracker/CVE-2022-2509"
    ]


def test_agent_decide_node_rule_fallback_drops_login_and_general_pages(
    seeded_cve_run, db_session
) -> None:
    state = build_initial_agent_state(
        run_id=str(seeded_cve_run.run_id),
        cve_id=seeded_cve_run.cve_id,
    )
    state["session"] = db_session
    state["current_page_url"] = "https://github.com/advisories/GHSA-w33j-4mrg-pgc3"
    state["frontier"] = [
        {
            "url": "https://github.com/login?return_to=/advisories/GHSA-w33j-4mrg-pgc3",
            "depth": 1,
            "score": 20,
            "expanded": False,
        },
        {
            "url": "https://nvd.nist.gov/general",
            "depth": 1,
            "score": 19,
            "expanded": False,
        },
        {
            "url": "https://www.debian.org/security/2022/dsa-5203",
            "depth": 1,
            "score": 18,
            "expanded": False,
        },
    ]

    result = agent_decide_node(state)

    assert result["next_action"] == "expand_frontier"
    assert result["selected_frontier_urls"] == [
        "https://www.debian.org/security/2022/dsa-5203"
    ]


def test_agent_decide_node_overrides_needs_human_review_when_expandable_frontier_exists(
    seeded_cve_run, db_session, monkeypatch
) -> None:
    state = build_initial_agent_state(
        run_id=str(seeded_cve_run.run_id),
        cve_id=seeded_cve_run.cve_id,
    )
    state["session"] = db_session
    state["current_page_url"] = "https://lists.debian.org/post"
    state["page_observations"] = {
        "https://lists.debian.org/post": {
            "url": "https://lists.debian.org/post",
            "depth": 0,
            "fetch_status": "fetched",
            "extracted_links": ["https://security-tracker.debian.org/tracker/gnutls28"],
            "candidates": [],
            "extracted": True,
        }
    }
    state["browser_snapshots"] = {
        "https://lists.debian.org/post": asdict(
            _make_snapshot(
                "https://lists.debian.org/post",
                page_role_hint="mailing_list_page",
                links=[
                    PageLink(
                        url="https://security-tracker.debian.org/tracker/gnutls28",
                        text="tracker",
                        context="follow tracker",
                        is_cross_domain=True,
                        estimated_target_role="tracker_page",
                    )
                ],
            )
        )
    }
    state["frontier"] = [
        {
            "url": "https://security-tracker.debian.org/tracker/gnutls28",
            "depth": 1,
            "score": 24,
            "expanded": False,
        }
    ]

    monkeypatch.setattr(
        "app.cve.agent_nodes.call_browser_agent_navigation",
        lambda navigation_context: {
            "action": "needs_human_review",
            "reason_summary": "当前页面没有直接 patch，需要人工看一下。",
            "selected_urls": [],
            "selected_candidate_keys": [],
            "model_name": "fake-llm",
            "chain_updates": [],
            "new_chains": [],
        },
    )

    result = agent_decide_node(state)

    assert result["next_action"] == "expand_frontier"
    assert result["selected_frontier_urls"] == [
        "https://security-tracker.debian.org/tracker/gnutls28"
    ]
    assert result["decision_history"][-1]["decision_type"] == "expand_frontier"


def test_filter_frontier_links_skips_mailing_list_navigation_noise_and_keeps_high_value_targets() -> None:
    links = [
        PageLink(
            url="https://lists.debian.org/debian-lts-announce/prev-date.html",
            text="Date Prev",
            context="mail archive navigation",
            is_cross_domain=False,
            estimated_target_role="mailing_list_page",
        ),
        PageLink(
            url="https://lists.debian.org/debian-lts-announce/next-date.html",
            text="Date Next",
            context="mail archive navigation",
            is_cross_domain=False,
            estimated_target_role="mailing_list_page",
        ),
        PageLink(
            url="https://lists.debian.org/debian-lts-announce/2022/08/thrd2.html",
            text="Thread Next",
            context="mail archive navigation",
            is_cross_domain=False,
            estimated_target_role="mailing_list_page",
        ),
        PageLink(
            url="https://lists.debian.org/debian-lts-announce/maillist.html",
            text="Date Index",
            context="mail archive navigation",
            is_cross_domain=False,
            estimated_target_role="mailing_list_page",
        ),
        PageLink(
            url="https://security-tracker.debian.org/tracker/CVE-2022-2509",
            text="Debian security tracker",
            context="follow tracker",
            is_cross_domain=True,
            estimated_target_role="tracker_page",
        ),
        PageLink(
            url="https://salsa.debian.org/gnutls-team/gnutls/-/commit/abcdef1234567890",
            text="upstream fix commit",
            context="commit reference",
            is_cross_domain=True,
            estimated_target_role="commit_page",
        ),
    ]

    filtered_links = _filter_frontier_links("mailing_list_page", links)

    assert [link.url for link in filtered_links] == [
        "https://security-tracker.debian.org/tracker/CVE-2022-2509",
        "https://salsa.debian.org/gnutls-team/gnutls/-/commit/abcdef1234567890",
    ]


def test_extract_links_and_candidates_node_filters_mailing_list_noise_before_frontier_slice(
    seeded_cve_run, db_session, monkeypatch
) -> None:
    root_node = CVESearchNode(
        run_id=seeded_cve_run.run_id,
        url="https://lists.debian.org/debian-lts-announce/2022/08/msg00002.html",
        depth=0,
        host="lists.debian.org",
        page_role="mailing_list_page",
        fetch_status="fetched",
    )
    db_session.add(root_node)
    db_session.flush()

    state = build_initial_agent_state(
        run_id=str(seeded_cve_run.run_id),
        cve_id="CVE-2022-2509",
    )
    state["session"] = db_session
    state["budget"]["max_children_per_node"] = 2
    state["page_nodes"] = [
        {
            "node_id": str(root_node.node_id),
            "url": root_node.url,
            "depth": root_node.depth,
            "host": root_node.host,
            "fetch_status": root_node.fetch_status,
            "page_role": root_node.page_role,
        }
    ]
    state["page_observations"] = {
        root_node.url: {
            "source_node_id": str(root_node.node_id),
            "chain_id": None,
            "url": root_node.url,
            "depth": 0,
            "fetch_status": "fetched",
            "content": "<html></html>",
            "content_type": "text/html",
            "extracted_links": [],
            "candidates": [],
            "extracted": False,
        }
    }
    state["browser_snapshots"] = {
        root_node.url: asdict(
            _make_snapshot(
                root_node.url,
                page_role_hint="mailing_list_page",
                links=[
                    PageLink(
                        url="https://lists.debian.org/debian-lts-announce/prev-date.html",
                        text="Date Prev",
                        context="mail archive navigation",
                        is_cross_domain=False,
                        estimated_target_role="mailing_list_page",
                    ),
                    PageLink(
                        url="https://lists.debian.org/debian-lts-announce/next-date.html",
                        text="Date Next",
                        context="mail archive navigation",
                        is_cross_domain=False,
                        estimated_target_role="mailing_list_page",
                    ),
                    PageLink(
                        url="https://lists.debian.org/debian-lts-announce/2022/08/thrd1.html",
                        text="Thread Prev",
                        context="mail archive navigation",
                        is_cross_domain=False,
                        estimated_target_role="mailing_list_page",
                    ),
                    PageLink(
                        url="https://lists.debian.org/debian-lts-announce/2022/08/thrd2.html",
                        text="Thread Next",
                        context="mail archive navigation",
                        is_cross_domain=False,
                        estimated_target_role="mailing_list_page",
                    ),
                    PageLink(
                        url="https://lists.debian.org/debian-lts-announce/maillist.html",
                        text="Date Index",
                        context="mail archive navigation",
                        is_cross_domain=False,
                        estimated_target_role="mailing_list_page",
                    ),
                    PageLink(
                        url="https://security-tracker.debian.org/tracker/CVE-2022-2509",
                        text="Debian security tracker",
                        context="follow tracker",
                        is_cross_domain=True,
                        estimated_target_role="tracker_page",
                    ),
                    PageLink(
                        url="https://salsa.debian.org/gnutls-team/gnutls/-/commit/abcdef1234567890",
                        text="upstream fix commit",
                        context="commit reference",
                        is_cross_domain=True,
                        estimated_target_role="commit_page",
                    ),
                ],
            )
        )
    }
    monkeypatch.setattr("app.cve.agent_nodes.analyze_page", lambda snapshot: [])

    result = extract_links_and_candidates_node(state)
    db_session.commit()

    frontier_urls = [item["url"] for item in result["frontier"]]
    assert frontier_urls == ["https://security-tracker.debian.org/tracker/CVE-2022-2509"]
    assert [candidate["candidate_url"] for candidate in result["direct_candidates"]] == [
        "https://salsa.debian.org/gnutls-team/gnutls/-/commit/abcdef1234567890.patch"
    ]


def test_extract_links_and_candidates_node_prioritizes_tracker_link_over_mailing_list_metadata_noise(
    seeded_cve_run, db_session, monkeypatch
) -> None:
    root_url = "https://lists.debian.org/debian-security-announce/2022/msg00172.html"
    root_node = CVESearchNode(
        run_id=seeded_cve_run.run_id,
        url=root_url,
        depth=0,
        host="lists.debian.org",
        page_role="mailing_list_page",
        fetch_status="fetched",
    )
    db_session.add(root_node)
    db_session.flush()

    state = build_initial_agent_state(
        run_id=str(seeded_cve_run.run_id),
        cve_id="CVE-2022-2509",
    )
    state["session"] = db_session
    state["budget"]["max_children_per_node"] = 3
    state["page_nodes"] = [
        {
            "node_id": str(root_node.node_id),
            "url": root_node.url,
            "depth": root_node.depth,
            "host": root_node.host,
            "fetch_status": root_node.fetch_status,
            "page_role": root_node.page_role,
        }
    ]
    state["page_observations"] = {
        root_url: {
            "source_node_id": str(root_node.node_id),
            "chain_id": None,
            "url": root_url,
            "depth": 0,
            "fetch_status": "fetched",
            "content": "<html></html>",
            "content_type": "text/html",
            "extracted_links": [],
            "candidates": [],
            "extracted": False,
        }
    }
    state["browser_snapshots"] = {
        root_url: asdict(
            _make_snapshot(
                root_url,
                page_role_hint="mailing_list_page",
                links=[
                    PageLink(
                        url="https://lists.debian.org/debian-security-announce/2022/msg00171.html",
                        text="Date Prev",
                        context="[Date Prev][Date Next] [Thread Prev][Thread Next] [Date Index] [Thread Index]",
                        is_cross_domain=False,
                        estimated_target_role="mailing_list_page",
                    ),
                    PageLink(
                        url="https://lists.debian.org/debian-security-announce/2022/msg00173.html",
                        text="Date Next",
                        context="[Date Prev][Date Next] [Thread Prev][Thread Next] [Date Index] [Thread Index]",
                        is_cross_domain=False,
                        estimated_target_role="mailing_list_page",
                    ),
                    PageLink(
                        url="mailto:debian-security-announce%40lists.debian.org",
                        text="debian-security-announce@lists.debian.org",
                        context="To: debian-security-announce@lists.debian.org",
                        is_cross_domain=True,
                        estimated_target_role="mailing_list_page",
                    ),
                    PageLink(
                        url="mailto:carnil%40debian.org",
                        text="carnil@debian.org",
                        context="From: Salvatore Bonaccorso <carnil@debian.org>",
                        is_cross_domain=True,
                        estimated_target_role="unknown_page",
                    ),
                    PageLink(
                        url="https://lists.debian.org/msgid-search/E1oL8O9-0004xA-CC@seger.debian.org",
                        text="[🔎]",
                        context="Message-id: <[🔎] E1oL8O9-0004xA-CC@seger.debian.org>",
                        is_cross_domain=False,
                        estimated_target_role="mailing_list_page",
                    ),
                    PageLink(
                        url=root_url,
                        text="E1oL8O9-0004xA-CC@seger.debian.org",
                        context="Message-id: <[🔎] E1oL8O9-0004xA-CC@seger.debian.org>",
                        is_cross_domain=False,
                        estimated_target_role="mailing_list_page",
                    ),
                    PageLink(
                        url="https://www.debian.org/security/",
                        text="https://www.debian.org/security/",
                        context="Debian Security Advisory",
                        is_cross_domain=True,
                        estimated_target_role="tracker_page",
                    ),
                    PageLink(
                        url="https://www.debian.org/security/faq",
                        text="https://www.debian.org/security/faq",
                        context="Debian Security FAQ",
                        is_cross_domain=True,
                        estimated_target_role="tracker_page",
                    ),
                    PageLink(
                        url="https://security-tracker.debian.org/tracker/gnutls28",
                        text="https://security-tracker.debian.org/tracker/gnutls28",
                        context="Debian Security Advisory",
                        is_cross_domain=True,
                        estimated_target_role="tracker_page",
                    ),
                    PageLink(
                        url="https://lists.debian.org/debian-security-announce/2022/msg00171.html",
                        text="[SECURITY] [DSA 5202-1] unzip security update",
                        context="Prev by Date: [SECURITY] [DSA 5202-1] unzip security update",
                        is_cross_domain=False,
                        estimated_target_role="mailing_list_page",
                    ),
                    PageLink(
                        url="https://lists.debian.org/debian-security-announce/2022/msg00173.html",
                        text="[SECURITY] [DSA 5204-1] gst-plugins-good1.0 security update",
                        context="Next by Date: [SECURITY] [DSA 5204-1] gst-plugins-good1.0 security update",
                        is_cross_domain=False,
                        estimated_target_role="mailing_list_page",
                    ),
                ],
            )
        )
    }
    monkeypatch.setattr("app.cve.agent_nodes.analyze_page", lambda snapshot: [])

    result = extract_links_and_candidates_node(state)
    db_session.commit()

    frontier_urls = [item["url"] for item in result["frontier"]]
    assert frontier_urls == ["https://security-tracker.debian.org/tracker/gnutls28"]


def test_agent_decide_node_rule_fallback_skips_mailto_and_msgid_noise(
    seeded_cve_run, db_session, monkeypatch
) -> None:
    state = build_initial_agent_state(
        run_id=str(seeded_cve_run.run_id),
        cve_id="CVE-2022-2509",
    )
    state["session"] = db_session
    state["current_page_url"] = "https://nvd.nist.gov/vuln/detail/CVE-2022-2509"
    state["budget"]["max_children_per_node"] = 3
    state["frontier"] = [
        {
            "url": "mailto:debian-security-announce%40lists.debian.org",
            "depth": 1,
            "score": 30,
            "expanded": False,
            "page_role": "mailing_list_page",
        },
        {
            "url": "https://lists.debian.org/msgid-search/E1oL8O9-0004xA-CC@seger.debian.org",
            "depth": 1,
            "score": 29,
            "expanded": False,
            "page_role": "mailing_list_page",
        },
        {
            "url": "https://www.debian.org/security/",
            "depth": 1,
            "score": 28,
            "expanded": False,
            "page_role": "tracker_page",
        },
        {
            "url": "https://security-tracker.debian.org/tracker/gnutls28",
            "depth": 1,
            "score": 27,
            "expanded": False,
            "page_role": "tracker_page",
        },
    ]
    state["page_observations"] = {
        state["current_page_url"]: {
            "url": state["current_page_url"],
            "depth": 0,
            "fetch_status": "fetched",
            "extracted_links": [],
            "candidates": [],
            "extracted": True,
        }
    }
    state["browser_snapshots"] = {
        state["current_page_url"]: asdict(_make_snapshot(state["current_page_url"]))
    }

    monkeypatch.setattr(
        "app.cve.agent_nodes.call_browser_agent_navigation",
        lambda navigation_context: {
            "action": "stop_search",
            "reason_summary": "页面没有直接 patch。",
            "selected_urls": [],
            "selected_candidate_keys": [],
            "model_name": "fake-llm",
            "chain_updates": [],
            "new_chains": [],
        },
    )

    result = agent_decide_node(state)

    assert result["next_action"] == "expand_frontier"
    assert result["selected_frontier_urls"] == [
        "https://security-tracker.debian.org/tracker/gnutls28"
    ]


def test_select_fallback_frontier_urls_prefers_high_value_cross_domain_over_nvd_same_domain_noise() -> None:
    state = build_initial_agent_state(run_id="run-1", cve_id="CVE-2022-2509")
    state["current_page_url"] = "https://nvd.nist.gov/vuln/detail/CVE-2022-2509"
    state["budget"]["max_children_per_node"] = 2
    state["budget"]["max_cross_domain_expansions"] = 2
    state["frontier"] = [
        {
            "url": "https://nvd.nist.gov/vuln/search",
            "depth": 1,
            "score": 10,
            "expanded": False,
            "page_role": "advisory_page",
        },
        {
            "url": "https://nvd.nist.gov/vuln",
            "depth": 1,
            "score": 9,
            "expanded": False,
            "page_role": "advisory_page",
        },
        {
            "url": "https://security-tracker.debian.org/tracker/gnutls28",
            "depth": 1,
            "score": 30,
            "expanded": False,
            "page_role": "tracker_page",
        },
    ]

    selected_urls = _select_fallback_frontier_urls(state, state["frontier"])

    assert selected_urls == ["https://security-tracker.debian.org/tracker/gnutls28"]


def test_extract_links_and_candidates_node_deduplicates_frontier_links_across_multiple_pages(
    seeded_cve_run, db_session, monkeypatch
) -> None:
    first_node = CVESearchNode(
        run_id=seeded_cve_run.run_id,
        url="https://lists.debian.org/debian-lts-announce/2022/08/msg00002.html",
        depth=0,
        host="lists.debian.org",
        page_role="mailing_list_page",
        fetch_status="fetched",
    )
    second_node = CVESearchNode(
        run_id=seeded_cve_run.run_id,
        url="https://www.debian.org/security/2022/dsa-5203",
        depth=0,
        host="www.debian.org",
        page_role="mailing_list_page",
        fetch_status="fetched",
    )
    db_session.add_all([first_node, second_node])
    db_session.flush()

    state = build_initial_agent_state(
        run_id=str(seeded_cve_run.run_id),
        cve_id="CVE-2022-2509",
    )
    state["session"] = db_session
    state["budget"]["max_children_per_node"] = 2
    state["page_nodes"] = [
        {
            "node_id": str(first_node.node_id),
            "url": first_node.url,
            "depth": first_node.depth,
            "host": first_node.host,
            "fetch_status": first_node.fetch_status,
            "page_role": first_node.page_role,
        },
        {
            "node_id": str(second_node.node_id),
            "url": second_node.url,
            "depth": second_node.depth,
            "host": second_node.host,
            "fetch_status": second_node.fetch_status,
            "page_role": second_node.page_role,
        },
    ]
    state["page_observations"] = {
        first_node.url: {
            "source_node_id": str(first_node.node_id),
            "chain_id": None,
            "url": first_node.url,
            "depth": 0,
            "fetch_status": "fetched",
            "content": "<html></html>",
            "content_type": "text/html",
            "extracted_links": [],
            "candidates": [],
            "extracted": False,
        },
        second_node.url: {
            "source_node_id": str(second_node.node_id),
            "chain_id": None,
            "url": second_node.url,
            "depth": 0,
            "fetch_status": "fetched",
            "content": "<html></html>",
            "content_type": "text/html",
            "extracted_links": [],
            "candidates": [],
            "extracted": False,
        },
    }
    tracker_link = PageLink(
        url="https://security-tracker.debian.org/tracker/gnutls28",
        text="https://security-tracker.debian.org/tracker/gnutls28",
        context="Debian Security Advisory",
        is_cross_domain=True,
        estimated_target_role="tracker_page",
    )
    state["browser_snapshots"] = {
        first_node.url: asdict(
            _make_snapshot(
                first_node.url,
                page_role_hint="mailing_list_page",
                links=[tracker_link],
            )
        ),
        second_node.url: asdict(
            _make_snapshot(
                second_node.url,
                page_role_hint="mailing_list_page",
                links=[tracker_link],
            )
        ),
    }
    monkeypatch.setattr("app.cve.agent_nodes.analyze_page", lambda snapshot: [])

    result = extract_links_and_candidates_node(state)
    db_session.commit()

    frontier_urls = [item["url"] for item in result["frontier"]]
    assert frontier_urls == ["https://security-tracker.debian.org/tracker/gnutls28"]


def test_extract_links_and_candidates_node_appends_frontier_edge_and_candidate(
    seeded_cve_run, db_session, monkeypatch
) -> None:
    root_node = CVESearchNode(
        run_id=seeded_cve_run.run_id,
        url="https://example.com/root",
        depth=0,
        host="example.com",
        page_role="frontier_page",
        fetch_status="fetched",
    )
    db_session.add(root_node)
    db_session.flush()

    state = build_initial_agent_state(
        run_id=str(seeded_cve_run.run_id),
        cve_id=seeded_cve_run.cve_id,
    )
    state["session"] = db_session
    state["page_nodes"] = [
        {
            "node_id": str(root_node.node_id),
            "url": root_node.url,
            "depth": root_node.depth,
            "host": root_node.host,
            "fetch_status": root_node.fetch_status,
            "page_role": root_node.page_role,
        }
    ]
    state["page_observations"] = {
        "https://example.com/root": {
            "source_node_id": str(root_node.node_id),
            "url": "https://example.com/root",
            "depth": 0,
            "fetch_status": "fetched",
            "content": "<html></html>",
            "content_type": "text/html",
            "extracted_links": [],
            "candidates": [],
            "extracted": False,
        }
    }
    state["browser_snapshots"] = {
        "https://example.com/root": asdict(
            _make_snapshot(
                "https://example.com/root",
                links=[
                    PageLink(
                        url="https://example.com/child",
                        text="child",
                        context="follow child",
                        is_cross_domain=False,
                        estimated_target_role="advisory_page",
                    )
                ],
            )
        )
    }
    monkeypatch.setattr(
        "app.cve.agent_nodes.analyze_page",
        lambda snapshot: [
            {
                "candidate_url": "https://example.com/fix.patch",
                "patch_type": "patch",
            }
        ],
    )

    result = extract_links_and_candidates_node(state)
    db_session.commit()

    assert any(item["url"] == "https://example.com/child" for item in result["frontier"])
    edge_count = db_session.execute(
        select(CVESearchNode).where(CVESearchNode.run_id == seeded_cve_run.run_id)
    ).scalars().all()
    assert len(edge_count) == 2
    candidate = db_session.execute(
        select(CVECandidateArtifact).where(CVECandidateArtifact.run_id == seeded_cve_run.run_id)
    ).scalar_one()
    assert candidate.candidate_url == "https://example.com/fix.patch"


def test_download_and_finalize_node_updates_run_summary(
    seeded_cve_run, db_session, monkeypatch
) -> None:
    state = build_initial_agent_state(
        run_id=str(seeded_cve_run.run_id),
        cve_id=seeded_cve_run.cve_id,
    )
    state["session"] = db_session
    state["seed_references"] = ["https://example.com/fix.patch"]
    build_initial_frontier_node(state)

    def _fake_download(session, *, run, candidate):
        patch = CVEPatchArtifact(
            run_id=run.run_id,
            candidate_url=str(candidate["candidate_url"]),
            patch_type=str(candidate["patch_type"]),
            download_status="downloaded",
            patch_meta_json={
                "discovered_from_url": "https://example.com/root",
                "discovered_from_host": "example.com",
                "discovery_sources": [
                    {
                        "source_url": "https://example.com/root",
                        "source_host": "example.com",
                        "discovery_rule": "matcher",
                        "source_kind": "page",
                        "order": 0,
                    }
                ],
            },
        )
        session.add(patch)
        session.flush()
        return patch

    monkeypatch.setattr("app.cve.agent_nodes.download_patch_candidate", _fake_download)

    downloaded_state = download_and_validate_node(state)
    finalize_run_node(downloaded_state)
    db_session.commit()

    run = db_session.get(type(seeded_cve_run), seeded_cve_run.run_id)
    assert run is not None
    assert run.status == "succeeded"
    assert run.stop_reason == "patches_downloaded"
    assert run.summary_json["primary_patch_url"] == "https://example.com/fix.patch"


def test_download_and_validate_node_prefers_selected_candidate_keys(monkeypatch) -> None:
    run_id = uuid.uuid4()

    class _FakeSession:
        def __init__(self) -> None:
            self.run = SimpleNamespace(
                run_id=run_id,
                phase="agent_decide",
                status="running",
                stop_reason=None,
                summary_json={},
            )
            self.candidates = [
                SimpleNamespace(
                    candidate_url="https://example.com/fix-a.patch",
                    candidate_type="patch",
                    canonical_key="https://example.com/fix-a.patch",
                    evidence_json={},
                    download_status="discovered",
                    validation_status="pending",
                    artifact_id=None,
                ),
                SimpleNamespace(
                    candidate_url="https://example.com/fix-b.patch",
                    candidate_type="patch",
                    canonical_key="https://example.com/fix-b.patch",
                    evidence_json={},
                    download_status="discovered",
                    validation_status="pending",
                    artifact_id=None,
                ),
            ]

        def get(self, model, value):
            if model is CVERun and value == run_id:
                return self.run
            return None

        def execute(self, statement):
            class _FakeScalars:
                def __init__(self, candidates) -> None:
                    self._candidates = candidates

                def all(self):
                    return list(self._candidates)

            class _FakeResult:
                def __init__(self, candidates) -> None:
                    self._candidates = candidates

                def scalars(self):
                    return _FakeScalars(self._candidates)

            return _FakeResult(self.candidates)

        def flush(self) -> None:
            return None

    session = _FakeSession()
    state = build_initial_agent_state(
        run_id=str(run_id),
        cve_id="CVE-2024-3094",
    )
    state["session"] = session
    state["budget"]["max_download_attempts"] = 1
    state["selected_candidate_keys"] = ["https://example.com/fix-b.patch"]

    attempted_urls: list[str] = []

    def _fake_download(session, *, run, candidate):
        attempted_urls.append(str(candidate["candidate_url"]))
        return SimpleNamespace(
            patch_id=uuid.uuid4(),
            artifact_id=uuid.uuid4(),
            candidate_url=str(candidate["candidate_url"]),
            patch_type=str(candidate["patch_type"]),
            download_status="downloaded",
            patch_meta_json={},
        )

    monkeypatch.setattr("app.cve.agent_nodes.download_patch_candidate", _fake_download)

    download_and_validate_node(state)

    assert attempted_urls == ["https://example.com/fix-b.patch"]
