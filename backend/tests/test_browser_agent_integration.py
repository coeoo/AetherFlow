from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path

from app.cve.agent_graph import build_cve_patch_graph
from app.cve.agent_state import build_initial_agent_state
from app.cve.browser.base import BrowserPageSnapshot, PageLink
from app.cve.service import create_cve_run
from app.models import CVERun
from app.models.cve import CVEPatchArtifact, CVESearchEdge


_FIXTURE_ROOT = Path(__file__).resolve().parent / "fixtures" / "browser_agent"


def _load_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_snapshot(path: Path) -> BrowserPageSnapshot:
    payload = _load_json(path)
    return BrowserPageSnapshot(
        url=str(payload["url"]),
        final_url=str(payload["final_url"]),
        status_code=int(payload["status_code"]),
        title=str(payload["title"]),
        raw_html=str(payload["raw_html"]),
        accessibility_tree=str(payload["accessibility_tree"]),
        markdown_content=str(payload["markdown_content"]),
        links=[
            PageLink(
                url=str(link["url"]),
                text=str(link["text"]),
                context=str(link["context"]),
                is_cross_domain=bool(link["is_cross_domain"]),
                estimated_target_role=str(link["estimated_target_role"]),
            )
            for link in list(payload.get("links") or [])
            if isinstance(link, dict)
        ],
        page_role_hint=str(payload["page_role_hint"]),
        fetch_duration_ms=int(payload["fetch_duration_ms"]),
    )


def _load_scenario_snapshots(scenario_name: str) -> dict[str, BrowserPageSnapshot]:
    scenario_dir = _FIXTURE_ROOT / scenario_name
    snapshots: dict[str, BrowserPageSnapshot] = {}
    for path in sorted(scenario_dir.glob("snapshot_*.json")):
        snapshot = _load_snapshot(path)
        snapshots[snapshot.url] = snapshot
    return snapshots


def _load_scenario_llm_responses(scenario_name: str) -> list[dict[str, object]]:
    scenario_dir = _FIXTURE_ROOT / scenario_name
    return [_load_json(path) for path in sorted(scenario_dir.glob("llm_response_*.json"))]


class _RecordedBridge:
    def __init__(self, snapshots: dict[str, BrowserPageSnapshot]) -> None:
        self._snapshots = snapshots
        self.visited_urls: list[str] = []

    def navigate(self, url: str, *, timeout_ms: int = 30_000) -> BrowserPageSnapshot:
        self.visited_urls.append(url)
        if url not in self._snapshots:
            raise AssertionError(f"缺少录制快照: {url}")
        return self._snapshots[url]

    def start(self) -> None:
        return None

    def stop(self) -> None:
        return None


class _RecordedLLM:
    def __init__(self, responses: list[dict[str, object]]) -> None:
        self._responses = list(responses)
        self.calls: list[object] = []

    def __call__(self, navigation_context):
        self.calls.append(navigation_context)
        if not self._responses:
            raise AssertionError("录制的 LLM 响应数量不足。")
        return self._responses.pop(0)


@dataclass
class _ScenarioExecution:
    run: CVERun
    state: dict[str, object]
    visited_urls: list[str]
    llm_call_count: int
    downloaded_candidate_urls: list[str]


def _execute_recorded_scenario(
    db_session,
    monkeypatch,
    *,
    scenario_name: str,
    cve_id: str,
    seed_references: list[str],
    budget_overrides: dict[str, int] | None = None,
) -> _ScenarioExecution:
    run = create_cve_run(db_session, cve_id=cve_id)
    db_session.commit()

    snapshots = _load_scenario_snapshots(scenario_name)
    llm = _RecordedLLM(_load_scenario_llm_responses(scenario_name))
    bridge = _RecordedBridge(snapshots)
    downloaded_candidate_urls: list[str] = []

    monkeypatch.setattr(
        "app.cve.agent_nodes.resolve_seed_references",
        lambda session, *, run, cve_id: list(seed_references),
    )
    monkeypatch.setattr("app.cve.agent_nodes.call_browser_agent_navigation", llm)

    def _fake_download(session, *, run, candidate):
        downloaded_candidate_urls.append(str(candidate["candidate_url"]))
        patch = CVEPatchArtifact(
            run_id=run.run_id,
            candidate_url=str(candidate["candidate_url"]),
            patch_type=str(candidate["patch_type"]),
            download_status="downloaded",
            patch_meta_json={
                "discovered_from_url": candidate.get("discovered_from_url"),
                "discovered_from_host": candidate.get("discovered_from_host"),
                "discovery_rule": candidate.get("discovery_rule"),
                "canonical_candidate_key": candidate.get("canonical_candidate_key"),
                "discovery_sources": list(candidate.get("discovery_sources") or []),
                "evidence_source_count": candidate.get("evidence_source_count"),
            },
        )
        session.add(patch)
        session.flush()
        return patch

    monkeypatch.setattr("app.cve.agent_nodes.download_patch_candidate", _fake_download)

    state = build_initial_agent_state(run_id=str(run.run_id), cve_id=cve_id)
    state["session"] = db_session
    state["_browser_bridge"] = bridge
    if budget_overrides:
        state["budget"].update(budget_overrides)

    result = build_cve_patch_graph().invoke(state)
    db_session.commit()

    reloaded_run = db_session.get(CVERun, run.run_id)
    assert reloaded_run is not None
    return _ScenarioExecution(
        run=reloaded_run,
        state=result,
        visited_urls=list(bridge.visited_urls),
        llm_call_count=len(llm.calls),
        downloaded_candidate_urls=downloaded_candidate_urls,
    )


def test_browser_agent_integration_tracks_cve_2022_2509_chain(
    db_session, monkeypatch
) -> None:
    execution = _execute_recorded_scenario(
        db_session,
        monkeypatch,
        scenario_name="cve_2022_2509",
        cve_id="CVE-2022-2509",
        seed_references=["https://nvd.nist.gov/vuln/detail/CVE-2022-2509"],
        budget_overrides={"max_parallel_frontier": 1},
    )

    assert execution.run.status == "succeeded"
    assert execution.run.stop_reason == "patches_downloaded"
    assert execution.run.summary_json["primary_patch_url"] == (
        "https://gitlab.com/gnutls/gnutls/-/commit/ce37f9eb.patch"
    )
    assert execution.visited_urls == [
        "https://nvd.nist.gov/vuln/detail/CVE-2022-2509",
        "https://security-tracker.debian.org/tracker/CVE-2022-2509",
    ]
    assert execution.llm_call_count == 3
    assert execution.downloaded_candidate_urls == [
        "https://gitlab.com/gnutls/gnutls/-/commit/ce37f9eb.patch"
    ]
    chain_summary = execution.run.summary_json["chain_summary"]
    assert len(chain_summary) == 1
    assert [step["url"] for step in chain_summary[0]["steps"]] == [
        "https://nvd.nist.gov/vuln/detail/CVE-2022-2509",
        "https://security-tracker.debian.org/tracker/CVE-2022-2509",
        "https://gitlab.com/gnutls/gnutls/-/commit/ce37f9eb",
    ]
    assert chain_summary[0]["status"] == "completed"


def test_browser_agent_integration_handles_multi_chain_multi_domain_cve_2024_3094(
    db_session, monkeypatch
) -> None:
    execution = _execute_recorded_scenario(
        db_session,
        monkeypatch,
        scenario_name="cve_2024_3094",
        cve_id="CVE-2024-3094",
        seed_references=[
            "https://www.openwall.com/lists/oss-security/2024/03/29/4",
            "https://access.redhat.com/security/cve/CVE-2024-3094",
        ],
        budget_overrides={"max_parallel_frontier": 1},
    )

    assert execution.run.status == "succeeded"
    assert execution.run.stop_reason == "patches_downloaded"
    assert execution.run.summary_json["primary_patch_url"] == (
        "https://gitlab.com/xz-backdoor/xz/-/commit/8f2c1a2.patch"
    )
    assert execution.run.summary_json["cross_domain_hops"] == 1
    assert execution.visited_urls == [
        "https://www.openwall.com/lists/oss-security/2024/03/29/4",
        "https://access.redhat.com/security/cve/CVE-2024-3094",
    ]
    edges = db_session.query(CVESearchEdge).filter(CVESearchEdge.run_id == execution.run.run_id).all()
    assert any("cross_domain" in edge.edge_type for edge in edges)
    chain_summary = execution.run.summary_json["chain_summary"]
    assert len(chain_summary) == 2
    assert {chain["status"] for chain in chain_summary} == {"dead_end", "completed"}


def test_browser_agent_integration_recognizes_github_commit_patch_from_reference(
    db_session, monkeypatch
) -> None:
    execution = _execute_recorded_scenario(
        db_session,
        monkeypatch,
        scenario_name="github_commit_only",
        cve_id="CVE-2023-9999",
        seed_references=["https://nvd.nist.gov/vuln/detail/CVE-2023-9999"],
        budget_overrides={"max_parallel_frontier": 1},
    )

    assert execution.run.status == "succeeded"
    assert execution.run.summary_json["primary_patch_url"] == (
        "https://github.com/example/project/commit/abcdef123456.patch"
    )
    assert execution.downloaded_candidate_urls == [
        "https://github.com/example/project/commit/abcdef123456.patch"
    ]
    assert execution.visited_urls == ["https://nvd.nist.gov/vuln/detail/CVE-2023-9999"]


def test_browser_agent_integration_stops_when_no_viable_patch_path_exists(
    db_session, monkeypatch
) -> None:
    execution = _execute_recorded_scenario(
        db_session,
        monkeypatch,
        scenario_name="no_patch",
        cve_id="CVE-2021-0001",
        seed_references=["https://nvd.nist.gov/vuln/detail/CVE-2021-0001"],
        budget_overrides={"max_parallel_frontier": 1},
    )

    assert execution.run.status == "failed"
    assert execution.run.stop_reason == "no_remaining_frontier_or_candidates"
    assert execution.run.summary_json["patch_found"] is False
    chain_summary = execution.run.summary_json["chain_summary"]
    assert len(chain_summary) == 1
    assert chain_summary[0]["status"] == "dead_end"


def test_browser_agent_integration_stops_when_page_budget_is_exhausted(
    db_session, monkeypatch
) -> None:
    execution = _execute_recorded_scenario(
        db_session,
        monkeypatch,
        scenario_name="budget_exhausted",
        cve_id="CVE-2020-4242",
        seed_references=["https://nvd.nist.gov/vuln/detail/CVE-2020-4242"],
        budget_overrides={
            "max_pages_total": 1,
            "max_parallel_frontier": 1,
        },
    )

    assert execution.run.status == "failed"
    assert execution.run.stop_reason == "max_pages_total_exhausted"
    assert execution.run.summary_json["patch_found"] is False
    assert execution.llm_call_count == 1
    assert execution.visited_urls == ["https://nvd.nist.gov/vuln/detail/CVE-2020-4242"]
