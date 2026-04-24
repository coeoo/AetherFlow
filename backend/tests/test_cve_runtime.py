import uuid

import logging

from app.cve.frontier_planner import plan_frontier
from app.cve.runtime import execute_cve_run
from app.cve.seed_resolver import SeedReference, _merge_seed_references
from app.cve.service import create_cve_run
from app.models import CVERun


def _refs(urls: list[str]) -> list[SeedReference]:
    return [SeedReference(url=url, source="test", authority_score=0) for url in urls]


class _FakeBridge:
    def __init__(self, lifecycle: list[str] | None = None) -> None:
        self._lifecycle = lifecycle

    def start(self) -> None:
        if self._lifecycle is not None:
            self._lifecycle.append("start")

    def stop(self) -> None:
        if self._lifecycle is not None:
            self._lifecycle.append("stop")


def test_execute_cve_run_fails_with_no_seed_references(db_session, monkeypatch) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.commit()

    monkeypatch.setattr(
        "app.cve.agent_nodes.resolve_seed_references",
        lambda session, *, run, cve_id: [],
    )
    monkeypatch.setattr("app.cve.runtime.SyncBrowserBridge", lambda backend: _FakeBridge())
    monkeypatch.setattr("app.cve.runtime.PlaywrightBackend", lambda **kwargs: object())

    execute_cve_run(db_session, run_id=run.run_id)
    db_session.commit()

    reloaded_run = db_session.get(CVERun, run.run_id)
    assert reloaded_run is not None
    assert reloaded_run.status == "failed"
    assert reloaded_run.stop_reason == "no_seed_references"


def test_execute_cve_run_marks_failure_when_seed_resolution_raises(
    db_session, monkeypatch
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.commit()

    def _raise_seed_error(session, *, run, cve_id: str) -> list[str]:
        raise RuntimeError("nvd timeout")

    monkeypatch.setattr(
        "app.cve.agent_nodes.resolve_seed_references",
        _raise_seed_error,
    )
    monkeypatch.setattr("app.cve.runtime.SyncBrowserBridge", lambda backend: _FakeBridge())
    monkeypatch.setattr("app.cve.runtime.PlaywrightBackend", lambda **kwargs: object())

    execute_cve_run(db_session, run_id=run.run_id)
    db_session.commit()

    reloaded_run = db_session.get(CVERun, run.run_id)
    assert reloaded_run is not None
    assert reloaded_run.status == "failed"
    assert reloaded_run.phase == "resolve_seeds"
    assert reloaded_run.stop_reason == "resolve_seeds_failed"
    assert reloaded_run.summary_json["patch_found"] is False
    assert reloaded_run.summary_json["patch_count"] == 0
    assert reloaded_run.summary_json["error"] == "nvd timeout"


def test_execute_cve_run_uses_browser_agent_single_path(monkeypatch) -> None:
    lifecycle: list[str] = []
    invoked_state: dict[str, object] = {}
    invoke_config: dict[str, object] = {}

    class _FakeRun:
        def __init__(self) -> None:
            self.run_id = uuid.uuid4()
            self.cve_id = "CVE-2024-3094"
            self.phase = "resolve_seeds"
            self.status = "queued"
            self.stop_reason = None
            self.summary_json = {}

    fake_run = _FakeRun()

    class _FakeSession:
        def get(self, model, run_id):
            if model is CVERun and run_id == fake_run.run_id:
                return fake_run
            return None

        def flush(self) -> None:
            lifecycle.append("flush")

    class _FakeGraph:
        def invoke(self, state, config=None):
            lifecycle.append("invoke")
            invoked_state.update(state)
            invoke_config.update(config or {})
            return state

    monkeypatch.setattr(
        "app.cve.runtime.SyncBrowserBridge",
        lambda backend: _FakeBridge(lifecycle),
    )
    monkeypatch.setattr("app.cve.runtime.PlaywrightBackend", lambda **kwargs: object())
    monkeypatch.setattr("app.cve.runtime.build_cve_patch_graph", lambda: _FakeGraph())

    fake_session = _FakeSession()
    execute_cve_run(fake_session, run_id=fake_run.run_id)

    assert lifecycle == ["start", "invoke", "stop", "flush"]
    assert invoked_state["run_id"] == str(fake_run.run_id)
    assert invoked_state["cve_id"] == "CVE-2024-3094"
    assert invoked_state["session"] is fake_session
    assert "_browser_bridge" in invoked_state
    assert int(invoke_config["recursion_limit"]) >= 64
    assert invoked_state["budget"]["max_parallel_frontier"] == 1


def test_execute_cve_run_returns_final_state(monkeypatch) -> None:
    class _FakeRun:
        def __init__(self) -> None:
            self.run_id = uuid.uuid4()
            self.cve_id = "CVE-2022-2509"
            self.phase = "resolve_seeds"
            self.status = "queued"
            self.stop_reason = None
            self.summary_json = {}

    fake_run = _FakeRun()

    class _FakeSession:
        def get(self, model, run_id):
            if model is CVERun and run_id == fake_run.run_id:
                return fake_run
            return None

        def flush(self) -> None:
            return None

        def commit(self) -> None:
            return None

    final_state = {
        "run_id": str(fake_run.run_id),
        "cve_id": fake_run.cve_id,
        "patches": [],
        "_llm_decision_log": [{"step_index": 1}],
    }

    class _FakeGraph:
        def invoke(self, state, config=None):
            state.update(final_state)
            return state

    monkeypatch.setattr("app.cve.runtime.SyncBrowserBridge", lambda backend: _FakeBridge())
    monkeypatch.setattr("app.cve.runtime.PlaywrightBackend", lambda **kwargs: object())
    monkeypatch.setattr("app.cve.runtime.build_cve_patch_graph", lambda: _FakeGraph())

    result = execute_cve_run(_FakeSession(), run_id=fake_run.run_id)

    assert result["_llm_decision_log"] == [{"step_index": 1}]
    assert result["cve_id"] == "CVE-2022-2509"


def test_execute_cve_run_flushes_after_graph_invoke(monkeypatch) -> None:
    lifecycle: list[str] = []

    class _FakeRun:
        def __init__(self) -> None:
            self.run_id = uuid.uuid4()
            self.cve_id = "CVE-2022-2509"
            self.phase = "resolve_seeds"
            self.status = "queued"
            self.stop_reason = None
            self.summary_json = {}

    fake_run = _FakeRun()

    class _FakeSession:
        def get(self, model, run_id):
            if model is CVERun and run_id == fake_run.run_id:
                return fake_run
            return None

        def flush(self) -> None:
            lifecycle.append("flush")

    class _FakeGraph:
        def invoke(self, state, config=None):
            lifecycle.append("invoke")
            state["stop_reason"] = "patched"
            return state

    monkeypatch.setattr("app.cve.runtime.SyncBrowserBridge", lambda backend: _FakeBridge(lifecycle))
    monkeypatch.setattr("app.cve.runtime.PlaywrightBackend", lambda **kwargs: object())
    monkeypatch.setattr("app.cve.runtime.build_cve_patch_graph", lambda: _FakeGraph())

    execute_cve_run(_FakeSession(), run_id=fake_run.run_id)

    assert lifecycle == ["start", "invoke", "stop", "flush"]


def test_execute_cve_run_logs_runtime_milestones(monkeypatch, caplog) -> None:
    class _FakeRun:
        def __init__(self) -> None:
            self.run_id = uuid.uuid4()
            self.cve_id = "CVE-2022-2509"
            self.phase = "resolve_seeds"
            self.status = "queued"
            self.stop_reason = None
            self.summary_json = {}

    fake_run = _FakeRun()

    class _FakeSession:
        def get(self, model, run_id):
            if model is CVERun and run_id == fake_run.run_id:
                return fake_run
            return None

        def flush(self) -> None:
            return None

    class _FakeGraph:
        def invoke(self, state, config=None):
            state["stop_reason"] = "patches_downloaded"
            return state

    monkeypatch.setattr("app.cve.runtime.SyncBrowserBridge", lambda backend: _FakeBridge())
    monkeypatch.setattr("app.cve.runtime.PlaywrightBackend", lambda **kwargs: object())
    monkeypatch.setattr("app.cve.runtime.build_cve_patch_graph", lambda: _FakeGraph())

    with caplog.at_level(logging.INFO, logger="app.cve.runtime"):
        execute_cve_run(_FakeSession(), run_id=fake_run.run_id)

    assert "开始执行 run" in caplog.text
    assert "bridge.start() 完成" in caplog.text
    assert "graph.invoke() 开始" in caplog.text
    assert "graph.invoke() 完成" in caplog.text


def test_execute_cve_run_uses_diagnostic_runner_when_enabled(monkeypatch) -> None:
    class _FakeRun:
        def __init__(self) -> None:
            self.run_id = uuid.uuid4()
            self.cve_id = "CVE-2022-2509"
            self.phase = "resolve_seeds"
            self.status = "queued"
            self.stop_reason = None
            self.summary_json = {}

    fake_run = _FakeRun()
    captured: dict[str, object] = {}

    class _FakeSession:
        def get(self, model, run_id):
            if model is CVERun and run_id == fake_run.run_id:
                return fake_run
            return None

        def flush(self) -> None:
            return None

    def _fake_diagnostic_runner(*, session, run, state):
        captured["session"] = session
        captured["run"] = run
        captured["state"] = dict(state)
        state["stop_reason"] = "diagnostic_done"
        return state

    monkeypatch.setenv("AETHERFLOW_CVE_RUNTIME_DIAGNOSTIC_MODE", "true")
    monkeypatch.setattr("app.cve.runtime.SyncBrowserBridge", lambda backend: _FakeBridge())
    monkeypatch.setattr("app.cve.runtime.PlaywrightBackend", lambda **kwargs: object())
    monkeypatch.setattr("app.cve.runtime._execute_diagnostic_run", _fake_diagnostic_runner)
    monkeypatch.setattr(
        "app.cve.runtime.build_cve_patch_graph",
        lambda: (_ for _ in ()).throw(AssertionError("不应走默认 graph 路径")),
    )

    result = execute_cve_run(_FakeSession(), run_id=fake_run.run_id)

    assert result["stop_reason"] == "diagnostic_done"
    assert captured["run"] is fake_run
    assert captured["state"]["cve_id"] == "CVE-2022-2509"


def test_execute_diagnostic_run_commits_progress_after_each_node(monkeypatch, caplog) -> None:
    class _FakeRun:
        def __init__(self) -> None:
            self.run_id = uuid.uuid4()
            self.cve_id = "CVE-2022-2509"
            self.phase = "resolve_seeds"
            self.status = "queued"
            self.stop_reason = None
            self.summary_json = {}

    fake_run = _FakeRun()
    lifecycle: list[str] = []

    class _FakeSession:
        def flush(self) -> None:
            lifecycle.append("flush")

        def commit(self) -> None:
            lifecycle.append("commit")

    monkeypatch.setattr(
        "app.cve.runtime.resolve_seeds_node",
        lambda state: {**state, "stop_reason": "diagnostic_stop"},
    )
    monkeypatch.setattr(
        "app.cve.runtime.finalize_run_node",
        lambda state: {**state, "stop_reason": state.get("stop_reason")},
    )

    from app.cve.runtime import _execute_diagnostic_run

    with caplog.at_level(logging.INFO, logger="app.cve.runtime"):
        result = _execute_diagnostic_run(
            session=_FakeSession(),
            run=fake_run,
            state={"cve_id": fake_run.cve_id},
        )

    assert result["stop_reason"] == "diagnostic_stop"
    assert lifecycle == ["flush", "commit", "flush", "commit"]
    assert "进入诊断节点 resolve_seeds" in caplog.text
    assert "诊断节点 resolve_seeds 完成" in caplog.text
    assert "elapsed=" in caplog.text
    assert "selected_candidate_keys_count" in caplog.text


def test_execute_diagnostic_run_loops_until_frontier_expansion_stops(monkeypatch) -> None:
    class _FakeRun:
        def __init__(self) -> None:
            self.run_id = uuid.uuid4()
            self.cve_id = "CVE-2022-2509"
            self.phase = "resolve_seeds"
            self.status = "queued"
            self.stop_reason = None
            self.summary_json = {}

    fake_run = _FakeRun()
    lifecycle: list[str] = []
    counters = {"fetch": 0, "extract": 0, "decide": 0}

    class _FakeSession:
        def flush(self) -> None:
            lifecycle.append("flush")

        def commit(self) -> None:
            lifecycle.append("commit")

    monkeypatch.setattr(
        "app.cve.runtime.resolve_seeds_node",
        lambda state: {**state, "seed_references": ["https://example.com/advisory"]},
    )
    monkeypatch.setattr(
        "app.cve.runtime.build_initial_frontier_node",
        lambda state: {**state, "frontier": [{"url": "https://example.com/advisory"}]},
    )

    def _fetch(state):
        counters["fetch"] += 1
        return {**state, "fetched_round": counters["fetch"]}

    def _extract(state):
        counters["extract"] += 1
        return {**state, "extracted_round": counters["extract"]}

    def _decide(state):
        counters["decide"] += 1
        if counters["decide"] == 1:
            return {**state, "next_action": "expand_frontier", "stop_reason": None}
        return {**state, "next_action": "stop_search", "stop_reason": "no_patch_candidates"}

    monkeypatch.setattr("app.cve.runtime.fetch_next_batch_node", _fetch)
    monkeypatch.setattr("app.cve.runtime.extract_links_and_candidates_node", _extract)
    monkeypatch.setattr("app.cve.runtime.agent_decide_node", _decide)
    monkeypatch.setattr(
        "app.cve.runtime.finalize_run_node",
        lambda state: {**state, "finalized": True},
    )

    from app.cve.runtime import _execute_diagnostic_run

    result = _execute_diagnostic_run(
        session=_FakeSession(),
        run=fake_run,
        state={"cve_id": fake_run.cve_id, "budget": {"max_parallel_frontier": 3}},
    )

    assert result["finalized"] is True
    assert counters == {"fetch": 2, "extract": 2, "decide": 2}
    assert lifecycle.count("commit") == 9


def test_execute_diagnostic_run_uses_configured_total_timeout(monkeypatch) -> None:
    class _FakeRun:
        def __init__(self) -> None:
            self.run_id = uuid.uuid4()
            self.cve_id = "CVE-2022-2509"
            self.phase = "resolve_seeds"
            self.status = "queued"
            self.stop_reason = None
            self.summary_json = {}

    fake_run = _FakeRun()
    counters = {"fetch": 0}

    class _FakeSession:
        def flush(self) -> None:
            return None

        def commit(self) -> None:
            return None

    monkeypatch.setenv("AETHERFLOW_CVE_RUNTIME_DIAGNOSTIC_TIMEOUT_SECONDS", "1")
    monkeypatch.setattr(
        "app.cve.runtime.resolve_seeds_node",
        lambda state: {**state, "seed_references": ["https://example.com/advisory"]},
    )
    monkeypatch.setattr(
        "app.cve.runtime.build_initial_frontier_node",
        lambda state: {**state, "frontier": [{"url": "https://example.com/advisory"}]},
    )

    def _fetch(state):
        counters["fetch"] += 1
        return state

    monkeypatch.setattr("app.cve.runtime.fetch_next_batch_node", _fetch)
    monkeypatch.setattr("app.cve.runtime.extract_links_and_candidates_node", lambda state: state)
    monkeypatch.setattr("app.cve.runtime.agent_decide_node", lambda state: state)
    monkeypatch.setattr(
        "app.cve.runtime.finalize_run_node",
        lambda state: {**state, "finalized": True},
    )

    monotonic_values = iter([0.0, 0.0, 0.0, 0.0, 0.0, 2.0, 2.0, 2.0])
    monkeypatch.setattr("app.cve.runtime.monotonic", lambda: next(monotonic_values))

    from app.cve.runtime import _execute_diagnostic_run

    result = _execute_diagnostic_run(
        session=_FakeSession(),
        run=fake_run,
        state={"cve_id": fake_run.cve_id, "budget": {"max_parallel_frontier": 1}},
    )

    assert result["stop_reason"] == "diagnostic_timeout"
    assert result["finalized"] is True
    assert counters["fetch"] == 0


def test_execute_diagnostic_run_forces_single_frontier_fetch_per_round(monkeypatch) -> None:
    class _FakeRun:
        def __init__(self) -> None:
            self.run_id = uuid.uuid4()
            self.cve_id = "CVE-2022-2509"
            self.phase = "resolve_seeds"
            self.status = "queued"
            self.stop_reason = None
            self.summary_json = {}

    fake_run = _FakeRun()
    captured_budget: dict[str, object] = {}

    class _FakeSession:
        def flush(self) -> None:
            return None

        def commit(self) -> None:
            return None

    monkeypatch.setattr(
        "app.cve.runtime.resolve_seeds_node",
        lambda state: {**state, "seed_references": ["https://example.com/advisory"]},
    )
    monkeypatch.setattr(
        "app.cve.runtime.build_initial_frontier_node",
        lambda state: {**state, "frontier": [{"url": "https://example.com/advisory"}]},
    )

    def _fetch(state):
        captured_budget.update(dict(state.get("budget") or {}))
        return {**state, "next_action": "stop_search", "stop_reason": "done"}

    monkeypatch.setattr("app.cve.runtime.fetch_next_batch_node", _fetch)
    monkeypatch.setattr("app.cve.runtime.extract_links_and_candidates_node", lambda state: state)
    monkeypatch.setattr("app.cve.runtime.agent_decide_node", lambda state: state)
    monkeypatch.setattr("app.cve.runtime.finalize_run_node", lambda state: state)

    from app.cve.runtime import _execute_diagnostic_run

    _execute_diagnostic_run(
        session=_FakeSession(),
        run=fake_run,
        state={"cve_id": fake_run.cve_id, "budget": {"max_parallel_frontier": 3}},
    )

    assert captured_budget["max_parallel_frontier"] == 1


def test_plan_frontier_deduplicates_urls_and_limits_page_count() -> None:
    frontier = plan_frontier(
        _refs([
            "https://example.com/a#top",
            "https://example.com/b",
            "https://example.com/a",
            "   ",
            "https://example.com/c",
            "https://example.com/d",
            "https://example.com/e",
            "https://example.com/f",
            "https://example.com/g",
            "https://example.com/h",
            "https://example.com/i",
            "https://example.com/j",
            "https://example.com/k",
        ])
    )

    assert frontier == [
        "https://example.com/a",
        "https://example.com/b",
        "https://example.com/c",
        "https://example.com/d",
        "https://example.com/e",
        "https://example.com/f",
        "https://example.com/g",
        "https://example.com/h",
        "https://example.com/i",
        "https://example.com/j",
    ]


def test_plan_frontier_skips_direct_patch_matches_before_limiting_pages() -> None:
    frontier = plan_frontier(
        _refs([
            "https://example.com/a#top",
            "https://github.com/acme/project/commit/abc1234",
            "https://example.com/b",
            "https://example.com/c",
            "https://example.com/d",
            "https://example.com/e",
            "https://example.com/f",
            "https://example.com/g",
            "https://example.com/h",
            "https://example.com/i",
            "https://example.com/j",
            "https://example.com/k",
        ])
    )

    assert frontier == [
        "https://example.com/a",
        "https://example.com/b",
        "https://example.com/c",
        "https://example.com/d",
        "https://example.com/e",
        "https://example.com/f",
        "https://example.com/g",
        "https://example.com/h",
        "https://example.com/i",
        "https://example.com/j",
    ]


def test_plan_frontier_prioritizes_debian_tracker_and_announce_pages() -> None:
    frontier = plan_frontier(
        _refs([
            "https://access.redhat.com/downloads",
            "https://access.redhat.com/security/cve/CVE-2022-2509",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-2509",
            "https://lists.debian.org/debian-lts-announce/2022/08/msg00002.html",
            "https://www.debian.org/security/2022/dsa-5203",
            "https://security-tracker.debian.org/tracker/CVE-2022-2509",
        ])
    )

    assert frontier == [
        "https://security-tracker.debian.org/tracker/CVE-2022-2509",
        "https://www.debian.org/security/2022/dsa-5203",
        "https://lists.debian.org/debian-lts-announce/2022/08/msg00002.html",
        "https://nvd.nist.gov/vuln/detail/CVE-2022-2509",
        "https://access.redhat.com/security/cve/CVE-2022-2509",
        "https://access.redhat.com/downloads",
    ]


def test_plan_frontier_prioritizes_openwall_oss_security_over_generic_vendor_pages() -> None:
    frontier = plan_frontier(
        _refs([
            "https://access.redhat.com/security/cve/CVE-2024-3094",
            "https://github.com/advisories/GHSA-rxwq-x6h5-x525",
            "https://www.vicarius.io/vsociety/vulnerabilities/cve-2024-3094",
            "https://www.openwall.com/lists/oss-security/2024/03/29/4",
        ])
    )

    assert frontier[:3] == [
        "https://www.openwall.com/lists/oss-security/2024/03/29/4",
        "https://access.redhat.com/security/cve/CVE-2024-3094",
        "https://github.com/advisories/GHSA-rxwq-x6h5-x525",
    ]


def test_plan_frontier_deduplicates_openwall_http_and_https_variants() -> None:
    frontier = plan_frontier(
        _refs([
            "https://www.openwall.com/lists/oss-security/2024/03/29/4",
            "http://www.openwall.com/lists/oss-security/2024/03/29/4",
            "https://access.redhat.com/security/cve/CVE-2024-3094",
        ])
    )

    assert frontier == [
        "https://www.openwall.com/lists/oss-security/2024/03/29/4",
        "https://access.redhat.com/security/cve/CVE-2024-3094",
    ]


def test_merge_seed_references_preserves_source_and_authority() -> None:
    from types import SimpleNamespace

    merged = _merge_seed_references(
        [
            SimpleNamespace(
                source="cve_official",
                references=[
                    "https://cve.example.org/CVE-2030-1001",
                    "https://git.example.org/acme/widget/commit/abc1234def5678",
                ],
            ),
            SimpleNamespace(
                source="nvd",
                references=["https://nvd.example.org/vuln/detail/CVE-2030-1001"],
            ),
        ]
    )

    merged_by_url = {reference.url: reference for reference in merged}

    assert merged_by_url["https://cve.example.org/CVE-2030-1001"].source == "cve_official"
    assert merged_by_url["https://cve.example.org/CVE-2030-1001"].authority_score == 100
    assert (
        merged_by_url["https://git.example.org/acme/widget/commit/abc1234def5678"].source
        == "cve_official"
    )
    assert (
        merged_by_url["https://git.example.org/acme/widget/commit/abc1234def5678"].authority_score
        == 100
    )
    assert merged_by_url["https://nvd.example.org/vuln/detail/CVE-2030-1001"].source == "nvd"
    assert merged_by_url["https://nvd.example.org/vuln/detail/CVE-2030-1001"].authority_score == 60


def test_merge_seed_references_dedup_keeps_highest_authority() -> None:
    from types import SimpleNamespace

    merged = _merge_seed_references(
        [
            SimpleNamespace(source="cve_official", references=["https://example.com/advisory/CVE-2030-2002"]),
            SimpleNamespace(source="nvd", references=["https://example.com/advisory/CVE-2030-2002"]),
        ]
    )

    assert len(merged) == 1
    assert merged[0] == SeedReference(
        url="https://example.com/advisory/CVE-2030-2002",
        source="cve_official",
        authority_score=100,
    )
