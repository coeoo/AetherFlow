import uuid

from app.cve.frontier_planner import plan_frontier
from app.cve.runtime import execute_cve_run
from app.cve.service import create_cve_run
from app.models import CVERun


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
        def invoke(self, state):
            lifecycle.append("invoke")
            invoked_state.update(state)
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


def test_plan_frontier_deduplicates_urls_and_limits_page_count() -> None:
    frontier = plan_frontier(
        [
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
        ]
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
        [
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
        ]
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
        [
            "https://access.redhat.com/downloads",
            "https://access.redhat.com/security/cve/CVE-2022-2509",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-2509",
            "https://lists.debian.org/debian-lts-announce/2022/08/msg00002.html",
            "https://www.debian.org/security/2022/dsa-5203",
            "https://security-tracker.debian.org/tracker/CVE-2022-2509",
        ]
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
        [
            "https://access.redhat.com/security/cve/CVE-2024-3094",
            "https://github.com/advisories/GHSA-rxwq-x6h5-x525",
            "https://www.vicarius.io/vsociety/vulnerabilities/cve-2024-3094",
            "https://www.openwall.com/lists/oss-security/2024/03/29/4",
        ]
    )

    assert frontier[:3] == [
        "https://www.openwall.com/lists/oss-security/2024/03/29/4",
        "https://access.redhat.com/security/cve/CVE-2024-3094",
        "https://github.com/advisories/GHSA-rxwq-x6h5-x525",
    ]


def test_plan_frontier_deduplicates_openwall_http_and_https_variants() -> None:
    frontier = plan_frontier(
        [
            "https://www.openwall.com/lists/oss-security/2024/03/29/4",
            "http://www.openwall.com/lists/oss-security/2024/03/29/4",
            "https://access.redhat.com/security/cve/CVE-2024-3094",
        ]
    )

    assert frontier == [
        "https://www.openwall.com/lists/oss-security/2024/03/29/4",
        "https://access.redhat.com/security/cve/CVE-2024-3094",
    ]
