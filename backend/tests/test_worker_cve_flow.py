from app.models import CVEPatchArtifact
from app.db.session import create_session_factory
from app.worker.runtime import process_once


def test_post_run_then_worker_once_then_get_summary_returns_terminal_state(
    client, test_database_url, monkeypatch
) -> None:
    monkeypatch.setattr(
        "app.cve.runtime.resolve_seed_references",
        lambda cve_id: ["https://example.com/advisory"],
    )
    monkeypatch.setattr(
        "app.cve.runtime.plan_frontier",
        lambda seed_references: seed_references,
    )
    monkeypatch.setattr(
        "app.cve.runtime.fetch_page",
        lambda url: {"url": url, "content": "https://example.com/fix.patch"},
    )
    monkeypatch.setattr(
        "app.cve.runtime.analyze_page",
        lambda snapshot: [
            {
                "candidate_url": "https://example.com/fix.patch",
                "patch_type": "patch",
            }
        ],
    )

    def _fake_download(session, *, run, candidate):
        patch = CVEPatchArtifact(
            run_id=run.run_id,
            candidate_url=candidate["candidate_url"],
            patch_type=candidate["patch_type"],
            download_status="downloaded",
            patch_meta_json={"source": "test"},
        )
        session.add(patch)
        session.flush()
        return patch

    monkeypatch.setattr("app.cve.runtime.download_patch_candidate", _fake_download)

    response = client.post("/api/v1/cve/runs", json={"cve_id": "CVE-2024-3094"})
    run_id = response.json()["data"]["run_id"]

    session_factory = create_session_factory(test_database_url)
    processed = process_once(session_factory, worker_name="worker-e2e")
    assert processed is True

    detail = client.get(f"/api/v1/cve/runs/{run_id}")
    assert detail.status_code == 200
    body = detail.json()["data"]
    assert body["status"] == "succeeded"
    assert body["stop_reason"] == "patches_downloaded"
    assert body["summary"]["patch_found"] is True
    assert body["summary"]["patch_count"] == 1


def test_worker_once_marks_run_failed_when_seed_resolution_returns_empty(
    client, test_database_url, monkeypatch
) -> None:
    monkeypatch.setattr("app.cve.runtime.resolve_seed_references", lambda cve_id: [])

    response = client.post("/api/v1/cve/runs", json={"cve_id": "CVE-2024-3094"})
    run_id = response.json()["data"]["run_id"]

    session_factory = create_session_factory(test_database_url)
    processed = process_once(session_factory, worker_name="worker-e2e")
    assert processed is True

    detail = client.get(f"/api/v1/cve/runs/{run_id}")
    assert detail.status_code == 200
    body = detail.json()["data"]
    assert body["status"] == "failed"
    assert body["stop_reason"] == "no_seed_references"
    assert body["summary"]["patch_found"] is False
