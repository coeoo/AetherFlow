from pathlib import Path

import httpx
from sqlalchemy import select

from app.models import Artifact, CVERun, CVEPatchArtifact, TaskAttempt, TaskJob
from app.db.session import create_session_factory
from app.worker.runtime import process_once


def test_post_run_then_worker_once_then_get_summary_returns_terminal_state(
    client, db_session, test_database_url, monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("AETHERFLOW_ARTIFACT_ROOT", str(tmp_path))
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
    patch_text = "diff --git a/app.py b/app.py\n+patched = True\n"

    def _fake_http_get(url: str, **kwargs) -> httpx.Response:
        request = httpx.Request("GET", url)
        return httpx.Response(
            200,
            text=patch_text,
            headers={"content-type": "text/x-patch"},
            request=request,
        )

    monkeypatch.setattr("app.cve.patch_downloader.httpx.get", _fake_http_get)

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

    db_session.expire_all()
    run = db_session.get(CVERun, run_id)
    assert run is not None
    patch = db_session.execute(
        select(CVEPatchArtifact).where(CVEPatchArtifact.run_id == run.run_id)
    ).scalar_one()
    assert patch.download_status == "downloaded"
    assert patch.artifact_id is not None

    artifact = db_session.get(Artifact, patch.artifact_id)
    assert artifact is not None
    assert artifact.storage_path.endswith("fix.patch")
    assert Path(artifact.storage_path).read_text(encoding="utf-8") == patch_text


def test_worker_once_marks_run_failed_when_seed_resolution_returns_empty(
    client, db_session, test_database_url, monkeypatch
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

    db_session.expire_all()
    run = db_session.get(CVERun, run_id)
    assert run is not None
    job = db_session.get(TaskJob, run.job_id)
    assert job is not None
    assert job.status == "failed"

    attempt = db_session.execute(
        select(TaskAttempt).where(TaskAttempt.job_id == run.job_id)
    ).scalar_one()
    assert attempt.status == "failed"
    assert attempt.error_message == "场景运行失败: no_seed_references"


def test_worker_once_marks_run_terminal_when_seed_resolution_raises(
    client, db_session, test_database_url, monkeypatch
) -> None:
    def _raise_seed_error(cve_id: str) -> list[str]:
        raise RuntimeError("nvd timeout")

    monkeypatch.setattr("app.cve.runtime.resolve_seed_references", _raise_seed_error)

    response = client.post("/api/v1/cve/runs", json={"cve_id": "CVE-2024-3094"})
    run_id = response.json()["data"]["run_id"]

    session_factory = create_session_factory(test_database_url)
    processed = process_once(session_factory, worker_name="worker-e2e")
    assert processed is True

    detail = client.get(f"/api/v1/cve/runs/{run_id}")
    assert detail.status_code == 200
    body = detail.json()["data"]
    assert body["status"] == "failed"
    assert body["stop_reason"] == "resolve_seeds_failed"
    assert body["summary"]["patch_found"] is False
    assert body["summary"]["error"] == "nvd timeout"

    db_session.expire_all()
    run = db_session.get(CVERun, run_id)
    assert run is not None
    assert run.phase == "finalize_run"

    job = db_session.get(TaskJob, run.job_id)
    assert job is not None
    assert job.status == "failed"
    assert job.last_error == "场景运行失败: resolve_seeds_failed"

    attempt = db_session.execute(
        select(TaskAttempt).where(TaskAttempt.job_id == run.job_id)
    ).scalar_one()
    assert attempt.status == "failed"
    assert attempt.error_message == "场景运行失败: resolve_seeds_failed"
