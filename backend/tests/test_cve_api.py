import uuid

from app.models import CVERun, TaskJob


def test_post_cve_runs_creates_queued_run_and_task_job(client, db_session) -> None:
    response = client.post("/api/v1/cve/runs", json={"cve_id": "CVE-2024-3094"})

    assert response.status_code == 200
    body = response.json()
    assert body["code"] == 0
    assert body["message"] == "success"
    assert body["data"]["cve_id"] == "CVE-2024-3094"
    assert body["data"]["status"] == "queued"
    assert body["data"]["phase"] == "resolve_seeds"

    run_id = uuid.UUID(body["data"]["run_id"])
    run = db_session.get(CVERun, run_id)
    assert run is not None
    assert run.cve_id == "CVE-2024-3094"
    assert run.status == "queued"
    assert run.phase == "resolve_seeds"

    job = db_session.get(TaskJob, run.job_id)
    assert job is not None
    assert job.scene_name == "cve"
    assert job.job_type == "cve_patch_fast_first"
    assert job.trigger_kind == "manual"
    assert job.status == "queued"


def test_post_cve_runs_rejects_invalid_cve_id(client) -> None:
    response = client.post("/api/v1/cve/runs", json={"cve_id": "bad-id"})

    assert response.status_code == 422


def test_get_cve_run_returns_minimal_summary(client, seeded_cve_run) -> None:
    response = client.get(f"/api/v1/cve/runs/{seeded_cve_run.run_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["code"] == 0
    assert body["message"] == "success"
    assert body["data"]["run_id"] == str(seeded_cve_run.run_id)
    assert body["data"]["cve_id"] == "CVE-2024-3094"
    assert body["data"]["status"] == "queued"
    assert body["data"]["phase"] == "resolve_seeds"
    assert body["data"]["stop_reason"] is None
    assert body["data"]["summary"] == {}


def test_get_cve_run_returns_404_for_missing_run(client) -> None:
    response = client.get(f"/api/v1/cve/runs/{uuid.uuid4()}")

    assert response.status_code == 404
