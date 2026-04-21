from sqlalchemy import select

from app.cve.service import create_cve_run
from app.db.session import create_session_factory
from app.models import CVERun, TaskAttempt, TaskJob
from app.worker.runtime import process_once


def test_post_run_then_worker_once_then_get_summary_returns_terminal_state(
    client, db_session, test_database_url, monkeypatch
) -> None:
    def _fake_execute_cve_run(session, *, run_id) -> None:
        run = session.get(CVERun, run_id)
        assert run is not None
        run.status = "succeeded"
        run.phase = "finalize_run"
        run.stop_reason = "patches_downloaded"
        run.summary_json = {
            "patch_found": True,
            "patch_count": 1,
            "runtime_kind": "patch_agent_graph",
        }

    monkeypatch.setattr("app.worker.runtime.execute_cve_run", _fake_execute_cve_run)

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
    job = db_session.get(TaskJob, run.job_id)
    assert job is not None
    assert job.status == "succeeded"

    attempt = db_session.execute(
        select(TaskAttempt).where(TaskAttempt.job_id == run.job_id)
    ).scalar_one()
    assert attempt.status == "succeeded"


def test_worker_once_marks_run_failed_when_seed_resolution_returns_empty(
    client, db_session, test_database_url, monkeypatch
) -> None:
    def _fake_execute_cve_run(session, *, run_id) -> None:
        run = session.get(CVERun, run_id)
        assert run is not None
        run.status = "failed"
        run.phase = "resolve_seeds"
        run.stop_reason = "no_seed_references"
        run.summary_json = {"patch_found": False, "patch_count": 0}

    monkeypatch.setattr("app.worker.runtime.execute_cve_run", _fake_execute_cve_run)

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


def test_worker_once_supports_agent_graph_job_type(
    db_session, test_database_url, monkeypatch
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.commit()

    invoked: list[str] = []

    def _fake_execute_cve_run(session, *, run_id) -> None:
        invoked.append(str(run_id))
        loaded_run = session.get(CVERun, run_id)
        assert loaded_run is not None
        loaded_run.status = "succeeded"
        loaded_run.phase = "finalize_run"
        loaded_run.stop_reason = "patches_downloaded"
        loaded_run.summary_json = {"patch_found": True, "patch_count": 1}

    monkeypatch.setattr("app.worker.runtime.execute_cve_run", _fake_execute_cve_run)

    session_factory = create_session_factory(test_database_url)
    processed = process_once(session_factory, worker_name="worker-agent")

    assert processed is True
    assert invoked == [str(run.run_id)]


def test_worker_once_marks_run_terminal_when_seed_resolution_raises(
    client, db_session, test_database_url, monkeypatch
) -> None:
    def _fake_execute_cve_run(session, *, run_id) -> None:
        run = session.get(CVERun, run_id)
        assert run is not None
        run.status = "failed"
        run.phase = "resolve_seeds"
        run.stop_reason = "resolve_seeds_failed"
        run.summary_json = {
            "patch_found": False,
            "patch_count": 0,
            "error": "nvd timeout",
        }

    monkeypatch.setattr("app.worker.runtime.execute_cve_run", _fake_execute_cve_run)

    response = client.post("/api/v1/cve/runs", json={"cve_id": "CVE-2024-3094"})
    run_id = response.json()["data"]["run_id"]

    session_factory = create_session_factory(test_database_url)
    processed = process_once(session_factory, worker_name="worker-e2e")
    assert processed is True

    detail = client.get(f"/api/v1/cve/runs/{run_id}")
    assert detail.status_code == 200
    body = detail.json()["data"]
    assert body["status"] == "failed"
    assert body["phase"] == "resolve_seeds"
    assert body["stop_reason"] == "resolve_seeds_failed"
    assert body["summary"]["patch_found"] is False
    assert body["summary"]["error"] == "nvd timeout"
    assert body["progress"]["current_phase"] == "resolve_seeds"
    assert body["progress"]["completed_steps"] == 0
    assert body["progress"]["total_steps"] == 6
    assert body["progress"]["terminal"] is True

    db_session.expire_all()
    run = db_session.get(CVERun, run_id)
    assert run is not None
    assert run.phase == "resolve_seeds"

    job = db_session.get(TaskJob, run.job_id)
    assert job is not None
    assert job.status == "failed"
    assert job.last_error == "场景运行失败: resolve_seeds_failed"

    attempt = db_session.execute(
        select(TaskAttempt).where(TaskAttempt.job_id == run.job_id)
    ).scalar_one()
    assert attempt.status == "failed"
    assert attempt.error_message == "场景运行失败: resolve_seeds_failed"
