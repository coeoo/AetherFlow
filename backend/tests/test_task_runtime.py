from __future__ import annotations

import os
from pathlib import Path
import subprocess
import uuid

import pytest
from sqlalchemy import select, text

from app import models  # noqa: F401
from app.config import Settings
from app.db.session import create_engine_from_url, create_session_factory
from app.models.platform import Artifact, TaskAttempt, TaskAttemptArtifact, TaskJob
from app.worker.runtime import run_worker_once
from app.platform.task_runtime import claim_next_job, mark_attempt_failed


ROOT_DIR = Path(__file__).resolve().parents[2]
BACKEND_DIR = ROOT_DIR / "backend"
ALEMBIC_BIN = ROOT_DIR / ".venv/bin/alembic"


def reset_public_schema(database_url: str) -> None:
    engine = create_engine_from_url(database_url)

    with engine.begin() as connection:
        connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        connection.execute(text("CREATE SCHEMA public"))

    engine.dispose()


def prepare_database(database_url: str) -> None:
    reset_public_schema(database_url)

    result = subprocess.run(
        [str(ALEMBIC_BIN), "upgrade", "head"],
        cwd=BACKEND_DIR,
        env=os.environ | {"DATABASE_URL": database_url},
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def seed_job(database_url: str, *, status: str = "queued") -> uuid.UUID:
    session_factory = create_session_factory(database_url)

    with session_factory() as session:
        job = TaskJob(
            scene_name="announcement",
            job_type="announcement.phase2_probe",
            trigger_kind="system",
            status=status,
            payload_json={"raw_text": "phase2 probe"},
        )
        session.add(job)
        session.commit()
        session.refresh(job)
        job_id = job.job_id

    return job_id


def load_job(database_url: str, job_id: uuid.UUID) -> TaskJob:
    session_factory = create_session_factory(database_url)

    with session_factory() as session:
        job = session.get(TaskJob, job_id)
        assert job is not None
        return job


def load_attempts(database_url: str, job_id: uuid.UUID) -> list[TaskAttempt]:
    session_factory = create_session_factory(database_url)

    with session_factory() as session:
        attempts = list(
            session.scalars(
                select(TaskAttempt)
                .where(TaskAttempt.job_id == job_id)
                .order_by(TaskAttempt.attempt_no),
            ),
        )

    return attempts


def test_claim_next_job_creates_running_attempt(test_database_url: str) -> None:
    prepare_database(test_database_url)
    job_id = seed_job(test_database_url)
    session_factory = create_session_factory(test_database_url)

    claimed = claim_next_job(session_factory, worker_name="worker-a")

    assert claimed is not None
    assert claimed.job_id == job_id
    assert claimed.attempt_no == 1

    job = load_job(test_database_url, job_id)
    attempts = load_attempts(test_database_url, job_id)

    assert job.status == "running"
    assert job.started_at is not None
    assert len(attempts) == 1
    assert attempts[0].status == "running"
    assert attempts[0].worker_name == "worker-a"


def test_mark_attempt_failed_updates_job_error(test_database_url: str) -> None:
    prepare_database(test_database_url)
    job_id = seed_job(test_database_url)
    session_factory = create_session_factory(test_database_url)
    claimed = claim_next_job(session_factory, worker_name="worker-b")
    assert claimed is not None

    mark_attempt_failed(session_factory, claimed.attempt_id, error_message="boom")

    job = load_job(test_database_url, job_id)
    attempts = load_attempts(test_database_url, job_id)

    assert job.status == "failed"
    assert job.last_error == "boom"
    assert job.finished_at is not None
    assert attempts[0].status == "failed"
    assert attempts[0].error_message == "boom"
    assert attempts[0].finished_at is not None


def test_run_worker_once_marks_job_succeeded(test_database_url: str) -> None:
    prepare_database(test_database_url)
    job_id = seed_job(test_database_url)

    result = run_worker_once(
        Settings(
            database_url=test_database_url,
            artifact_root="./backend/.runtime/artifacts",
            runtime_heartbeat_interval_seconds=10,
            runtime_heartbeat_stale_seconds=30,
        ),
        worker_name="worker-c",
    )

    assert result.processed is True
    assert result.job_id == job_id

    job = load_job(test_database_url, job_id)
    attempts = load_attempts(test_database_url, job_id)

    assert job.status == "succeeded"
    assert job.finished_at is not None
    assert len(attempts) == 1
    assert attempts[0].status == "succeeded"
    assert attempts[0].finished_at is not None


def test_run_worker_once_cleans_artifact_when_completion_step_fails(
    test_database_url: str,
    tmp_path: Path,
    monkeypatch,
) -> None:
    prepare_database(test_database_url)
    job_id = seed_job(test_database_url)
    session_factory = create_session_factory(test_database_url)

    def fail_mark_attempt_succeeded(*args, **kwargs):
        raise RuntimeError("mark succeeded failed")

    monkeypatch.setattr(
        "app.worker.runtime.mark_attempt_succeeded",
        fail_mark_attempt_succeeded,
    )

    with pytest.raises(RuntimeError, match="mark succeeded failed") as exc_info:
        run_worker_once(
            Settings(
                database_url=test_database_url,
                artifact_root=str(tmp_path),
                runtime_heartbeat_interval_seconds=10,
                runtime_heartbeat_stale_seconds=30,
            ),
            worker_name="worker-d",
        )

    job = load_job(test_database_url, job_id)
    attempts = load_attempts(test_database_url, job_id)
    with session_factory() as session:
        artifacts = list(session.scalars(select(Artifact)))
        links = list(session.scalars(select(TaskAttemptArtifact)))

    assert job.status == "failed"
    assert attempts[0].status == "failed"
    assert artifacts == []
    assert links == []
    assert list(tmp_path.rglob("*")) == []


def test_run_worker_once_preserves_original_failure_when_cleanup_fails(
    test_database_url: str,
    tmp_path: Path,
    monkeypatch,
) -> None:
    prepare_database(test_database_url)
    job_id = seed_job(test_database_url)

    def fail_mark_attempt_succeeded(*args, **kwargs):
        raise RuntimeError("mark succeeded failed")

    def fail_delete_artifact(*args, **kwargs):
        raise RuntimeError("artifact cleanup failed")

    monkeypatch.setattr(
        "app.worker.runtime.mark_attempt_succeeded",
        fail_mark_attempt_succeeded,
    )
    monkeypatch.setattr(
        "app.worker.runtime.delete_artifact",
        fail_delete_artifact,
    )

    with pytest.raises(RuntimeError, match="mark succeeded failed") as exc_info:
        run_worker_once(
            Settings(
                database_url=test_database_url,
                artifact_root=str(tmp_path),
                runtime_heartbeat_interval_seconds=10,
                runtime_heartbeat_stale_seconds=30,
            ),
            worker_name="worker-e",
        )

    job = load_job(test_database_url, job_id)
    attempts = load_attempts(test_database_url, job_id)

    assert job.status == "failed"
    assert attempts[0].status == "failed"
    assert job.last_error == "mark succeeded failed"
    assert attempts[0].error_message == "mark succeeded failed"
    assert exc_info.value.__notes__ == ["artifact cleanup failed: artifact cleanup failed"]
