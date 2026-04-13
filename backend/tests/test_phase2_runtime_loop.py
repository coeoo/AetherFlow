from __future__ import annotations

import os
from pathlib import Path
import subprocess
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select, text

from app import models  # noqa: F401
from app.config import Settings
from app.db.session import create_engine_from_url, create_session_factory
from app.main import create_app
from app.models.platform import Artifact, RuntimeHeartbeat, TaskAttemptArtifact, TaskJob
from app.scheduler.runtime import run_scheduler_once
from app.worker.runtime import run_worker_once


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


def seed_job(database_url: str) -> uuid.UUID:
    session_factory = create_session_factory(database_url)

    with session_factory() as session:
        job = TaskJob(
            scene_name="announcement",
            job_type="announcement.phase2_probe",
            trigger_kind="system",
            status="queued",
            payload_json={"raw_text": "phase2 probe"},
        )
        session.add(job)
        session.commit()
        session.refresh(job)
        job_id = job.job_id

    return job_id


def test_worker_once_processes_seeded_job_and_creates_artifact(
    test_database_url: str,
    tmp_path: Path,
) -> None:
    prepare_database(test_database_url)
    job_id = seed_job(test_database_url)

    result = run_worker_once(
        Settings(
            database_url=test_database_url,
            artifact_root=str(tmp_path),
            runtime_heartbeat_interval_seconds=10,
            runtime_heartbeat_stale_seconds=30,
        ),
        worker_name="worker-e2e",
    )

    assert result.processed is True
    assert result.job_id == job_id

    session_factory = create_session_factory(test_database_url)
    with session_factory() as session:
        job = session.get(TaskJob, job_id)
        assert job is not None
        links = list(session.scalars(select(TaskAttemptArtifact)))
        artifacts = list(session.scalars(select(Artifact)))

    assert job.status == "succeeded"
    assert len(links) == 1
    assert len(artifacts) == 1
    assert Path(artifacts[0].storage_path).exists()


def test_scheduler_once_updates_heartbeat_and_summary(
    test_database_url: str,
    tmp_path: Path,
    monkeypatch,
) -> None:
    prepare_database(test_database_url)

    run_scheduler_once(
        Settings(
            database_url=test_database_url,
            artifact_root=str(tmp_path),
            runtime_heartbeat_interval_seconds=10,
            runtime_heartbeat_stale_seconds=30,
        ),
        instance_name="scheduler-e2e",
    )

    session_factory = create_session_factory(test_database_url)
    with session_factory() as session:
        heartbeat = session.scalar(
            select(RuntimeHeartbeat).where(RuntimeHeartbeat.role == "scheduler"),
        )

    assert heartbeat is not None
    assert heartbeat.instance_name == "scheduler-e2e"

    monkeypatch.setenv("DATABASE_URL", test_database_url)
    app = create_app()
    client = TestClient(app)
    response = client.get("/api/v1/platform/health/summary")

    assert response.status_code == 200
    assert response.json()["database"] == "healthy"
    assert response.json()["scheduler"] == "healthy"
