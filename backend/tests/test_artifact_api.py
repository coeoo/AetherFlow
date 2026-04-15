from __future__ import annotations

import os
from pathlib import Path
import subprocess
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import text

from app import models  # noqa: F401
from app.main import create_app
from app.db.session import create_engine_from_url, create_session_factory
from app.models.platform import TaskAttempt, TaskJob
from app.platform.artifact_store import write_text_artifact


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


def seed_running_attempt(database_url: str) -> uuid.UUID:
    session_factory = create_session_factory(database_url)

    with session_factory() as session:
        job = TaskJob(
            scene_name="announcement",
            job_type="announcement.phase2_probe",
            trigger_kind="system",
            status="running",
            payload_json={"raw_text": "hello"},
        )
        session.add(job)
        session.flush()
        attempt = TaskAttempt(
            job_id=job.job_id,
            attempt_no=1,
            status="running",
            worker_name="artifact-api-test",
        )
        session.add(attempt)
        session.commit()
        session.refresh(attempt)
        return attempt.attempt_id


def test_get_artifact_metadata_hides_storage_path(
    test_database_url: str,
    tmp_path: Path,
    monkeypatch,
) -> None:
    prepare_database(test_database_url)
    attempt_id = seed_running_attempt(test_database_url)
    session_factory = create_session_factory(test_database_url)
    artifact = write_text_artifact(
        session_factory,
        attempt_id=attempt_id,
        scene_name="announcement",
        artifact_root=tmp_path,
        content="metadata body",
        artifact_kind="text",
    )

    monkeypatch.setenv("DATABASE_URL", test_database_url)
    client = TestClient(create_app())
    response = client.get(f"/api/v1/platform/artifacts/{artifact.artifact_id}")

    assert response.status_code == 200
    payload = response.json()
    assert payload["artifact_id"] == str(artifact.artifact_id)
    assert "storage_path" not in payload


def test_get_artifact_content_returns_text_body(
    test_database_url: str,
    tmp_path: Path,
    monkeypatch,
) -> None:
    prepare_database(test_database_url)
    attempt_id = seed_running_attempt(test_database_url)
    session_factory = create_session_factory(test_database_url)
    artifact = write_text_artifact(
        session_factory,
        attempt_id=attempt_id,
        scene_name="announcement",
        artifact_root=tmp_path,
        content="content body",
        artifact_kind="text",
    )

    monkeypatch.setenv("DATABASE_URL", test_database_url)
    client = TestClient(create_app())
    response = client.get(f"/api/v1/platform/artifacts/{artifact.artifact_id}/content")

    assert response.status_code == 200
    assert response.text == "content body"
