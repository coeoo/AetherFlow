from __future__ import annotations

import os
from pathlib import Path
import subprocess
import uuid

import pytest
from sqlalchemy import select, text

from app import models  # noqa: F401
from app.db.session import create_engine_from_url, create_session_factory
from app.models.platform import Artifact, TaskAttempt, TaskAttemptArtifact, TaskJob
from app.platform.artifact_store import read_artifact_content, write_text_artifact


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
            worker_name="artifact-test",
        )
        session.add(attempt)
        session.commit()
        session.refresh(attempt)

        return attempt.attempt_id


def test_write_text_artifact_creates_file_and_metadata(
    test_database_url: str,
    tmp_path: Path,
) -> None:
    prepare_database(test_database_url)
    attempt_id = seed_running_attempt(test_database_url)
    session_factory = create_session_factory(test_database_url)

    artifact = write_text_artifact(
        session_factory,
        attempt_id=attempt_id,
        scene_name="announcement",
        artifact_root=tmp_path,
        content="hello artifact",
        artifact_kind="text",
    )

    stored_path = Path(artifact.storage_path)
    assert stored_path.exists()
    assert artifact.artifact_kind == "text"
    assert artifact.checksum
    assert read_artifact_content(session_factory, artifact.artifact_id) == b"hello artifact"


def test_attempt_artifact_relation_is_persisted(
    test_database_url: str,
    tmp_path: Path,
) -> None:
    prepare_database(test_database_url)
    attempt_id = seed_running_attempt(test_database_url)
    session_factory = create_session_factory(test_database_url)

    artifact = write_text_artifact(
        session_factory,
        attempt_id=attempt_id,
        scene_name="announcement",
        artifact_root=tmp_path,
        content="hello relation",
        artifact_kind="text",
    )

    with session_factory() as session:
        links = list(session.scalars(select(TaskAttemptArtifact)))
        artifacts = list(session.scalars(select(Artifact)))

    assert len(links) == 1
    assert links[0].attempt_id == attempt_id
    assert links[0].artifact_id == artifact.artifact_id
    assert len(artifacts) == 1


def test_write_text_artifact_cleans_file_when_db_persist_fails(
    test_database_url: str,
    tmp_path: Path,
    monkeypatch,
) -> None:
    prepare_database(test_database_url)
    attempt_id = seed_running_attempt(test_database_url)
    session_factory = create_session_factory(test_database_url)

    def fail_persist(*args, **kwargs):
        raise RuntimeError("db persist failed")

    monkeypatch.setattr(
        "app.platform.artifact_store._persist_artifact_records",
        fail_persist,
    )

    with pytest.raises(RuntimeError, match="db persist failed"):
        write_text_artifact(
            session_factory,
            attempt_id=attempt_id,
            scene_name="announcement",
            artifact_root=tmp_path,
            content="hello cleanup",
            artifact_kind="text",
        )

    assert list(tmp_path.rglob("*")) == []
