from __future__ import annotations

import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import uuid

import pytest
from sqlalchemy import select, text

from app import models  # noqa: F401
from app.config import load_settings
from app.db.base import Base
from app.db.session import create_engine_from_url, create_session_factory
from app.models import Artifact, TaskAttempt, TaskAttemptArtifact, TaskJob
from app.platform.artifact_store import read_artifact_content, save_text_artifact, write_text_artifact


ROOT_DIR = Path(__file__).resolve().parents[2]
BACKEND_DIR = ROOT_DIR / "backend"
ALEMBIC_BIN = ROOT_DIR / ".venv/bin/alembic"


def _get_test_database_url() -> str:
    database_url = os.environ.get("TEST_DATABASE_URL")
    if not database_url:
        pytest.fail("缺少 TEST_DATABASE_URL，无法运行 PostgreSQL 测试。")
    return database_url


def _reset_database(database_url: str) -> None:
    engine = create_engine_from_url(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
            connection.execute(text("CREATE EXTENSION IF NOT EXISTS pgcrypto"))
        Base.metadata.create_all(engine)
    finally:
        engine.dispose()


def prepare_database(database_url: str) -> None:
    engine = create_engine_from_url(database_url)
    with engine.begin() as connection:
        connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        connection.execute(text("CREATE SCHEMA public"))
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


def test_save_text_artifact_persists_file_and_database_row(monkeypatch) -> None:
    database_url = _get_test_database_url()
    _reset_database(database_url)
    session_factory = create_session_factory(database_url)

    with tempfile.TemporaryDirectory() as temp_root:
        monkeypatch.setenv("AETHERFLOW_ARTIFACT_ROOT", temp_root)
        content = "diff --git a/a.txt b/a.txt\n+hello\n"

        with session_factory() as session:
            artifact = save_text_artifact(
                session,
                scene_name="cve",
                artifact_kind="patch",
                source_url="https://example.com/patch.diff",
                filename_hint="fix.patch",
                content=content,
                content_type="text/x-diff",
                metadata={"origin": "test"},
            )
            session.commit()

        assert Path(artifact.storage_path).exists()
        assert Path(artifact.storage_path).read_text(encoding="utf-8") == content
        assert artifact.metadata_json == {"origin": "test"}
        assert artifact.content_type == "text/x-diff"
        assert artifact.checksum == hashlib.sha256(content.encode("utf-8")).hexdigest()


def test_save_text_artifact_uses_stable_absolute_root(monkeypatch) -> None:
    database_url = _get_test_database_url()
    _reset_database(database_url)
    session_factory = create_session_factory(database_url)

    relative_root = Path(".runtime/test-artifacts")
    monkeypatch.setenv("AETHERFLOW_ARTIFACT_ROOT", str(relative_root))

    repo_root = Path(__file__).resolve().parents[2]
    expected_root = (repo_root / relative_root).resolve()

    try:
        with session_factory() as session:
            artifact = save_text_artifact(
                session,
                scene_name="cve",
                artifact_kind="patch",
                source_url=None,
                filename_hint="note.txt",
                content="ok",
                content_type="text/plain",
                metadata={},
            )
            session.commit()

        settings = load_settings()
        assert Path(settings.artifact_root).is_absolute()
        assert Path(settings.artifact_root).resolve() == expected_root
        assert Path(artifact.storage_path).is_absolute()
        assert Path(artifact.storage_path).resolve().is_relative_to(expected_root)
    finally:
        if expected_root.exists():
            shutil.rmtree(expected_root)


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
