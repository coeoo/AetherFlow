import hashlib
import os
from pathlib import Path
import shutil
import tempfile

import pytest
from sqlalchemy import text

from app import models  # noqa: F401
from app.config import load_settings
from app.db.base import Base
from app.db.session import create_engine_from_url, create_session_factory
from app.platform.artifact_store import save_text_artifact


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
