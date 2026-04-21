import os
from pathlib import Path
import sys
import uuid

BACKEND_DIR = Path(__file__).resolve().parents[1]
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from app import models  # noqa: F401
from app.db.base import Base
from app.db.session import create_engine_from_url, create_session_factory
from app.main import create_app
from app.models import CVERun, TaskJob


@pytest.fixture(scope="session")
def test_database_url() -> str:
    database_url = os.environ.get("TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("缺少 TEST_DATABASE_URL，跳过依赖 PostgreSQL 的测试。")

    return database_url


def reset_database(database_url: str) -> None:
    _reset_cached_db_factories(database_url)
    engine = create_engine_from_url(database_url)
    try:
        with engine.begin() as connection:
            connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
            connection.execute(text("CREATE SCHEMA public"))
            connection.execute(text("CREATE EXTENSION IF NOT EXISTS pgcrypto"))
        Base.metadata.create_all(engine)
    finally:
        engine.dispose()
        _reset_cached_db_factories(database_url)


def _reset_cached_db_factories(database_url: str) -> None:
    # 测试会反复重建 public schema，清掉缓存的 engine/session factory 可以避免跨用例复用旧连接状态。
    try:
        create_engine_from_url(database_url).dispose()
    except Exception:
        pass
    create_session_factory.cache_clear()
    create_engine_from_url.cache_clear()


@pytest.fixture()
def db_session(test_database_url: str) -> Session:
    reset_database(test_database_url)
    session_factory = create_session_factory(test_database_url)
    session = session_factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client(
    db_session: Session, monkeypatch: pytest.MonkeyPatch, test_database_url: str
) -> TestClient:
    monkeypatch.setenv("DATABASE_URL", test_database_url)
    monkeypatch.delenv("AETHERFLOW_DATABASE_URL", raising=False)
    with TestClient(create_app()) as test_client:
        yield test_client


@pytest.fixture()
def seeded_cve_run(db_session: Session) -> CVERun:
    job = TaskJob(
        job_id=uuid.uuid4(),
        scene_name="cve",
        job_type="cve_patch_agent_graph",
        trigger_kind="manual",
        status="queued",
        payload_json={},
    )
    db_session.add(job)
    db_session.flush()

    run = CVERun(
        job_id=job.job_id,
        cve_id="CVE-2024-3094",
        status="queued",
        phase="resolve_seeds",
        summary_json={},
    )
    db_session.add(run)
    db_session.commit()
    db_session.refresh(run)
    return run
