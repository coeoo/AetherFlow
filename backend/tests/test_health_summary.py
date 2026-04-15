from __future__ import annotations

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import subprocess

from fastapi.testclient import TestClient
from sqlalchemy import text

from app.config import Settings
from app.db.session import create_engine_from_url, create_session_factory
from app.main import create_app
from app.platform.health_summary import collect_health_summary
from app.platform.runtime_heartbeats import upsert_runtime_heartbeat
from app.scheduler.runtime import run_scheduler_once


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


def build_settings(database_url: str) -> Settings:
    return Settings(
        database_url=database_url,
        artifact_root="./backend/.runtime/artifacts",
        runtime_heartbeat_interval_seconds=10,
        runtime_heartbeat_stale_seconds=30,
    )


def test_health_summary_reports_database_healthy(test_database_url: str) -> None:
    prepare_database(test_database_url)

    summary = collect_health_summary(build_settings(test_database_url))

    assert summary["api"] == "healthy"
    assert summary["database"] == "healthy"
    assert summary["worker"] == "down"
    assert summary["scheduler"] == "down"
    assert "enabled_sources" not in summary
    assert "enabled_channels" not in summary


def test_worker_heartbeat_becomes_degraded_after_stale_threshold(
    test_database_url: str,
) -> None:
    prepare_database(test_database_url)
    settings = build_settings(test_database_url)
    session_factory = create_session_factory(test_database_url)
    stale_time = datetime.now(timezone.utc) - timedelta(seconds=31)

    upsert_runtime_heartbeat(
        session_factory,
        role="worker",
        instance_name="worker-stale",
        heartbeat_at=stale_time,
    )

    summary = collect_health_summary(
        settings,
        current_time=datetime.now(timezone.utc),
    )

    assert summary["worker"] == "degraded"


def test_scheduler_once_updates_heartbeat_and_summary(
    test_database_url: str,
    monkeypatch,
) -> None:
    prepare_database(test_database_url)
    settings = build_settings(test_database_url)

    run_scheduler_once(settings, instance_name="scheduler-a")

    summary = collect_health_summary(settings)
    assert summary["scheduler"] == "healthy"

    monkeypatch.setenv("DATABASE_URL", test_database_url)
    client = TestClient(create_app())
    response = client.get("/api/v1/platform/health/summary")

    assert response.status_code == 200
    assert response.json()["scheduler"] == "healthy"
    assert set(response.json()) == {"api", "database", "worker", "scheduler", "notes"}
