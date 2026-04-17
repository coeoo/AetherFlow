import os
import subprocess
from pathlib import Path
import sys

from sqlalchemy import create_engine, inspect, text

from app.db.base import Base
from app import models  # noqa: F401


ROOT_DIR = Path(__file__).resolve().parents[2]
BACKEND_DIR = ROOT_DIR / "backend"
PYTHON_BIN = Path(sys.executable)


def reset_public_schema(database_url: str) -> None:
    engine = create_engine(database_url, future=True)

    with engine.begin() as connection:
        connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        connection.execute(text("CREATE SCHEMA public"))

    engine.dispose()


def test_alembic_upgrade_head(test_database_url: str) -> None:
    reset_public_schema(test_database_url)

    env = os.environ | {"DATABASE_URL": test_database_url}
    result = subprocess.run(
        [str(PYTHON_BIN), "-m", "alembic", "upgrade", "head"],
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr

    engine = create_engine(test_database_url, future=True)
    try:
        table_names = set(inspect(engine).get_table_names())
    finally:
        engine.dispose()

    assert {
        "alembic_version",
        "task_jobs",
        "task_attempts",
        "task_attempt_artifacts",
        "delivery_targets",
        "delivery_records",
        "artifacts",
        "runtime_heartbeats",
        "source_fetch_records",
        "cve_runs",
        "cve_patch_artifacts",
        "announcement_sources",
        "announcement_runs",
        "announcement_documents",
        "announcement_intelligence_packages",
    }.issubset(table_names)


def test_platform_metadata_matches_bootstrap_contract() -> None:
    task_jobs = Base.metadata.tables["task_jobs"]
    task_attempts = Base.metadata.tables["task_attempts"]
    delivery_records = Base.metadata.tables["delivery_records"]

    check_constraint_names = {constraint.name for constraint in task_jobs.constraints}
    assert "ck_task_jobs_scene_name" in check_constraint_names

    task_job_index_names = {index.name for index in task_jobs.indexes}
    assert {
        "idx_task_jobs_scene_status",
        "idx_task_jobs_created_at",
        "idx_task_jobs_trigger_kind",
    }.issubset(task_job_index_names)

    unique_constraint_names = {constraint.name for constraint in task_attempts.constraints}
    assert "uq_task_attempts_job_attempt_no" in unique_constraint_names

    assert "delivery_kind" in delivery_records.c
    assert "scheduled_at" in delivery_records.c
    assert "updated_at" in delivery_records.c


def test_alembic_incremental_upgrade_adds_delivery_record_columns(test_database_url: str) -> None:
    reset_public_schema(test_database_url)

    env = os.environ | {"DATABASE_URL": test_database_url}
    upgrade_base = subprocess.run(
        [str(PYTHON_BIN), "-m", "alembic", "upgrade", "20260415_0003"],
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
    )
    assert upgrade_base.returncode == 0, upgrade_base.stderr

    engine = create_engine(test_database_url, future=True)
    try:
        base_columns = {column["name"] for column in inspect(engine).get_columns("delivery_records")}
    finally:
        engine.dispose()

    assert "delivery_kind" not in base_columns
    assert "scheduled_at" not in base_columns
    assert "updated_at" not in base_columns

    upgrade_head = subprocess.run(
        [str(PYTHON_BIN), "-m", "alembic", "upgrade", "head"],
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
    )
    assert upgrade_head.returncode == 0, upgrade_head.stderr

    engine = create_engine(test_database_url, future=True)
    try:
        upgraded_columns = {column["name"] for column in inspect(engine).get_columns("delivery_records")}
    finally:
        engine.dispose()

    assert {"delivery_kind", "scheduled_at", "updated_at"}.issubset(upgraded_columns)
