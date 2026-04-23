import os
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import select, text

from app import models  # noqa: F401
from app.db.base import Base
from app.db.session import create_engine_from_url, create_session_factory
from app.models import CVERun, TaskAttempt, TaskJob
from app.platform.task_runtime import (
    claim_next_job,
    finish_attempt_failure,
    finish_attempt_success,
)
from app.worker.runtime import process_once


def _get_test_database_url() -> str:
    database_url = os.environ.get("TEST_DATABASE_URL")
    if not database_url:
        pytest.skip("缺少 TEST_DATABASE_URL，跳过 PostgreSQL 测试。")
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


def _create_job(
    session, *, scene_name: str, status: str, job_type: str = "cve_patch_agent_graph"
) -> TaskJob:
    job = TaskJob(
        job_id=uuid.uuid4(),
        scene_name=scene_name,
        job_type=job_type,
        trigger_kind="manual",
        status=status,
        payload_json={},
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    session.add(job)
    session.flush()
    return job


def test_process_once_rejects_legacy_cve_fast_first_job_type(monkeypatch) -> None:
    database_url = _get_test_database_url()
    _reset_database(database_url)
    session_factory = create_session_factory(database_url)
    legacy_job_type = "cve_patch_" + "fast_first"

    with session_factory() as session:
        job = _create_job(
            session,
            scene_name="cve",
            status="queued",
            job_type=legacy_job_type,
        )
        run = CVERun(
            job_id=job.job_id,
            cve_id="CVE-2024-3094",
            status="queued",
            phase="resolve_seeds",
            summary_json={},
        )
        session.add(run)
        session.commit()

    def _fail_if_invoked(session, *, run_id) -> None:
        raise AssertionError(f"旧 fast_first 任务不应继续执行 run: {run_id}")

    monkeypatch.setattr("app.worker.runtime.execute_cve_run", _fail_if_invoked)

    processed = process_once(session_factory, worker_name="worker-legacy")
    assert processed is True

    with session_factory() as session:
        reloaded_job = session.get(TaskJob, job.job_id)
        assert reloaded_job is not None
        assert reloaded_job.status == "failed"
        assert reloaded_job.last_error == f"不支持的任务类型: cve/{legacy_job_type}"


def test_claim_next_job_only_returns_matching_queued_job() -> None:
    database_url = _get_test_database_url()
    _reset_database(database_url)
    session_factory = create_session_factory(database_url)

    with session_factory() as session:
        job_cve = _create_job(session, scene_name="cve", status="queued")
        job_other = _create_job(session, scene_name="announcement", status="queued")
        session.commit()

        attempt = claim_next_job(session, scene_name="cve", worker_name="worker-1")
        session.commit()

        assert attempt is not None
        assert attempt.job_id == job_cve.job_id
        reloaded_other = session.get(TaskJob, job_other.job_id)
        assert reloaded_other is not None
        assert reloaded_other.status == "queued"


def test_claim_next_job_creates_running_attempt_and_marks_job_running() -> None:
    database_url = _get_test_database_url()
    _reset_database(database_url)
    session_factory = create_session_factory(database_url)

    with session_factory() as session:
        job = _create_job(session, scene_name="cve", status="queued")
        session.commit()

        attempt = claim_next_job(session, scene_name="cve", worker_name="worker-1")
        session.commit()

        assert attempt is not None
        reloaded_job = session.get(TaskJob, job.job_id)
        assert reloaded_job is not None
        assert reloaded_job.status == "running"
        assert reloaded_job.started_at is not None

        reloaded_attempt = session.get(TaskAttempt, attempt.attempt_id)
        assert reloaded_attempt is not None
        assert reloaded_attempt.status == "running"
        assert reloaded_attempt.worker_name == "worker-1"
        assert reloaded_attempt.attempt_no == 1


def test_finish_attempt_success_updates_job_terminal_state() -> None:
    database_url = _get_test_database_url()
    _reset_database(database_url)
    session_factory = create_session_factory(database_url)

    with session_factory() as session:
        _create_job(session, scene_name="cve", status="queued")
        session.commit()

        attempt = claim_next_job(session, scene_name="cve", worker_name="worker-1")
        assert attempt is not None
        finish_attempt_success(session, attempt=attempt)
        session.commit()

        reloaded_attempt = session.get(TaskAttempt, attempt.attempt_id)
        assert reloaded_attempt is not None
        assert reloaded_attempt.status == "succeeded"
        assert reloaded_attempt.finished_at is not None

        reloaded_job = session.get(TaskJob, attempt.job_id)
        assert reloaded_job is not None
        assert reloaded_job.status == "succeeded"
        assert reloaded_job.finished_at is not None
        assert reloaded_job.last_error is None


def test_finish_attempt_failure_preserves_error_message() -> None:
    database_url = _get_test_database_url()
    _reset_database(database_url)
    session_factory = create_session_factory(database_url)

    with session_factory() as session:
        _create_job(session, scene_name="cve", status="queued")
        session.commit()

        attempt = claim_next_job(session, scene_name="cve", worker_name="worker-1")
        assert attempt is not None
        finish_attempt_failure(session, attempt=attempt, error_message="worker failed")
        session.commit()

        reloaded_attempt = session.get(TaskAttempt, attempt.attempt_id)
        assert reloaded_attempt is not None
        assert reloaded_attempt.status == "failed"
        assert reloaded_attempt.error_message == "worker failed"

        reloaded_job = session.get(TaskJob, attempt.job_id)
        assert reloaded_job is not None
        assert reloaded_job.status == "failed"
        assert reloaded_job.last_error == "worker failed"
