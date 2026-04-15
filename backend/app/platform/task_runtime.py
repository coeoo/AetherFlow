from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from app.models import TaskAttempt, TaskJob


@dataclass(frozen=True)
class ClaimedTaskAttempt:
    job_id: uuid.UUID
    attempt_id: uuid.UUID
    attempt_no: int
    scene_name: str
    job_type: str
    payload_json: dict[str, object]


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _next_attempt_no(session: Session, job_id: uuid.UUID) -> int:
    next_attempt_no = session.scalar(
        select(func.coalesce(func.max(TaskAttempt.attempt_no), 0) + 1).where(
            TaskAttempt.job_id == job_id
        )
    )
    assert next_attempt_no is not None
    return int(next_attempt_no)


def _claim_next_job_from_session(
    session: Session,
    *,
    scene_name: str,
    worker_name: str,
) -> TaskAttempt | None:
    job = (
        session.execute(
            select(TaskJob)
            .where(TaskJob.scene_name == scene_name, TaskJob.status == "queued")
            .order_by(TaskJob.created_at, TaskJob.job_id)
            .with_for_update(skip_locked=True)
        )
        .scalars()
        .first()
    )
    if job is None:
        return None

    now = _utcnow()
    job.status = "running"
    job.started_at = job.started_at or now
    job.finished_at = None
    job.last_error = None
    job.updated_at = now

    attempt = TaskAttempt(
        job=job,
        attempt_no=_next_attempt_no(session, job.job_id),
        status="running",
        worker_name=worker_name,
        started_at=now,
    )
    session.add(attempt)
    session.flush()
    return attempt


def _claim_next_job_from_factory(
    session_factory: sessionmaker,
    *,
    worker_name: str,
) -> ClaimedTaskAttempt | None:
    with session_factory() as session, session.begin():
        job = session.scalar(
            select(TaskJob)
            .where(TaskJob.status == "queued")
            .order_by(TaskJob.created_at, TaskJob.job_id)
            .limit(1)
            .with_for_update(skip_locked=True)
        )
        if job is None:
            return None

        current_time = _utcnow()
        attempt = TaskAttempt(
            job_id=job.job_id,
            attempt_no=_next_attempt_no(session, job.job_id),
            status="running",
            worker_name=worker_name,
            started_at=current_time,
        )
        job.status = "running"
        job.started_at = job.started_at or current_time
        job.finished_at = None
        job.last_error = None
        job.updated_at = current_time
        session.add(attempt)
        session.flush()

        assert attempt.attempt_id is not None
        return ClaimedTaskAttempt(
            job_id=job.job_id,
            attempt_id=attempt.attempt_id,
            attempt_no=attempt.attempt_no,
            scene_name=job.scene_name,
            job_type=job.job_type,
            payload_json=dict(job.payload_json),
        )


def claim_next_job(
    session_or_factory: Session | sessionmaker,
    *,
    worker_name: str,
    scene_name: str | None = None,
) -> TaskAttempt | ClaimedTaskAttempt | None:
    if isinstance(session_or_factory, Session):
        if scene_name is None:
            raise ValueError("基于 Session claim task 时必须提供 scene_name")
        return _claim_next_job_from_session(
            session_or_factory,
            scene_name=scene_name,
            worker_name=worker_name,
        )

    return _claim_next_job_from_factory(
        session_or_factory,
        worker_name=worker_name,
    )


def finish_attempt_success(session: Session, *, attempt: TaskAttempt) -> None:
    now = _utcnow()
    attempt.status = "succeeded"
    attempt.finished_at = now
    attempt.error_message = None

    job = attempt.job or session.get(TaskJob, attempt.job_id)
    if job is None:
        return
    job.status = "succeeded"
    job.finished_at = now
    job.updated_at = now
    job.last_error = None


def finish_attempt_failure(
    session: Session,
    *,
    attempt: TaskAttempt,
    error_message: str,
) -> None:
    now = _utcnow()
    attempt.status = "failed"
    attempt.finished_at = now
    attempt.error_message = error_message

    job = attempt.job or session.get(TaskJob, attempt.job_id)
    if job is None:
        return
    job.status = "failed"
    job.finished_at = now
    job.updated_at = now
    job.last_error = error_message


def _load_attempt_with_job(session: Session, attempt_id: uuid.UUID) -> TaskAttempt:
    attempt = session.get(TaskAttempt, attempt_id)
    if attempt is None:
        raise ValueError(f"未找到 task_attempt: {attempt_id}")
    return attempt


def mark_attempt_failed(
    session_factory: sessionmaker,
    attempt_id: uuid.UUID,
    *,
    error_message: str,
) -> None:
    with session_factory() as session, session.begin():
        attempt = _load_attempt_with_job(session, attempt_id)
        finish_attempt_failure(session, attempt=attempt, error_message=error_message)


def mark_attempt_succeeded(session_factory: sessionmaker, attempt_id: uuid.UUID) -> None:
    with session_factory() as session, session.begin():
        attempt = _load_attempt_with_job(session, attempt_id)
        finish_attempt_success(session, attempt=attempt)
