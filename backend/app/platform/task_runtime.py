from __future__ import annotations

"""Phase 2 task runtime service."""

from dataclasses import dataclass
from datetime import datetime, timezone
import uuid

from sqlalchemy import func, select
from sqlalchemy.orm import sessionmaker

from app.models.platform import TaskAttempt, TaskJob


@dataclass(frozen=True)
class ClaimedTaskAttempt:
    job_id: uuid.UUID
    attempt_id: uuid.UUID
    attempt_no: int
    scene_name: str
    job_type: str
    payload_json: dict[str, object]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _next_attempt_no(session, job_id: uuid.UUID) -> int:
    next_attempt_no = session.scalar(
        select(func.coalesce(func.max(TaskAttempt.attempt_no), 0) + 1).where(
            TaskAttempt.job_id == job_id,
        ),
    )

    assert next_attempt_no is not None
    return int(next_attempt_no)


def claim_next_job(
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
            .with_for_update(skip_locked=True),
        )

        if job is None:
            return None

        current_time = _now()
        attempt = TaskAttempt(
            job_id=job.job_id,
            attempt_no=_next_attempt_no(session, job.job_id),
            status="running",
            worker_name=worker_name,
            started_at=current_time,
        )
        job.status = "running"
        job.started_at = current_time
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


def _load_attempt_with_job(session, attempt_id: uuid.UUID) -> TaskAttempt:
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
    current_time = _now()

    with session_factory() as session, session.begin():
        attempt = _load_attempt_with_job(session, attempt_id)
        job = attempt.job

        attempt.status = "failed"
        attempt.error_message = error_message
        attempt.finished_at = current_time

        job.status = "failed"
        job.last_error = error_message
        job.finished_at = current_time
        job.updated_at = current_time


def mark_attempt_succeeded(
    session_factory: sessionmaker,
    attempt_id: uuid.UUID,
) -> None:
    current_time = _now()

    with session_factory() as session, session.begin():
        attempt = _load_attempt_with_job(session, attempt_id)
        job = attempt.job

        attempt.status = "succeeded"
        attempt.error_message = None
        attempt.finished_at = current_time

        job.status = "succeeded"
        job.last_error = None
        job.finished_at = current_time
        job.updated_at = current_time
