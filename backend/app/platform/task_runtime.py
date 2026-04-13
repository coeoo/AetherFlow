from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import TaskAttempt, TaskJob


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def claim_next_job(
    session: Session, *, scene_name: str, worker_name: str
) -> TaskAttempt | None:
    job = (
        session.execute(
            select(TaskJob)
            .where(TaskJob.scene_name == scene_name, TaskJob.status == "queued")
            .order_by(TaskJob.created_at)
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
    job.updated_at = now

    attempt_no = session.execute(
        select(func.coalesce(func.max(TaskAttempt.attempt_no), 0)).where(
            TaskAttempt.job_id == job.job_id
        )
    ).scalar_one()

    attempt = TaskAttempt(
        job=job,
        attempt_no=int(attempt_no) + 1,
        status="running",
        worker_name=worker_name,
        started_at=now,
    )
    session.add(attempt)
    session.flush()
    return attempt


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
    session: Session, *, attempt: TaskAttempt, error_message: str
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
