from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AnnouncementRun, CVERun, TaskAttempt, TaskJob


def list_platform_tasks(
    session: Session,
    *,
    scene_name: str | None,
    status: str | None,
    trigger_kind: str | None,
    page: int,
    page_size: int,
) -> dict[str, object]:
    query = select(TaskJob)
    count_query = select(func.count()).select_from(TaskJob)

    if scene_name:
        query = query.where(TaskJob.scene_name == scene_name)
        count_query = count_query.where(TaskJob.scene_name == scene_name)
    if status:
        query = query.where(TaskJob.status == status)
        count_query = count_query.where(TaskJob.status == status)
    if trigger_kind:
        query = query.where(TaskJob.trigger_kind == trigger_kind)
        count_query = count_query.where(TaskJob.trigger_kind == trigger_kind)

    total = int(session.scalar(count_query) or 0)
    offset = (page - 1) * page_size
    jobs = list(
        session.execute(
            query.order_by(TaskJob.created_at.desc(), TaskJob.job_id.desc()).offset(offset).limit(page_size)
        ).scalars()
    )
    run_ids = _load_scene_run_ids(session, [job.job_id for job in jobs])
    last_attempt_times = _load_last_attempt_times(session, [job.job_id for job in jobs])

    return {
        "items": [
            _serialize_task_list_item(
                job,
                scene_run_id=run_ids.get(job.job_id),
                last_attempt_at=last_attempt_times.get(job.job_id),
            )
            for job in jobs
        ],
        "total": total,
        "page": page,
        "page_size": page_size,
    }


def get_platform_task_detail(session: Session, *, job_id: UUID) -> dict[str, object] | None:
    job = session.get(TaskJob, job_id)
    if job is None:
        return None

    scene_run_id = _load_scene_run_ids(session, [job.job_id]).get(job.job_id)
    attempts = list(
        session.execute(
            select(TaskAttempt)
            .where(TaskAttempt.job_id == job.job_id)
            .order_by(TaskAttempt.attempt_no.desc(), TaskAttempt.started_at.desc())
        ).scalars()
    )
    return {
        "job_id": str(job.job_id),
        "scene_name": job.scene_name,
        "job_type": job.job_type,
        "trigger_kind": job.trigger_kind,
        "status": job.status,
        "scene_run_id": str(scene_run_id) if scene_run_id is not None else None,
        "payload_summary": _build_payload_summary(job),
        "last_error": job.last_error,
        "created_at": job.created_at.isoformat(),
        "started_at": job.started_at.isoformat() if job.started_at is not None else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at is not None else None,
        "attempts": [_serialize_attempt(attempt) for attempt in attempts],
    }


def requeue_failed_task(session: Session, *, job_id: UUID) -> dict[str, object] | None:
    job = session.get(TaskJob, job_id)
    if job is None:
        return None
    if job.status != "failed":
        raise ValueError("只有失败态任务允许重排。")

    current_time = datetime.now(timezone.utc)
    job.status = "queued"
    job.started_at = None
    job.finished_at = None
    job.last_error = None
    job.updated_at = current_time
    session.flush()

    return {
        "job_id": str(job.job_id),
        "status": job.status,
        "scene_name": job.scene_name,
        "job_type": job.job_type,
        "trigger_kind": job.trigger_kind,
        "queued_at": current_time.isoformat(),
    }


def list_recent_platform_jobs(session: Session, *, limit: int) -> list[dict[str, object]]:
    jobs = list(
        session.execute(
            select(TaskJob).order_by(TaskJob.created_at.desc(), TaskJob.job_id.desc()).limit(limit)
        ).scalars()
    )
    run_ids = _load_scene_run_ids(session, [job.job_id for job in jobs])
    last_attempt_times = _load_last_attempt_times(session, [job.job_id for job in jobs])
    return [
        _serialize_task_list_item(
            job,
            scene_run_id=run_ids.get(job.job_id),
            last_attempt_at=last_attempt_times.get(job.job_id),
        )
        for job in jobs
    ]


def get_latest_scene_status_by_scene(session: Session) -> dict[str, str]:
    jobs = list(
        session.execute(
            select(TaskJob)
            .order_by(TaskJob.created_at.desc(), TaskJob.job_id.desc())
        ).scalars()
    )

    latest_by_scene: dict[str, str] = {}
    for job in jobs:
        if job.scene_name in latest_by_scene:
            continue
        latest_by_scene[job.scene_name] = _build_scene_status_copy(job)
    return latest_by_scene


def _serialize_task_list_item(
    job: TaskJob,
    *,
    scene_run_id: UUID | None,
    last_attempt_at: datetime | None,
) -> dict[str, object]:
    return {
        "job_id": str(job.job_id),
        "scene_name": job.scene_name,
        "job_type": job.job_type,
        "trigger_kind": job.trigger_kind,
        "status": job.status,
        "scene_run_id": str(scene_run_id) if scene_run_id is not None else None,
        "payload_summary": _build_payload_summary(job),
        "last_error": job.last_error,
        "last_attempt_at": last_attempt_at.isoformat() if last_attempt_at is not None else None,
        "created_at": job.created_at.isoformat(),
        "started_at": job.started_at.isoformat() if job.started_at is not None else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at is not None else None,
    }


def _serialize_attempt(attempt: TaskAttempt) -> dict[str, object]:
    return {
        "attempt_id": str(attempt.attempt_id),
        "attempt_no": attempt.attempt_no,
        "status": attempt.status,
        "worker_name": attempt.worker_name,
        "error_message": attempt.error_message,
        "started_at": attempt.started_at.isoformat(),
        "finished_at": attempt.finished_at.isoformat() if attempt.finished_at is not None else None,
    }


def _build_payload_summary(job: TaskJob) -> dict[str, object]:
    payload = dict(job.payload_json or {})
    if job.scene_name == "cve":
        return {
            "cve_id": payload.get("cve_id"),
        }

    if job.job_type == "announcement_manual_extract":
        return {
            "input_mode": payload.get("input_mode"),
            "source_url": payload.get("source_url"),
        }

    if job.job_type == "announcement_monitor_fetch":
        return {
            "source_id": payload.get("source_id"),
        }

    return payload


def _build_scene_status_copy(job: TaskJob) -> str:
    payload_summary = _build_payload_summary(job)
    if job.scene_name == "cve" and payload_summary.get("cve_id"):
        return f"{payload_summary['cve_id']} · {job.status}"
    if job.scene_name == "announcement" and payload_summary.get("source_url"):
        return f"手动提取 · {job.status}"
    if job.scene_name == "announcement" and payload_summary.get("source_id"):
        return f"监控抓取 · {job.status}"
    return f"最近任务状态：{job.status}"


def _load_last_attempt_times(session: Session, job_ids: list[UUID]) -> dict[UUID, datetime]:
    if not job_ids:
        return {}

    rows = session.execute(
        select(TaskAttempt.job_id, func.max(TaskAttempt.started_at))
        .where(TaskAttempt.job_id.in_(job_ids))
        .group_by(TaskAttempt.job_id)
    ).all()
    return {job_id: last_attempt_at for job_id, last_attempt_at in rows if last_attempt_at is not None}


def _load_scene_run_ids(session: Session, job_ids: list[UUID]) -> dict[UUID, UUID]:
    if not job_ids:
        return {}

    run_ids: dict[UUID, UUID] = {}
    for run in session.execute(select(CVERun).where(CVERun.job_id.in_(job_ids))).scalars():
        run_ids[run.job_id] = run.run_id
    for run in session.execute(select(AnnouncementRun).where(AnnouncementRun.job_id.in_(job_ids))).scalars():
        run_ids[run.job_id] = run.run_id
    return run_ids
