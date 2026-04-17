from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AnnouncementRun, AnnouncementSource, TaskJob


def create_announcement_run(
    session: Session,
    *,
    input_mode: str,
    source_url: str,
) -> AnnouncementRun:
    if input_mode != "url":
        raise ValueError(f"暂不支持的公告输入模式: {input_mode}")

    job = TaskJob(
        scene_name="announcement",
        job_type="announcement_manual_extract",
        trigger_kind="manual",
        status="queued",
        payload_json={
            "input_mode": input_mode,
            "source_url": source_url,
        },
    )
    session.add(job)
    session.flush()

    run = AnnouncementRun(
        job_id=job.job_id,
        entry_mode="manual_url",
        status="queued",
        stage="fetch_source",
        input_snapshot_json={
            "input_mode": input_mode,
            "source_url": source_url,
        },
        summary_json={},
    )
    session.add(run)
    session.flush()
    return run


def list_announcement_sources(session: Session) -> list[AnnouncementSource]:
    return list(
        session.execute(
            select(AnnouncementSource).order_by(
                AnnouncementSource.created_at,
                AnnouncementSource.source_id,
            )
        ).scalars()
    )


def create_run_now_job(
    session: Session,
    *,
    source_id,
) -> TaskJob | None:
    source = session.get(AnnouncementSource, source_id)
    if source is None:
        return None

    job = TaskJob(
        scene_name="announcement",
        job_type="announcement_monitor_fetch",
        trigger_kind="manual",
        status="queued",
        payload_json={
            "source_id": str(source.source_id),
        },
    )
    session.add(job)
    session.flush()
    return job
