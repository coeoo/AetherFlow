from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException

from app.announcements.service import create_run_now_job, list_announcement_sources
from app.config import load_settings
from app.db.session import create_session_factory

router = APIRouter(prefix="/api/v1/announcements", tags=["announcements"])


@router.get("/sources")
def get_sources() -> dict[str, object]:
    settings = load_settings()
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        sources = list_announcement_sources(session)

    return {
        "code": 0,
        "message": "success",
        "data": [
            {
                "source_id": str(source.source_id),
                "name": source.name,
                "source_type": source.source_type,
                "enabled": source.enabled,
                "schedule_cron": source.schedule_cron,
                "config": dict(source.config_json or {}),
                "delivery_policy": dict(source.delivery_policy_json or {}),
            }
            for source in sources
        ],
    }


@router.post("/sources/{source_id}/run-now")
def run_source_now(source_id: UUID) -> dict[str, object]:
    settings = load_settings()
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        job = create_run_now_job(session, source_id=source_id)
        if job is None:
            raise HTTPException(status_code=404, detail="公告监控源不存在")
        session.commit()
        session.refresh(job)

    return {
        "code": 0,
        "message": "success",
        "data": {
            "job_id": str(job.job_id),
            "source_id": str(source_id),
            "job_type": job.job_type,
            "status": job.status,
        },
    }
