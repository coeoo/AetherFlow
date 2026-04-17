from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException

from app.announcements.service import get_monitor_run_detail, list_monitor_runs
from app.config import load_settings
from app.db.session import create_session_factory

router = APIRouter(prefix="/api/v1/announcements", tags=["announcements"])


@router.get("/monitor-runs")
def get_monitor_runs() -> dict[str, object]:
    settings = load_settings()
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        runs = list_monitor_runs(session)

    return {
        "code": 0,
        "message": "success",
        "data": runs,
    }


@router.get("/monitor-runs/{fetch_id}")
def get_monitor_run(fetch_id: UUID) -> dict[str, object]:
    settings = load_settings()
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        detail = get_monitor_run_detail(session, fetch_id=fetch_id)
        if detail is None:
            raise HTTPException(status_code=404, detail="公告监控批次不存在")

    return {
        "code": 0,
        "message": "success",
        "data": detail,
    }
