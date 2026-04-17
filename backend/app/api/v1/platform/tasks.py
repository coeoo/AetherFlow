from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Query

from app.config import load_settings
from app.db.session import create_session_factory
from app.platform.tasks import get_platform_task_detail, list_platform_tasks, requeue_failed_task

router = APIRouter(prefix="/api/v1/platform", tags=["platform"])


@router.get("/tasks")
def get_tasks(
    *,
    scene_name: str | None = Query(default=None),
    status: str | None = Query(default=None),
    trigger_kind: str | None = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
) -> dict[str, object]:
    settings = load_settings()
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        payload = list_platform_tasks(
            session,
            scene_name=scene_name,
            status=status,
            trigger_kind=trigger_kind,
            page=page,
            page_size=page_size,
        )

    return {
        "code": 0,
        "message": "success",
        "data": payload,
    }


@router.get("/tasks/{job_id}")
def get_task(job_id: UUID) -> dict[str, object]:
    settings = load_settings()
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        detail = get_platform_task_detail(session, job_id=job_id)
        if detail is None:
            raise HTTPException(status_code=404, detail="任务不存在")

    return {
        "code": 0,
        "message": "success",
        "data": detail,
    }


@router.post("/tasks/{job_id}/retry")
def retry_task(job_id: UUID) -> dict[str, object]:
    settings = load_settings()
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        try:
            payload = requeue_failed_task(session, job_id=job_id)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        if payload is None:
            raise HTTPException(status_code=404, detail="任务不存在")
        session.commit()

    return {
        "code": 0,
        "message": "success",
        "data": payload,
    }
