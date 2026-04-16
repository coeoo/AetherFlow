from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.announcements.delivery_service import create_announcement_delivery_records
from app.announcements.detail_service import get_announcement_run_detail
from app.announcements.service import create_announcement_run
from app.config import load_settings
from app.db.session import create_session_factory

router = APIRouter(prefix="/api/v1/announcements", tags=["announcements"])


class CreateAnnouncementRunRequest(BaseModel):
    input_mode: str = Field(pattern=r"^url$")
    source_url: str = Field(min_length=1)


class CreateAnnouncementDeliveriesRequest(BaseModel):
    target_ids: list[UUID] | None = None


def _serialize_run_summary(run) -> dict[str, object]:
    return {
        "run_id": str(run.run_id),
        "entry_mode": run.entry_mode,
        "status": run.status,
        "stage": run.stage,
        "input_snapshot": dict(run.input_snapshot_json or {}),
        "summary": dict(run.summary_json or {}),
        "created_at": run.created_at.isoformat(),
    }


@router.post("/runs")
def create_run(payload: CreateAnnouncementRunRequest) -> dict[str, object]:
    settings = load_settings()
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        run = create_announcement_run(
            session,
            input_mode=payload.input_mode,
            source_url=payload.source_url,
        )
        session.commit()
        session.refresh(run)

    return {
        "code": 0,
        "message": "success",
        "data": _serialize_run_summary(run),
    }


@router.get("/runs/{run_id}")
def get_run(run_id: UUID) -> dict[str, object]:
    settings = load_settings()
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        detail = get_announcement_run_detail(session, run_id=run_id)
        if detail is None:
            raise HTTPException(status_code=404, detail="公告运行记录不存在")

    return {
        "code": 0,
        "message": "success",
        "data": detail,
    }


@router.post("/runs/{run_id}/deliveries")
def create_deliveries(
    run_id: UUID,
    payload: CreateAnnouncementDeliveriesRequest,
) -> dict[str, object]:
    settings = load_settings()
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        try:
            result = create_announcement_delivery_records(
                session,
                run_id=run_id,
                target_ids=payload.target_ids,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        session.commit()

    return {
        "code": 0,
        "message": "success",
        "data": result,
    }
