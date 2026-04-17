from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.config import load_settings
from app.db.session import create_session_factory
from app.platform.delivery_service import (
    create_test_delivery_record,
    create_delivery_target,
    list_delivery_targets,
    list_platform_delivery_records,
    retry_delivery_record,
    schedule_delivery_record,
    send_delivery_record_now,
    update_delivery_target,
)

router = APIRouter(prefix="/api/v1/platform", tags=["platform"])


class CreateDeliveryTargetRequest(BaseModel):
    name: str
    channel_type: str
    enabled: bool = True
    config_json: dict[str, object] = Field(default_factory=dict)


class UpdateDeliveryTargetRequest(BaseModel):
    name: str | None = None
    channel_type: str | None = None
    enabled: bool | None = None
    config_json: dict[str, object] | None = None


class TestDeliveryTargetRequest(BaseModel):
    payload_summary: dict[str, object] = Field(default_factory=dict)


class ScheduleDeliveryRecordRequest(BaseModel):
    scheduled_at: datetime


def _build_session_factory():
    settings = load_settings()
    if not settings.database_url:
        raise HTTPException(status_code=500, detail="缺少数据库连接配置。")
    return create_session_factory(settings.database_url)


@router.get("/delivery-records")
def get_delivery_records(
    scene_name: str | None = Query(default=None),
    status: str | None = Query(default=None),
    channel_type: str | None = Query(default=None),
    delivery_kind: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
) -> dict[str, object]:
    session_factory = _build_session_factory()
    with session_factory() as session:
        records = list_platform_delivery_records(
            session,
            scene_name=scene_name,
            status=status,
            channel_type=channel_type,
            delivery_kind=delivery_kind,
            limit=limit,
        )

    return {
        "code": 0,
        "message": "success",
        "data": records,
    }


@router.get("/delivery-targets")
def get_delivery_targets() -> dict[str, object]:
    session_factory = _build_session_factory()
    with session_factory() as session:
        targets = list_delivery_targets(session)

    return {
        "code": 0,
        "message": "success",
        "data": targets,
    }


@router.post("/delivery-targets")
def post_delivery_target(payload: CreateDeliveryTargetRequest) -> dict[str, object]:
    session_factory = _build_session_factory()
    with session_factory() as session:
        try:
            target = create_delivery_target(
                session,
                name=payload.name,
                channel_type=payload.channel_type,
                enabled=payload.enabled,
                config_json=payload.config_json,
            )
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        session.commit()

    return {
        "code": 0,
        "message": "success",
        "data": target,
    }


@router.patch("/delivery-targets/{target_id}")
def patch_delivery_target(
    target_id: str,
    payload: UpdateDeliveryTargetRequest,
) -> dict[str, object]:
    session_factory = _build_session_factory()
    with session_factory() as session:
        try:
            target = update_delivery_target(
                session,
                target_id=target_id,
                name=payload.name,
                channel_type=payload.channel_type,
                enabled=payload.enabled,
                config_json=payload.config_json,
            )
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        session.commit()

    return {
        "code": 0,
        "message": "success",
        "data": target,
    }


@router.post("/delivery-targets/{target_id}/test")
def post_delivery_target_test(
    target_id: str,
    payload: TestDeliveryTargetRequest,
) -> dict[str, object]:
    session_factory = _build_session_factory()
    with session_factory() as session:
        try:
            record = create_test_delivery_record(
                session,
                target_id=target_id,
                payload_summary=payload.payload_summary,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        session.commit()

    return {
        "code": 0,
        "message": "success",
        "data": record,
    }


@router.post("/delivery-records/{record_id}/send")
def post_delivery_record_send(record_id: str) -> dict[str, object]:
    session_factory = _build_session_factory()
    with session_factory() as session:
        try:
            record = send_delivery_record_now(session, record_id=record_id)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        session.commit()

    return {
        "code": 0,
        "message": "success",
        "data": record,
    }


@router.post("/delivery-records/{record_id}/retry")
def post_delivery_record_retry(record_id: str) -> dict[str, object]:
    session_factory = _build_session_factory()
    with session_factory() as session:
        try:
            record = retry_delivery_record(session, record_id=record_id)
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        session.commit()

    return {
        "code": 0,
        "message": "success",
        "data": record,
    }


@router.post("/delivery-records/{record_id}/schedule")
def post_delivery_record_schedule(
    record_id: str,
    payload: ScheduleDeliveryRecordRequest,
) -> dict[str, object]:
    session_factory = _build_session_factory()
    with session_factory() as session:
        try:
            record = schedule_delivery_record(
                session,
                record_id=record_id,
                scheduled_at=payload.scheduled_at,
            )
        except LookupError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except (ValueError, TypeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        session.commit()

    return {
        "code": 0,
        "message": "success",
        "data": record,
    }
