from __future__ import annotations

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.announcements.delivery_service import (
    create_delivery_target,
    list_delivery_targets,
    list_platform_delivery_records,
    update_delivery_target,
)
from app.config import load_settings
from app.db.session import create_session_factory

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


@router.get("/delivery-records")
def get_delivery_records(
    scene_name: str | None = Query(default=None),
    status: str | None = Query(default=None),
    channel_type: str | None = Query(default=None),
    limit: int = Query(default=20, ge=1, le=100),
) -> dict[str, object]:
    settings = load_settings()
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        records = list_platform_delivery_records(
            session,
            scene_name=scene_name,
            status=status,
            channel_type=channel_type,
            limit=limit,
        )

    return {
        "code": 0,
        "message": "success",
        "data": records,
    }


@router.get("/delivery-targets")
def get_delivery_targets() -> dict[str, object]:
    settings = load_settings()
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        targets = list_delivery_targets(session)

    return {
        "code": 0,
        "message": "success",
        "data": targets,
    }


@router.post("/delivery-targets")
def post_delivery_target(payload: CreateDeliveryTargetRequest) -> dict[str, object]:
    settings = load_settings()
    session_factory = create_session_factory(settings.database_url)
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
    settings = load_settings()
    session_factory = create_session_factory(settings.database_url)
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
