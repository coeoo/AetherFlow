from __future__ import annotations

from datetime import datetime

from sqlalchemy import text

from app.config import Settings
from app.db.session import create_engine_from_url, create_session_factory
from app.platform.runtime_heartbeats import get_latest_heartbeat_at, now_utc


def _role_status(
    latest_heartbeat_at: datetime | None,
    *,
    current_time: datetime,
    stale_seconds: int,
) -> str:
    if latest_heartbeat_at is None:
        return "down"

    age_seconds = (current_time - latest_heartbeat_at).total_seconds()
    if age_seconds <= stale_seconds:
        return "healthy"
    if age_seconds <= stale_seconds * 2:
        return "degraded"
    return "down"


def collect_health_summary(
    settings: Settings,
    *,
    current_time: datetime | None = None,
) -> dict[str, object]:
    resolved_time = current_time or now_utc()
    notes: list[str] = []
    database_status = "down"
    worker_status = "down"
    scheduler_status = "down"

    if not settings.database_url:
        notes.append("缺少 DATABASE_URL，无法检查数据库与运行时心跳。")
        return {
            "api": "healthy",
            "database": database_status,
            "worker": worker_status,
            "scheduler": scheduler_status,
            "notes": notes,
        }

    engine = create_engine_from_url(settings.database_url)
    try:
        with engine.connect() as connection:
            connection.execute(text("select 1"))
        database_status = "healthy"
    except Exception as exc:
        notes.append(f"数据库连接异常: {exc}")
        return {
            "api": "healthy",
            "database": database_status,
            "worker": worker_status,
            "scheduler": scheduler_status,
            "notes": notes,
        }

    session_factory = create_session_factory(settings.database_url)
    worker_status = _role_status(
        get_latest_heartbeat_at(session_factory, role="worker"),
        current_time=resolved_time,
        stale_seconds=settings.runtime_heartbeat_stale_seconds,
    )
    scheduler_status = _role_status(
        get_latest_heartbeat_at(session_factory, role="scheduler"),
        current_time=resolved_time,
        stale_seconds=settings.runtime_heartbeat_stale_seconds,
    )

    if worker_status != "healthy":
        notes.append(f"worker 当前状态为 {worker_status}")
    if scheduler_status != "healthy":
        notes.append(f"scheduler 当前状态为 {scheduler_status}")

    return {
        "api": "healthy",
        "database": database_status,
        "worker": worker_status,
        "scheduler": scheduler_status,
        "notes": notes,
    }
