from __future__ import annotations

from app.config import Settings
from app.db.session import create_session_factory
from app.platform.delivery_service import process_scheduled_delivery_records
from app.platform.runtime_heartbeats import build_instance_name, upsert_runtime_heartbeat


def run_scheduler_once(
    settings: Settings,
    *,
    instance_name: str | None = None,
) -> None:
    if not settings.database_url:
        raise RuntimeError("缺少数据库连接配置，无法执行 scheduler once。")

    session_factory = create_session_factory(settings.database_url)
    upsert_runtime_heartbeat(
        session_factory,
        role="scheduler",
        instance_name=build_instance_name("scheduler", instance_name),
    )
    process_scheduled_delivery_records(session_factory)
