from __future__ import annotations

from datetime import datetime, timezone
import os
import socket

from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app.models.platform import RuntimeHeartbeat


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def build_instance_name(role: str, explicit_name: str | None = None) -> str:
    if explicit_name:
        return explicit_name

    return f"{role}@{socket.gethostname()}:{os.getpid()}"


def upsert_runtime_heartbeat(
    session_factory: sessionmaker,
    *,
    role: str,
    instance_name: str,
    heartbeat_at: datetime | None = None,
) -> None:
    current_time = now_utc()
    resolved_heartbeat_at = heartbeat_at or current_time

    with session_factory() as session, session.begin():
        heartbeat = session.get(
            RuntimeHeartbeat,
            {"role": role, "instance_name": instance_name},
        )

        if heartbeat is None:
            heartbeat = RuntimeHeartbeat(
                role=role,
                instance_name=instance_name,
                heartbeat_at=resolved_heartbeat_at,
                created_at=current_time,
                updated_at=current_time,
            )
            session.add(heartbeat)
            return

        heartbeat.heartbeat_at = resolved_heartbeat_at
        heartbeat.updated_at = current_time


def get_latest_heartbeat_at(
    session_factory: sessionmaker,
    *,
    role: str,
) -> datetime | None:
    with session_factory() as session:
        heartbeat = session.scalar(
            select(RuntimeHeartbeat)
            .where(RuntimeHeartbeat.role == role)
            .order_by(RuntimeHeartbeat.heartbeat_at.desc())
            .limit(1),
        )

        if heartbeat is None:
            return None

        return heartbeat.heartbeat_at
