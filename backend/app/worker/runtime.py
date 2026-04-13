from __future__ import annotations

"""Worker runtime implementation."""

from dataclasses import dataclass
import os
from pathlib import Path
import socket
import uuid

from app.config import Settings
from app.db.session import create_session_factory
from app.platform.artifact_store import delete_artifact, write_text_artifact
from app.platform.runtime_heartbeats import upsert_runtime_heartbeat
from app.platform.task_runtime import claim_next_job, mark_attempt_failed, mark_attempt_succeeded


@dataclass(frozen=True)
class WorkerRunResult:
    processed: bool
    job_id: uuid.UUID | None


def build_worker_name(explicit_name: str | None = None) -> str:
    if explicit_name:
        return explicit_name

    return f"worker@{socket.gethostname()}:{os.getpid()}"


def run_worker_once(
    settings: Settings,
    *,
    worker_name: str | None = None,
) -> WorkerRunResult:
    if not settings.database_url:
        raise RuntimeError("缺少数据库连接配置，无法执行 worker once。")

    session_factory = create_session_factory(settings.database_url)
    resolved_worker_name = build_worker_name(worker_name)
    upsert_runtime_heartbeat(
        session_factory,
        role="worker",
        instance_name=resolved_worker_name,
    )
    claimed = claim_next_job(
        session_factory,
        worker_name=resolved_worker_name,
    )

    if claimed is None:
        return WorkerRunResult(processed=False, job_id=None)

    artifact_id: uuid.UUID | None = None
    try:
        raw_text = str(claimed.payload_json.get("raw_text", "")).strip()
        if not raw_text:
            raise RuntimeError("当前最小 worker 任务缺少 raw_text，无法生成 Artifact。")

        artifact = write_text_artifact(
            session_factory,
            attempt_id=claimed.attempt_id,
            scene_name=claimed.scene_name,
            artifact_root=Path(settings.artifact_root),
            content=raw_text,
            artifact_kind="text",
            metadata_json={"job_type": claimed.job_type},
        )
        artifact_id = artifact.artifact_id
        mark_attempt_succeeded(session_factory, claimed.attempt_id)
    except Exception as exc:
        mark_attempt_failed(
            session_factory,
            claimed.attempt_id,
            error_message=str(exc),
        )
        if artifact_id is not None:
            try:
                delete_artifact(session_factory, artifact_id)
            except Exception as cleanup_exc:
                exc.add_note(f"artifact cleanup failed: {cleanup_exc}")
        raise

    return WorkerRunResult(processed=True, job_id=claimed.job_id)
