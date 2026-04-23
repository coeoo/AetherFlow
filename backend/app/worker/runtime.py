from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import socket
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from app.config import Settings
from app.announcements.runtime import execute_announcement_run, execute_monitor_fetch
from app.cve.runtime import execute_cve_run
from app.db.session import create_session_factory
from app.models import AnnouncementRun, CVERun
from app.platform.artifact_store import delete_artifact, write_text_artifact
from app.platform.runtime_heartbeats import upsert_runtime_heartbeat
from app.platform.task_runtime import (
    claim_next_job,
    finish_attempt_failure,
    finish_attempt_success,
    mark_attempt_failed,
    mark_attempt_succeeded,
)


@dataclass(frozen=True)
class WorkerRunResult:
    processed: bool
    job_id: uuid.UUID | None


def build_worker_name(explicit_name: str | None = None) -> str:
    if explicit_name:
        return explicit_name
    return f"worker@{socket.gethostname()}:{os.getpid()}"


def _finish_cve_attempt_from_run(session: Session, *, attempt, run: CVERun) -> None:
    if run.status == "succeeded":
        finish_attempt_success(session, attempt=attempt)
        return

    if run.status == "failed":
        finish_attempt_failure(
            session,
            attempt=attempt,
            error_message=f"场景运行失败: {run.stop_reason or 'unknown'}",
        )
        return

    raise RuntimeError(f"CVE run 未收口: status={run.status}, phase={run.phase}")


def process_once(session_factory: sessionmaker[Session], *, worker_name: str) -> bool:
    with session_factory() as session:
        attempt = claim_next_job(session, scene_name="cve", worker_name=worker_name)
        if attempt is None:
            attempt = claim_next_job(session, scene_name="announcement", worker_name=worker_name)
        if attempt is None:
            return False

        job = attempt.job
        try:
            if job.scene_name == "cve" and job.job_type == "cve_patch_agent_graph":
                run_id = session.execute(
                    select(CVERun.run_id).where(CVERun.job_id == job.job_id)
                ).scalar_one()
                execute_cve_run(session, run_id=run_id)
                run = session.get(CVERun, run_id)
                if run is None:
                    raise RuntimeError(f"CVE run 不存在: {run_id}")
                _finish_cve_attempt_from_run(session, attempt=attempt, run=run)
                session.commit()
                return True
            if job.scene_name == "announcement" and job.job_type == "announcement_manual_extract":
                run_id = session.execute(
                    select(AnnouncementRun.run_id).where(AnnouncementRun.job_id == job.job_id)
                ).scalar_one()
                execute_announcement_run(session, run_id=run_id)
                run = session.get(AnnouncementRun, run_id)
                if run is None:
                    raise RuntimeError(f"公告 run 不存在: {run_id}")
                if run.status == "succeeded":
                    finish_attempt_success(session, attempt=attempt)
                else:
                    finish_attempt_failure(
                        session,
                        attempt=attempt,
                        error_message=f"场景运行失败: {run.summary_json.get('error', 'unknown')}",
                    )
                session.commit()
                return True
            if job.scene_name == "announcement" and job.job_type == "announcement_monitor_fetch":
                execute_monitor_fetch(session, job=job)
                finish_attempt_success(session, attempt=attempt)
                session.commit()
                return True

            finish_attempt_failure(
                session,
                attempt=attempt,
                error_message=f"不支持的任务类型: {job.scene_name}/{job.job_type}",
            )
        except Exception as exc:
            finish_attempt_failure(session, attempt=attempt, error_message=str(exc))
        session.commit()
        return True


def run_worker_once(
    settings: Settings,
    *,
    worker_name: str | None = None,
) -> WorkerRunResult:
    if not settings.database_url:
        raise RuntimeError("缺少数据库连接配置，无法执行 worker once。")

    session_factory = create_session_factory(settings.database_url)
    resolved_worker_name = build_worker_name(worker_name or settings.worker_name)
    upsert_runtime_heartbeat(
        session_factory,
        role="worker",
        instance_name=resolved_worker_name,
    )
    claimed = claim_next_job(session_factory, worker_name=resolved_worker_name)

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
