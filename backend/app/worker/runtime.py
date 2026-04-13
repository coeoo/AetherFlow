from __future__ import annotations

from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy import select

from app.cve.runtime import execute_cve_run
from app.models import CVERun
from app.platform.task_runtime import claim_next_job
from app.platform.task_runtime import finish_attempt_failure, finish_attempt_success


def process_once(session_factory: sessionmaker[Session], *, worker_name: str) -> bool:
    with session_factory() as session:
        attempt = claim_next_job(session, scene_name="cve", worker_name=worker_name)
        if attempt is None:
            return False

        job = attempt.job
        try:
            if job.scene_name == "cve" and job.job_type == "cve_patch_fast_first":
                run_id = session.execute(
                    select(CVERun.run_id).where(CVERun.job_id == job.job_id)
                ).scalar_one()
                execute_cve_run(session, run_id=run_id)
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
