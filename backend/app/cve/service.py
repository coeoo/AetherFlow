from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import CVERun, TaskJob


def create_cve_run(session: Session, *, cve_id: str) -> CVERun:
    job = TaskJob(
        scene_name="cve",
        job_type="cve_patch_agent_graph",
        trigger_kind="manual",
        status="queued",
        payload_json={"cve_id": cve_id},
    )
    session.add(job)
    session.flush()

    run = CVERun(
        job_id=job.job_id,
        cve_id=cve_id,
        status="queued",
        phase="resolve_seeds",
        summary_json={},
    )
    session.add(run)
    session.flush()
    return run


def get_cve_run(session: Session, *, run_id) -> CVERun | None:
    return session.get(CVERun, run_id)


def list_cve_runs(session: Session, *, limit: int) -> list[CVERun]:
    statement = (
        select(CVERun)
        .order_by(CVERun.created_at.desc(), CVERun.run_id.desc())
        .limit(limit)
    )
    return session.execute(statement).scalars().all()
