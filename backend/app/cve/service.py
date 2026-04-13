from __future__ import annotations

from sqlalchemy.orm import Session

from app.models import CVERun, TaskJob


def create_cve_run(session: Session, *, cve_id: str) -> CVERun:
    job = TaskJob(
        scene_name="cve",
        job_type="cve_patch_fast_first",
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
