from __future__ import annotations

from sqlalchemy.orm import Session, sessionmaker

from app.platform.task_runtime import claim_next_job


def process_once(session_factory: sessionmaker[Session], *, worker_name: str) -> bool:
    with session_factory() as session:
        attempt = claim_next_job(session, scene_name="cve", worker_name=worker_name)
        if attempt is None:
            return False

        session.commit()
        return True
