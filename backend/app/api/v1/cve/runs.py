from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.config import load_settings
from app.cve.service import create_cve_run, get_cve_run
from app.db.session import create_session_factory

router = APIRouter(prefix="/api/v1/cve", tags=["cve"])


class CreateCVERunRequest(BaseModel):
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")


def _serialize_run(run) -> dict[str, object]:
    return {
        "run_id": str(run.run_id),
        "cve_id": run.cve_id,
        "status": run.status,
        "phase": run.phase,
        "stop_reason": run.stop_reason,
        "summary": run.summary_json,
    }


@router.post("/runs")
def create_run(payload: CreateCVERunRequest) -> dict[str, object]:
    settings = load_settings()
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        run = create_cve_run(session, cve_id=payload.cve_id)
        session.commit()
        session.refresh(run)

    return {
        "code": 0,
        "message": "success",
        "data": _serialize_run(run),
    }


@router.get("/runs/{run_id}")
def get_run(run_id: UUID) -> dict[str, object]:
    settings = load_settings()
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        run = get_cve_run(session, run_id=run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="CVE 运行记录不存在")

        return {
            "code": 0,
            "message": "success",
            "data": _serialize_run(run),
        }
