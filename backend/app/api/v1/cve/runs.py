from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from app.config import load_settings
from app.cve.detail_service import get_cve_run_detail, get_patch_content
from app.cve.service import create_cve_run, list_cve_runs
from app.db.session import create_session_factory

router = APIRouter(prefix="/api/v1/cve", tags=["cve"])


class CreateCVERunRequest(BaseModel):
    cve_id: str = Field(pattern=r"^CVE-\d{4}-\d{4,}$")


def _serialize_run_summary(run) -> dict[str, object]:
    return {
        "run_id": str(run.run_id),
        "cve_id": run.cve_id,
        "status": run.status,
        "phase": run.phase,
        "stop_reason": run.stop_reason,
        "summary": run.summary_json,
        "created_at": run.created_at.isoformat(),
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
        "data": _serialize_run_summary(run),
    }


@router.get("/runs")
def get_runs(*, limit: int = Query(6, ge=1, le=20)) -> dict[str, object]:
    settings = load_settings()
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        runs = list_cve_runs(session, limit=limit)
        return {
            "code": 0,
            "message": "success",
            "data": [_serialize_run_summary(run) for run in runs],
        }


@router.get("/runs/{run_id}")
def get_run(run_id: UUID) -> dict[str, object]:
    settings = load_settings()
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        detail = get_cve_run_detail(session, run_id=run_id)
        if detail is None:
            raise HTTPException(status_code=404, detail="CVE 运行记录不存在")

        return {
            "code": 0,
            "message": "success",
            "data": detail,
        }


@router.get("/runs/{run_id}/patch-content")
def get_run_patch_content(
    run_id: UUID,
    *,
    patch_id: UUID | None = Query(default=None),
    candidate_url: str | None = Query(default=None, min_length=1),
) -> dict[str, object]:
    if patch_id is None and candidate_url is None:
        raise HTTPException(status_code=422, detail="patch_id 或 candidate_url 至少提供一个")

    settings = load_settings()
    session_factory = create_session_factory(settings.database_url)
    with session_factory() as session:
        payload = get_patch_content(
            session,
            run_id=run_id,
            patch_id=patch_id,
            candidate_url=candidate_url,
        )
        if payload is None:
            raise HTTPException(status_code=404, detail="Patch 内容不存在")

        return {
            "code": 0,
            "message": "success",
            "data": payload,
        }
