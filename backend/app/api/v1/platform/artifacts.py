from __future__ import annotations

from pathlib import Path
import uuid

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse

from app.config import load_settings
from app.db.session import create_session_factory
from app.platform.artifact_store import get_artifact, read_artifact_content


router = APIRouter(prefix="/api/v1/platform", tags=["platform"])


def _build_session_factory():
    settings = load_settings()
    if not settings.database_url:
        raise HTTPException(status_code=500, detail="缺少数据库连接配置。")

    return create_session_factory(settings.database_url)


@router.get("/artifacts/{artifact_id}")
def get_artifact_metadata(artifact_id: uuid.UUID) -> dict[str, object]:
    artifact = get_artifact(_build_session_factory(), artifact_id)
    if artifact is None:
        raise HTTPException(status_code=404, detail="Artifact 不存在。")

    return {
        "artifact_id": str(artifact.artifact_id),
        "artifact_kind": artifact.artifact_kind,
        "scene_name": artifact.scene_name,
        "source_url": artifact.source_url,
        "content_type": artifact.content_type,
        "checksum": artifact.checksum,
        "metadata_json": artifact.metadata_json,
        "created_at": artifact.created_at.isoformat(),
    }


@router.get("/artifacts/{artifact_id}/content")
def get_artifact_content(artifact_id: uuid.UUID):
    session_factory = _build_session_factory()
    artifact = get_artifact(session_factory, artifact_id)
    if artifact is None:
        raise HTTPException(status_code=404, detail="Artifact 不存在。")

    if artifact.content_type and artifact.content_type.startswith("text/"):
        content = read_artifact_content(session_factory, artifact_id).decode("utf-8")
        return PlainTextResponse(content, media_type=artifact.content_type)

    return FileResponse(
        Path(artifact.storage_path),
        media_type=artifact.content_type or "application/octet-stream",
    )
