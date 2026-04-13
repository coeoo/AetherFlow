from __future__ import annotations

import hashlib
from pathlib import Path
from uuid import uuid4

from sqlalchemy.orm import Session

from app.config import load_settings
from app.models import Artifact


def save_text_artifact(
    session: Session,
    *,
    scene_name: str,
    artifact_kind: str,
    source_url: str | None,
    filename_hint: str,
    content: str,
    content_type: str,
    metadata: dict[str, object],
) -> Artifact:
    settings = load_settings()
    root = Path(settings.artifact_root)
    root.mkdir(parents=True, exist_ok=True)

    safe_name = Path(filename_hint).name or "artifact.txt"
    target_dir = root / scene_name / artifact_kind / uuid4().hex
    target_dir.mkdir(parents=True, exist_ok=True)
    file_path = target_dir / safe_name
    file_path.write_text(content, encoding="utf-8")

    checksum = hashlib.sha256(content.encode("utf-8")).hexdigest()
    artifact = Artifact(
        artifact_kind=artifact_kind,
        scene_name=scene_name,
        source_url=source_url,
        storage_path=str(file_path),
        content_type=content_type,
        checksum=checksum,
        metadata_json=metadata,
    )
    session.add(artifact)
    session.flush()
    return artifact
