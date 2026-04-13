from __future__ import annotations

from hashlib import sha256
from pathlib import Path
import uuid

from sqlalchemy import delete
from sqlalchemy.orm import sessionmaker

from app.models.platform import Artifact, TaskAttemptArtifact


def _artifact_file_path(
    *,
    artifact_root: Path,
    scene_name: str,
    artifact_id: uuid.UUID,
    artifact_kind: str,
) -> Path:
    suffix = ".txt" if artifact_kind == "text" else ".bin"
    return artifact_root / scene_name / f"{artifact_id}{suffix}"


def _cleanup_storage_path(
    storage_path: Path,
    *,
    stop_dir: Path,
) -> None:
    storage_path.unlink(missing_ok=True)

    current_dir = storage_path.parent
    resolved_stop_dir = stop_dir.resolve()
    while current_dir.exists() and current_dir != resolved_stop_dir:
        try:
            current_dir.rmdir()
        except OSError:
            break
        current_dir = current_dir.parent


def _persist_artifact_records(
    session_factory: sessionmaker,
    *,
    artifact: Artifact,
    attempt_id: uuid.UUID,
) -> None:
    with session_factory() as session, session.begin():
        session.add(artifact)
        session.add(
            TaskAttemptArtifact(
                attempt_id=attempt_id,
                artifact_id=artifact.artifact_id,
            ),
        )


def write_text_artifact(
    session_factory: sessionmaker,
    *,
    attempt_id: uuid.UUID,
    scene_name: str,
    artifact_root: Path,
    content: str,
    artifact_kind: str,
    source_url: str | None = None,
    content_type: str = "text/plain; charset=utf-8",
    metadata_json: dict[str, object] | None = None,
) -> Artifact:
    artifact_id = uuid.uuid4()
    content_bytes = content.encode("utf-8")
    checksum = sha256(content_bytes).hexdigest()
    resolved_artifact_root = artifact_root.resolve()
    storage_path = _artifact_file_path(
        artifact_root=resolved_artifact_root,
        scene_name=scene_name,
        artifact_id=artifact_id,
        artifact_kind=artifact_kind,
    )
    storage_path.parent.mkdir(parents=True, exist_ok=True)
    storage_path.write_bytes(content_bytes)

    artifact = Artifact(
        artifact_id=artifact_id,
        artifact_kind=artifact_kind,
        scene_name=scene_name,
        source_url=source_url,
        storage_path=str(storage_path),
        content_type=content_type,
        checksum=checksum,
        metadata_json=metadata_json or {},
    )

    try:
        _persist_artifact_records(
            session_factory,
            artifact=artifact,
            attempt_id=attempt_id,
        )
    except Exception:
        _cleanup_storage_path(
            storage_path,
            stop_dir=resolved_artifact_root,
        )
        raise

    return artifact


def delete_artifact(
    session_factory: sessionmaker,
    artifact_id: uuid.UUID,
) -> None:
    artifact = get_artifact(session_factory, artifact_id)
    if artifact is None:
        return

    storage_path = Path(artifact.storage_path)
    stop_dir = storage_path.parent.parent if storage_path.parent.parent != storage_path.parent else storage_path.parent

    with session_factory() as session, session.begin():
        session.execute(
            delete(TaskAttemptArtifact).where(TaskAttemptArtifact.artifact_id == artifact_id),
        )
        session.execute(
            delete(Artifact).where(Artifact.artifact_id == artifact_id),
        )

    _cleanup_storage_path(storage_path, stop_dir=stop_dir)


def get_artifact(
    session_factory: sessionmaker,
    artifact_id: uuid.UUID,
) -> Artifact | None:
    with session_factory() as session:
        return session.get(Artifact, artifact_id)


def read_artifact_content(
    session_factory: sessionmaker,
    artifact_id: uuid.UUID,
) -> bytes:
    artifact = get_artifact(session_factory, artifact_id)
    if artifact is None:
        raise ValueError(f"未找到 artifact: {artifact_id}")

    return Path(artifact.storage_path).read_bytes()
