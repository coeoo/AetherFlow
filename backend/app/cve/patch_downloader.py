from __future__ import annotations

from pathlib import Path

import httpx
from sqlalchemy.orm import Session

from app.models import CVEPatchArtifact
from app.platform.artifact_store import save_text_artifact


def download_patch_candidate(
    session: Session,
    *,
    run,
    candidate: dict[str, str],
) -> CVEPatchArtifact:
    candidate_url = candidate["candidate_url"]
    patch_type = candidate["patch_type"]

    try:
        response = httpx.get(
            candidate_url,
            timeout=10.0,
            follow_redirects=True,
            headers={"User-Agent": "AetherFlow/0.1"},
        )
        response.raise_for_status()
        artifact = save_text_artifact(
            session,
            scene_name="cve",
            artifact_kind=patch_type,
            source_url=candidate_url,
            filename_hint=Path(candidate_url).name or f"patch.{patch_type}",
            content=response.text,
            content_type=response.headers.get("content-type", "text/plain"),
            metadata={"download_url": candidate_url, "run_id": str(run.run_id)},
        )
        patch = CVEPatchArtifact(
            run_id=run.run_id,
            candidate_url=candidate_url,
            patch_type=patch_type,
            download_status="downloaded",
            artifact_id=artifact.artifact_id,
            patch_meta_json={
                "status_code": response.status_code,
                "content_type": response.headers.get("content-type", ""),
            },
        )
    except Exception as exc:
        patch = CVEPatchArtifact(
            run_id=run.run_id,
            candidate_url=candidate_url,
            patch_type=patch_type,
            download_status="failed",
            patch_meta_json={"error": str(exc)},
        )

    session.add(patch)
    session.flush()
    return patch
