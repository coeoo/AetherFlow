from __future__ import annotations

from pathlib import Path
import re

import httpx
from sqlalchemy.orm import Session

from app import http_client
from app.cve.source_trace import record_source_fetch
from app.models import CVEPatchArtifact
from app.platform.artifact_store import save_text_artifact


_GITHUB_COMMIT_PATTERN = re.compile(
    r"^https://github\.com/[^/]+/[^/]+/commit/[0-9a-f]{6,40}/?$",
    re.IGNORECASE,
)


def _resolve_download_url(candidate_url: str, patch_type: str) -> str:
    normalized_url = candidate_url.rstrip("/")
    lower_url = normalized_url.lower()
    if lower_url.endswith((".patch", ".diff")) or "patch=" in lower_url:
        return normalized_url

    if _GITHUB_COMMIT_PATTERN.match(normalized_url):
        return f"{normalized_url}.{patch_type}"

    return normalized_url


def _looks_like_patch(content: str) -> bool:
    stripped = content.lstrip()
    if not stripped:
        return False

    if stripped.startswith(("diff --git ", "From ", "--- ")):
        return True

    return "\ndiff --git " in content or ("\n--- " in content and "\n+++ " in content)


def _validate_downloaded_content(*, content: str, content_type: str) -> None:
    if "html" in content_type.lower():
        raise ValueError("下载内容不是有效的 patch/diff")

    if not _looks_like_patch(content):
        raise ValueError("下载内容不是有效的 patch/diff")


def download_patch_candidate(
    session: Session,
    *,
    run,
    candidate: dict[str, object],
) -> CVEPatchArtifact:
    candidate_url = str(candidate["candidate_url"])
    patch_type = str(candidate["patch_type"])
    download_url = _resolve_download_url(candidate_url, patch_type)
    response: httpx.Response | None = None
    request_snapshot = {
        "candidate_url": candidate_url,
        "download_url": download_url,
        "patch_type": patch_type,
        "discovered_from_url": candidate.get("discovered_from_url"),
        "discovered_from_host": candidate.get("discovered_from_host"),
        "discovery_rule": candidate.get("discovery_rule"),
        "canonical_candidate_key": candidate.get("canonical_candidate_key"),
        "discovery_sources": candidate.get("discovery_sources"),
        "evidence_source_count": candidate.get("evidence_source_count"),
    }

    try:
        response = http_client.get(
            download_url,
            timeout=10.0,
            follow_redirects=True,
            headers={"User-Agent": "AetherFlow/0.1"},
        )
        response.raise_for_status()
        content_type = response.headers.get("content-type", "text/plain")
        _validate_downloaded_content(content=response.text, content_type=content_type)
        artifact = save_text_artifact(
            session,
            scene_name="cve",
            artifact_kind=patch_type,
            source_url=candidate_url,
            filename_hint=Path(download_url).name or f"patch.{patch_type}",
            content=response.text,
            content_type=content_type,
            metadata={
                "candidate_url": candidate_url,
                "download_url": download_url,
                "run_id": str(run.run_id),
            },
        )
        patch = CVEPatchArtifact(
            run_id=run.run_id,
            candidate_url=candidate_url,
            patch_type=patch_type,
            download_status="downloaded",
            artifact_id=artifact.artifact_id,
            patch_meta_json={
                "status_code": response.status_code,
                "content_type": content_type,
                "download_url": download_url,
                "discovered_from_url": candidate.get("discovered_from_url"),
                "discovered_from_host": candidate.get("discovered_from_host"),
                "discovery_rule": candidate.get("discovery_rule"),
                "canonical_candidate_key": candidate.get("canonical_candidate_key"),
                "discovery_sources": candidate.get("discovery_sources"),
                "evidence_source_count": candidate.get("evidence_source_count"),
            },
        )
        record_source_fetch(
            session,
            run=run,
            source_type="cve_patch_download",
            source_ref=candidate_url,
            status="succeeded",
            request_snapshot=request_snapshot,
            response_meta={
                "status_code": response.status_code,
                "content_type": content_type,
                "download_url": download_url,
                "artifact_id": str(artifact.artifact_id),
            },
        )
    except Exception as exc:
        patch_meta = {
            "error": str(exc),
            "download_url": download_url,
            "discovered_from_url": candidate.get("discovered_from_url"),
            "discovered_from_host": candidate.get("discovered_from_host"),
            "discovery_rule": candidate.get("discovery_rule"),
            "canonical_candidate_key": candidate.get("canonical_candidate_key"),
            "discovery_sources": candidate.get("discovery_sources"),
            "evidence_source_count": candidate.get("evidence_source_count"),
        }
        if response is not None:
            patch_meta["content_type"] = response.headers.get("content-type", "")
        patch = CVEPatchArtifact(
            run_id=run.run_id,
            candidate_url=candidate_url,
            patch_type=patch_type,
            download_status="failed",
            patch_meta_json=patch_meta,
        )
        record_source_fetch(
            session,
            run=run,
            source_type="cve_patch_download",
            source_ref=candidate_url,
            status="failed",
            request_snapshot=request_snapshot,
            response_meta={
                "status_code": response.status_code,
                "content_type": response.headers.get("content-type", ""),
                "download_url": download_url,
            }
            if response is not None
            else {"download_url": download_url},
            error_message=str(exc),
        )

    session.add(patch)
    session.flush()
    return patch
