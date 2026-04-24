from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import os
from pathlib import Path
import re
import time
from urllib.parse import urlparse

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
_GITHUB_COMMIT_WITH_SUFFIX_PATTERN = re.compile(
    r"^https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/commit/(?P<sha>[0-9a-f]{6,40})(?P<suffix>\.(?:patch|diff))?/?$",
    re.IGNORECASE,
)
_RETRY_TIMEOUT_SECONDS = (15.0, 20.0, 30.0)
_RETRY_DELAYS_SECONDS = (2.0, 5.0)
_PATCH_DOWNLOAD_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    ),
    "Accept": "text/x-patch,text/plain,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
}


class DownloadErrorKind(str, Enum):
    TIMEOUT = "timeout"
    RATE_LIMITED = "rate_limited"
    NOT_FOUND = "not_found"
    HTTP_ERROR = "http_error"
    INVALID_CONTENT = "invalid_content"
    NETWORK_ERROR = "network_error"


@dataclass(frozen=True)
class DownloadStrategy:
    name: str
    url: str
    headers: dict[str, str]


class PatchDownloadError(RuntimeError):
    def __init__(
        self,
        message: str,
        *,
        response: httpx.Response | None,
        attempts: list[dict[str, object]],
        error_kind: DownloadErrorKind,
        download_url: str,
    ) -> None:
        super().__init__(message)
        self.response = response
        self.attempts = attempts
        self.error_kind = error_kind
        self.download_url = download_url


def _resolve_download_url(candidate_url: str, patch_type: str) -> str:
    normalized_url = candidate_url.rstrip("/")
    lower_url = normalized_url.lower()
    if lower_url.endswith((".patch", ".diff")) or "patch=" in lower_url:
        return normalized_url

    if _GITHUB_COMMIT_PATTERN.match(normalized_url):
        return f"{normalized_url}.{patch_type}"

    return normalized_url


def _build_github_api_headers(accept: str) -> dict[str, str]:
    headers = {
        "User-Agent": "AetherFlow/0.1",
        "Accept": accept,
        "X-GitHub-Api-Version": "2022-11-28",
    }
    github_token = os.getenv("GITHUB_TOKEN", "").strip()
    if github_token:
        headers["Authorization"] = f"Bearer {github_token}"
    return headers


def _build_download_strategies(candidate_url: str, patch_type: str) -> list[DownloadStrategy]:
    download_url = _resolve_download_url(candidate_url, patch_type)
    strategies = [
        DownloadStrategy(
            name="direct_patch_url",
            url=download_url,
            headers=dict(_PATCH_DOWNLOAD_HEADERS),
        )
    ]
    match = _GITHUB_COMMIT_WITH_SUFFIX_PATTERN.match(candidate_url.rstrip("/"))
    if match is None:
        return strategies

    owner = match.group("owner")
    repo = match.group("repo")
    sha = match.group("sha")
    base_url = f"https://github.com/{owner}/{repo}/commit/{sha}"
    diff_url = f"{base_url}.diff"
    if diff_url != download_url:
        strategies.append(
            DownloadStrategy(
                name="github_commit_diff_url",
                url=diff_url,
                headers=dict(_PATCH_DOWNLOAD_HEADERS),
            )
        )

    if os.getenv("GITHUB_TOKEN", "").strip():
        api_url = f"https://api.github.com/repos/{owner}/{repo}/commits/{sha}"
        strategies.extend(
            [
                DownloadStrategy(
                    name="github_api_patch",
                    url=api_url,
                    headers=_build_github_api_headers("application/vnd.github.patch"),
                ),
                DownloadStrategy(
                    name="github_api_diff",
                    url=api_url,
                    headers=_build_github_api_headers("application/vnd.github.diff"),
                ),
            ]
        )
    return strategies


def _looks_like_patch(content: str) -> bool:
    stripped = content.lstrip()
    if not stripped:
        return False

    if stripped.startswith(("diff --git ", "From ", "--- ")):
        return True

    return "\ndiff --git " in content or ("\n--- " in content and "\n+++ " in content)


def _validate_downloaded_content(*, content: str, content_type: str) -> None:
    if "html" in content_type.lower() or "<html" in content.lower() or "<!doctype" in content.lower():
        raise ValueError("下载内容不是有效的 patch/diff")

    if not _looks_like_patch(content):
        raise ValueError("下载内容不是有效的 patch/diff")


def _classify_failure(exc: Exception, response: httpx.Response | None) -> DownloadErrorKind:
    if isinstance(exc, (httpx.ReadTimeout, httpx.ConnectTimeout, httpx.TimeoutException)):
        return DownloadErrorKind.TIMEOUT
    if isinstance(exc, httpx.RequestError):
        return DownloadErrorKind.NETWORK_ERROR
    if isinstance(exc, ValueError):
        return DownloadErrorKind.INVALID_CONTENT
    if response is not None:
        response_text = response.text.lower()
        if response.status_code == 429:
            return DownloadErrorKind.RATE_LIMITED
        if response.status_code == 403 and "rate limit" in response_text:
            return DownloadErrorKind.RATE_LIMITED
        if response.status_code == 404:
            return DownloadErrorKind.NOT_FOUND
        if response.status_code >= 400:
            return DownloadErrorKind.HTTP_ERROR
    return DownloadErrorKind.NETWORK_ERROR


def _build_attempt_record(
    *,
    strategy: DownloadStrategy,
    attempt_no: int,
    timeout_seconds: float,
    status: str,
    response: httpx.Response | None = None,
    error: Exception | None = None,
    error_kind: DownloadErrorKind | None = None,
) -> dict[str, object]:
    record: dict[str, object] = {
        "strategy": strategy.name,
        "url": strategy.url,
        "attempt_no": attempt_no,
        "timeout_seconds": timeout_seconds,
        "status": status,
    }
    if response is not None:
        record["status_code"] = response.status_code
        record["content_type"] = response.headers.get("content-type", "")
    if error is not None:
        record["error"] = str(error)
    if error_kind is not None:
        record["error_kind"] = error_kind.value
    return record


def _download_with_strategies(candidate_url: str, patch_type: str):
    attempts: list[dict[str, object]] = []
    last_response: httpx.Response | None = None
    last_error: Exception | None = None
    last_error_kind = DownloadErrorKind.NETWORK_ERROR
    last_download_url = _resolve_download_url(candidate_url, patch_type)
    for strategy in _build_download_strategies(candidate_url, patch_type):
        last_download_url = strategy.url
        for index, timeout_seconds in enumerate(_RETRY_TIMEOUT_SECONDS):
            attempt_no = index + 1
            try:
                response = http_client.get(
                    strategy.url,
                    timeout=timeout_seconds,
                    follow_redirects=True,
                    headers=strategy.headers,
                )
                last_response = response
                response.raise_for_status()
                content_type = response.headers.get("content-type", "text/plain")
                _validate_downloaded_content(content=response.text, content_type=content_type)
                attempts.append(
                    _build_attempt_record(
                        strategy=strategy,
                        attempt_no=attempt_no,
                        timeout_seconds=timeout_seconds,
                        status="succeeded",
                        response=response,
                    )
                )
                return response, strategy.url, attempts
            except Exception as exc:
                last_error = exc
                last_error_kind = _classify_failure(exc, last_response)
                attempts.append(
                    _build_attempt_record(
                        strategy=strategy,
                        attempt_no=attempt_no,
                        timeout_seconds=timeout_seconds,
                        status="failed",
                        response=last_response,
                        error=exc,
                        error_kind=last_error_kind,
                    )
                )
                if last_error_kind in {
                    DownloadErrorKind.RATE_LIMITED,
                    DownloadErrorKind.NOT_FOUND,
                    DownloadErrorKind.INVALID_CONTENT,
                }:
                    break
                if index < len(_RETRY_DELAYS_SECONDS):
                    time.sleep(_RETRY_DELAYS_SECONDS[index])
    assert last_error is not None
    raise PatchDownloadError(
        str(last_error),
        response=last_response,
        attempts=attempts,
        error_kind=last_error_kind,
        download_url=last_download_url,
    )


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
    attempts: list[dict[str, object]] = []
    error_kind: DownloadErrorKind | None = None
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
        response, download_url, attempts = _download_with_strategies(candidate_url, patch_type)
        content_type = response.headers.get("content-type", "text/plain")
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
                "attempts": attempts,
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
                "attempts": attempts,
            },
        )
    except PatchDownloadError as exc:
        response = exc.response
        attempts = exc.attempts
        error_kind = exc.error_kind
        download_url = exc.download_url
        patch_meta = {
            "error": str(exc),
            "error_kind": error_kind.value,
            "download_url": download_url,
            "attempts": attempts,
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
                "attempts": attempts,
                "error_kind": error_kind.value,
            }
            if response is not None
            else {"download_url": download_url, "attempts": attempts, "error_kind": error_kind.value},
            error_message=str(exc),
        )
    except Exception as exc:
        error_kind = _classify_failure(exc, response)
        patch_meta = {
            "error": str(exc),
            "error_kind": error_kind.value,
            "download_url": download_url,
            "attempts": attempts,
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
                "attempts": attempts,
                "error_kind": error_kind.value,
            }
            if response is not None
            else {"download_url": download_url, "attempts": attempts, "error_kind": error_kind.value},
            error_message=str(exc),
        )

    session.add(patch)
    session.flush()
    return patch
