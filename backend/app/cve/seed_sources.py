from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from urllib.parse import urldefrag

import httpx

from app import http_client


@dataclass(frozen=True)
class SeedSourceResult:
    source: str
    status: str
    status_code: int | None
    reference_count: int
    error_kind: str | None
    error_message: str | None
    references: list[str]
    request_url: str


def _build_request_url(source: str, cve_id: str) -> str:
    if source == "cve_official":
        return f"https://cveawg.mitre.org/api/cve/{cve_id}"
    if source == "osv":
        return f"https://api.osv.dev/v1/vulns/{cve_id}"
    if source == "github_advisory":
        return f"https://api.github.com/advisories?cve_id={cve_id}&per_page=20"
    if source == "nvd":
        return f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    raise ValueError(f"不支持的 seed 来源: {source}")


def _dedupe_preserve_order(urls: list[str]) -> list[str]:
    deduped: list[str] = []
    seen: set[str] = set()
    for url in urls:
        normalized = urldefrag(url.strip()).url
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(normalized)
    return deduped


def _success_result(*, source: str, status_code: int, references: list[str], request_url: str) -> SeedSourceResult:
    deduped = _dedupe_preserve_order(references)
    return SeedSourceResult(
        source=source,
        status="success",
        status_code=status_code,
        reference_count=len(deduped),
        error_kind=None,
        error_message=None,
        references=deduped,
        request_url=request_url,
    )


def _not_found_result(*, source: str, status_code: int | None, request_url: str) -> SeedSourceResult:
    return SeedSourceResult(
        source=source,
        status="not_found",
        status_code=status_code,
        reference_count=0,
        error_kind=None,
        error_message=None,
        references=[],
        request_url=request_url,
    )


def _failed_result(
    *,
    source: str,
    status_code: int | None,
    error_kind: str,
    error_message: str,
    request_url: str,
) -> SeedSourceResult:
    return SeedSourceResult(
        source=source,
        status="failed",
        status_code=status_code,
        reference_count=0,
        error_kind=error_kind,
        error_message=error_message,
        references=[],
        request_url=request_url,
    )


def _extract_cve_official_references(payload: dict[str, Any]) -> list[str]:
    containers = payload.get("containers", {})
    cna_refs = containers.get("cna", {}).get("references", [])
    program_refs = containers.get("cveProgram", {}).get("references", [])
    references: list[str] = []
    for item in [*cna_refs, *program_refs]:
        url = item.get("url") if isinstance(item, dict) else None
        if isinstance(url, str) and url.strip():
            references.append(url)
    return references


def _extract_osv_references(payload: dict[str, Any]) -> list[str]:
    references: list[str] = []
    for item in payload.get("references", []):
        url = item.get("url") if isinstance(item, dict) else None
        if isinstance(url, str) and url.strip():
            references.append(url)
    return references


def _extract_github_advisory_references(payload: Any) -> list[str]:
    advisories = payload if isinstance(payload, list) else []
    references: list[str] = []
    for advisory in advisories:
        if not isinstance(advisory, dict):
            continue
        html_url = advisory.get("html_url")
        if isinstance(html_url, str) and html_url.strip():
            references.append(html_url)
        for item in advisory.get("references", []):
            if isinstance(item, str) and item.strip():
                references.append(item)
            elif isinstance(item, dict):
                url = item.get("url")
                if isinstance(url, str) and url.strip():
                    references.append(url)
    return references


def _extract_nvd_references(payload: dict[str, Any]) -> list[str]:
    vulnerabilities = payload.get("vulnerabilities", [])
    if not vulnerabilities:
        return []
    cve = vulnerabilities[0].get("cve", {})
    references: list[str] = []
    for item in cve.get("references", []):
        url = item.get("url") if isinstance(item, dict) else None
        if isinstance(url, str) and url.strip():
            references.append(url)
    return references


def fetch_seed_source(source: str, *, cve_id: str) -> SeedSourceResult:
    request_url = _build_request_url(source, cve_id)
    try:
        response = http_client.get(request_url, timeout=10.0)
    except httpx.RequestError as exc:
        return _failed_result(
            source=source,
            status_code=None,
            error_kind="network_error",
            error_message=str(exc),
            request_url=request_url,
        )
    except Exception as exc:  # pragma: no cover - defensive
        return _failed_result(
            source=source,
            status_code=None,
            error_kind="unexpected_error",
            error_message=str(exc),
            request_url=request_url,
        )

    if response.status_code == 404 and source in {"cve_official", "osv"}:
        return _not_found_result(source=source, status_code=404, request_url=request_url)

    if response.status_code >= 400:
        return _failed_result(
            source=source,
            status_code=response.status_code,
            error_kind="http_error",
            error_message=f"{response.status_code} {response.reason_phrase}",
            request_url=request_url,
        )

    try:
        payload = response.json()
    except (ValueError, TypeError, httpx.DecodingError) as exc:
        return _failed_result(
            source=source,
            status_code=response.status_code,
            error_kind="json_error",
            error_message=str(exc),
            request_url=request_url,
        )

    if source == "cve_official":
        return _success_result(
            source=source,
            status_code=response.status_code,
            references=_extract_cve_official_references(payload),
            request_url=request_url,
        )
    if source == "osv":
        return _success_result(
            source=source,
            status_code=response.status_code,
            references=_extract_osv_references(payload),
            request_url=request_url,
        )
    if source == "github_advisory":
        references = _extract_github_advisory_references(payload)
        if not references:
            return _not_found_result(source=source, status_code=response.status_code, request_url=request_url)
        return _success_result(
            source=source,
            status_code=response.status_code,
            references=references,
            request_url=request_url,
        )
    if source == "nvd":
        references = _extract_nvd_references(payload)
        if not references and not payload.get("vulnerabilities"):
            return _not_found_result(source=source, status_code=response.status_code, request_url=request_url)
        return _success_result(
            source=source,
            status_code=response.status_code,
            references=references,
            request_url=request_url,
        )

    raise ValueError(f"不支持的 seed 来源: {source}")


def resolve_all_seed_sources(cve_id: str) -> list[SeedSourceResult]:
    return [
        fetch_seed_source("cve_official", cve_id=cve_id),
        fetch_seed_source("osv", cve_id=cve_id),
        fetch_seed_source("github_advisory", cve_id=cve_id),
        fetch_seed_source("nvd", cve_id=cve_id),
    ]
