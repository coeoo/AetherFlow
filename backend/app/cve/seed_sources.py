from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urldefrag

import httpx

from app import http_client


@dataclass(frozen=True)
class StructuredReference:
    url: str
    ref_type: str | None = None
    tags: tuple[str, ...] = ()
    source: str = ""


@dataclass(frozen=True)
class FixCommitEvidence:
    commit_sha: str
    repo_hint: str | None = None
    source: str = ""
    field_path: str = ""


@dataclass(frozen=True)
class FixedVersionEvidence:
    version: str
    version_type: str | None = None
    package_name: str | None = None
    package_ecosystem: str | None = None
    repo_hint: str | None = None
    source: str = ""
    field_path: str = ""


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
    structured_references: list[StructuredReference] = field(default_factory=list)
    fix_commits: list[FixCommitEvidence] = field(default_factory=list)
    fixed_versions: list[FixedVersionEvidence] = field(default_factory=list)


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


def _success_result(
    *,
    source: str,
    status_code: int,
    references: list[str],
    request_url: str,
    structured_references: list[StructuredReference] | None = None,
    fix_commits: list[FixCommitEvidence] | None = None,
    fixed_versions: list[FixedVersionEvidence] | None = None,
) -> SeedSourceResult:
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
        structured_references=structured_references or [],
        fix_commits=fix_commits or [],
        fixed_versions=fixed_versions or [],
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


@dataclass(frozen=True)
class _EnrichedExtraction:
    """Internal result from an enriched extract function."""
    references: list[str]
    structured_references: list[StructuredReference]
    fix_commits: list[FixCommitEvidence]
    fixed_versions: list[FixedVersionEvidence]


def _extract_cve_official_references(payload: dict[str, Any]) -> list[str]:
    return _extract_cve_official_enriched(payload).references


def _extract_cve_official_enriched(payload: dict[str, Any]) -> _EnrichedExtraction:
    containers = payload.get("containers", {})
    cna = containers.get("cna", {})
    cna_refs = cna.get("references", [])
    program_refs = containers.get("cveProgram", {}).get("references", [])
    adp_list = containers.get("adp", [])

    references: list[str] = []
    structured: list[StructuredReference] = []
    fix_commits: list[FixCommitEvidence] = []

    # cna + cveProgram references
    for item in [*cna_refs, *program_refs]:
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        if not isinstance(url, str) or not url.strip():
            continue
        references.append(url)
        raw_tags = item.get("tags", [])
        tags = tuple(str(t) for t in raw_tags if isinstance(t, str)) if isinstance(raw_tags, list) else ()
        structured.append(StructuredReference(url=url.strip(), tags=tags, source="cve_official"))

    # adp references
    for adp_entry in adp_list if isinstance(adp_list, list) else []:
        if not isinstance(adp_entry, dict):
            continue
        for item in adp_entry.get("references", []):
            if not isinstance(item, dict):
                continue
            url = item.get("url")
            if not isinstance(url, str) or not url.strip():
                continue
            references.append(url)
            raw_tags = item.get("tags", [])
            tags = tuple(str(t) for t in raw_tags if isinstance(t, str)) if isinstance(raw_tags, list) else ()
            structured.append(StructuredReference(url=url.strip(), tags=tags, source="cve_official"))

    # fix commits from affected[].versions[] where versionType == "git"
    for affected_entry in cna.get("affected", []):
        if not isinstance(affected_entry, dict):
            continue
        for version_entry in affected_entry.get("versions", []):
            if not isinstance(version_entry, dict):
                continue
            if version_entry.get("versionType") != "git":
                continue
            less_than = version_entry.get("lessThan")
            if isinstance(less_than, str) and less_than.strip():
                fix_commits.append(FixCommitEvidence(
                    commit_sha=less_than.strip(),
                    source="cve_official",
                    field_path="containers.cna.affected[].versions[].lessThan",
                ))

    return _EnrichedExtraction(
        references=references,
        structured_references=structured,
        fix_commits=fix_commits,
        fixed_versions=[],
    )


def _extract_osv_references(payload: dict[str, Any]) -> list[str]:
    return _extract_osv_enriched(payload).references


def _extract_osv_enriched(payload: dict[str, Any]) -> _EnrichedExtraction:
    references: list[str] = []
    structured: list[StructuredReference] = []
    fix_commits: list[FixCommitEvidence] = []
    fixed_versions: list[FixedVersionEvidence] = []

    for item in payload.get("references", []):
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        if not isinstance(url, str) or not url.strip():
            continue
        references.append(url)
        ref_type = item.get("type")
        structured.append(StructuredReference(
            url=url.strip(),
            ref_type=str(ref_type) if isinstance(ref_type, str) else None,
            source="osv",
        ))

    for affected_entry in payload.get("affected", []):
        if not isinstance(affected_entry, dict):
            continue
        pkg = affected_entry.get("package", {})
        pkg_name = pkg.get("name") if isinstance(pkg, dict) else None
        pkg_ecosystem = pkg.get("ecosystem") if isinstance(pkg, dict) else None

        for range_entry in affected_entry.get("ranges", []):
            if not isinstance(range_entry, dict):
                continue
            range_type = range_entry.get("type", "")
            repo_hint = range_entry.get("repo")
            repo_hint = str(repo_hint) if isinstance(repo_hint, str) and repo_hint.strip() else None

            for event in range_entry.get("events", []):
                if not isinstance(event, dict):
                    continue
                fixed_value = event.get("fixed")
                if not isinstance(fixed_value, str) or not fixed_value.strip():
                    continue

                if range_type == "GIT":
                    fix_commits.append(FixCommitEvidence(
                        commit_sha=fixed_value.strip(),
                        repo_hint=repo_hint,
                        source="osv",
                        field_path="affected[].ranges[].events[].fixed",
                    ))
                else:
                    fixed_versions.append(FixedVersionEvidence(
                        version=fixed_value.strip(),
                        version_type=str(range_type).lower() if range_type else None,
                        package_name=str(pkg_name) if isinstance(pkg_name, str) else None,
                        package_ecosystem=str(pkg_ecosystem) if isinstance(pkg_ecosystem, str) else None,
                        repo_hint=repo_hint,
                        source="osv",
                        field_path="affected[].ranges[].events[].fixed",
                    ))

    return _EnrichedExtraction(
        references=references,
        structured_references=structured,
        fix_commits=fix_commits,
        fixed_versions=fixed_versions,
    )


def _extract_github_advisory_references(payload: Any) -> list[str]:
    return _extract_github_advisory_enriched(payload).references


def _extract_github_advisory_enriched(payload: Any) -> _EnrichedExtraction:
    advisories = payload if isinstance(payload, list) else []
    references: list[str] = []
    structured: list[StructuredReference] = []
    fixed_versions: list[FixedVersionEvidence] = []

    for advisory in advisories:
        if not isinstance(advisory, dict):
            continue
        html_url = advisory.get("html_url")
        if isinstance(html_url, str) and html_url.strip():
            references.append(html_url)
            structured.append(StructuredReference(
                url=html_url.strip(),
                ref_type="ADVISORY",
                source="github_advisory",
            ))
        for item in advisory.get("references", []):
            if isinstance(item, str) and item.strip():
                references.append(item)
                structured.append(StructuredReference(url=item.strip(), source="github_advisory"))
            elif isinstance(item, dict):
                url = item.get("url")
                if isinstance(url, str) and url.strip():
                    references.append(url)
                    structured.append(StructuredReference(url=url.strip(), source="github_advisory"))

        source_code_location = advisory.get("source_code_location")
        repo_hint = str(source_code_location) if isinstance(source_code_location, str) and source_code_location.strip() else None

        for vuln in advisory.get("vulnerabilities", []):
            if not isinstance(vuln, dict):
                continue
            first_patched = vuln.get("first_patched_version")
            if not isinstance(first_patched, str) or not first_patched.strip():
                continue
            pkg = vuln.get("package", {})
            pkg_name = pkg.get("name") if isinstance(pkg, dict) else None
            pkg_ecosystem = pkg.get("ecosystem") if isinstance(pkg, dict) else None
            fixed_versions.append(FixedVersionEvidence(
                version=first_patched.strip(),
                version_type=None,
                package_name=str(pkg_name) if isinstance(pkg_name, str) else None,
                package_ecosystem=str(pkg_ecosystem) if isinstance(pkg_ecosystem, str) else None,
                repo_hint=repo_hint,
                source="github_advisory",
                field_path="vulnerabilities[].first_patched_version",
            ))

    return _EnrichedExtraction(
        references=references,
        structured_references=structured,
        fix_commits=[],
        fixed_versions=fixed_versions,
    )


def _extract_nvd_references(payload: dict[str, Any]) -> list[str]:
    return _extract_nvd_enriched(payload).references


def _extract_nvd_enriched(payload: dict[str, Any]) -> _EnrichedExtraction:
    vulnerabilities = payload.get("vulnerabilities", [])
    if not vulnerabilities:
        return _EnrichedExtraction(references=[], structured_references=[], fix_commits=[], fixed_versions=[])
    cve = vulnerabilities[0].get("cve", {})
    references: list[str] = []
    structured: list[StructuredReference] = []
    for item in cve.get("references", []):
        if not isinstance(item, dict):
            continue
        url = item.get("url")
        if not isinstance(url, str) or not url.strip():
            continue
        references.append(url)
        raw_tags = item.get("tags", [])
        tags = tuple(str(t) for t in raw_tags if isinstance(t, str)) if isinstance(raw_tags, list) else ()
        structured.append(StructuredReference(
            url=url.strip(),
            tags=tags,
            source="nvd",
        ))
    return _EnrichedExtraction(
        references=references,
        structured_references=structured,
        fix_commits=[],
        fixed_versions=[],
    )


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
        enriched = _extract_cve_official_enriched(payload)
        return _success_result(
            source=source,
            status_code=response.status_code,
            references=enriched.references,
            request_url=request_url,
            structured_references=enriched.structured_references,
            fix_commits=enriched.fix_commits,
            fixed_versions=enriched.fixed_versions,
        )
    if source == "osv":
        enriched = _extract_osv_enriched(payload)
        return _success_result(
            source=source,
            status_code=response.status_code,
            references=enriched.references,
            request_url=request_url,
            structured_references=enriched.structured_references,
            fix_commits=enriched.fix_commits,
            fixed_versions=enriched.fixed_versions,
        )
    if source == "github_advisory":
        enriched = _extract_github_advisory_enriched(payload)
        if not enriched.references:
            return _not_found_result(source=source, status_code=response.status_code, request_url=request_url)
        return _success_result(
            source=source,
            status_code=response.status_code,
            references=enriched.references,
            request_url=request_url,
            structured_references=enriched.structured_references,
            fix_commits=enriched.fix_commits,
            fixed_versions=enriched.fixed_versions,
        )
    if source == "nvd":
        enriched = _extract_nvd_enriched(payload)
        if not enriched.references and not payload.get("vulnerabilities"):
            return _not_found_result(source=source, status_code=response.status_code, request_url=request_url)
        return _success_result(
            source=source,
            status_code=response.status_code,
            references=enriched.references,
            request_url=request_url,
            structured_references=enriched.structured_references,
            fix_commits=enriched.fix_commits,
            fixed_versions=enriched.fixed_versions,
        )

    raise ValueError(f"不支持的 seed 来源: {source}")


def resolve_all_seed_sources(cve_id: str) -> list[SeedSourceResult]:
    return [
        fetch_seed_source("cve_official", cve_id=cve_id),
        fetch_seed_source("osv", cve_id=cve_id),
        fetch_seed_source("github_advisory", cve_id=cve_id),
        fetch_seed_source("nvd", cve_id=cve_id),
    ]
