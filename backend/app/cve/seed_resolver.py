from __future__ import annotations

import httpx


def resolve_seed_references(cve_id: str) -> list[str]:
    response = httpx.get(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
        timeout=10.0,
    )
    response.raise_for_status()
    payload = response.json()

    vulnerabilities = payload.get("vulnerabilities") or []
    if not vulnerabilities:
        return []

    cve = vulnerabilities[0].get("cve") or {}
    references = cve.get("references") or []
    resolved: list[str] = []
    for reference in references:
        url = reference.get("url")
        if isinstance(url, str) and url:
            resolved.append(url)
    return resolved
