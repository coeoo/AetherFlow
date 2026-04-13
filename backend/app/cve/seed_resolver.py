from __future__ import annotations

import httpx

from app.cve.source_trace import record_source_fetch


def _build_nvd_cve_url(cve_id: str) -> str:
    return f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

def resolve_seed_references(session, *, run, cve_id: str) -> list[str]:
    request_url = _build_nvd_cve_url(cve_id)
    request_snapshot = {"cve_id": cve_id, "url": request_url}
    response: httpx.Response | None = None

    try:
        response = httpx.get(request_url, timeout=10.0)
        response.raise_for_status()
        payload = response.json()

        vulnerabilities = payload.get("vulnerabilities") or []
        if not vulnerabilities:
            record_source_fetch(
                session,
                run=run,
                source_type="cve_seed_resolve",
                source_ref=cve_id,
                status="succeeded",
                request_snapshot=request_snapshot,
                response_meta={
                    "status_code": response.status_code,
                    "reference_count": 0,
                },
            )
            return []

        cve = vulnerabilities[0].get("cve") or {}
        references = cve.get("references") or []
        resolved: list[str] = []
        for reference in references:
            url = reference.get("url")
            if isinstance(url, str) and url:
                resolved.append(url)

        record_source_fetch(
            session,
            run=run,
            source_type="cve_seed_resolve",
            source_ref=cve_id,
            status="succeeded",
            request_snapshot=request_snapshot,
            response_meta={
                "status_code": response.status_code,
                "reference_count": len(resolved),
            },
        )
        return resolved
    except Exception as exc:
        response_meta: dict[str, object] = {}
        if response is not None:
            response_meta["status_code"] = response.status_code
        record_source_fetch(
            session,
            run=run,
            source_type="cve_seed_resolve",
            source_ref=cve_id,
            status="failed",
            request_snapshot=request_snapshot,
            response_meta=response_meta,
            error_message=str(exc),
        )
        raise
