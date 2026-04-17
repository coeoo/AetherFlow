from __future__ import annotations

from urllib.parse import urldefrag

from app.cve.seed_sources import resolve_all_seed_sources
from app.cve.source_trace import record_source_fetch


def _merge_seed_references(source_results) -> list[str]:
    merged: list[str] = []
    seen: set[str] = set()
    for result in source_results:
        for reference in result.references:
            normalized = urldefrag(reference).url
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            merged.append(normalized)
    return merged


def _select_status_code(source_results) -> int | None:
    for result in source_results:
        if result.status == "success" and result.status_code is not None:
            return result.status_code
    for result in source_results:
        if result.status_code is not None:
            return result.status_code
    return None


def _build_request_snapshot(cve_id: str, source_results) -> dict[str, object]:
    return {
        "cve_id": cve_id,
        "sources": [result.source for result in source_results],
        "request_urls": {
            result.source: result.request_url for result in source_results
        },
    }


def _build_response_meta(references: list[str], source_results) -> dict[str, object]:
    return {
        "status_code": _select_status_code(source_results),
        "reference_count": len(references),
        "source_results": [
            {
                "source": result.source,
                "status": result.status,
                "status_code": result.status_code,
                "reference_count": result.reference_count,
                "error_kind": result.error_kind,
                "error_message": result.error_message,
            }
            for result in source_results
        ],
    }

def resolve_seed_references(session, *, run, cve_id: str) -> list[str]:
    source_results = resolve_all_seed_sources(cve_id)
    request_snapshot = _build_request_snapshot(cve_id, source_results)
    references = _merge_seed_references(source_results)
    response_meta = _build_response_meta(references, source_results)
    all_failed = all(result.status == "failed" for result in source_results)

    record_source_fetch(
        session,
        run=run,
        source_type="cve_seed_resolve",
        source_ref=cve_id,
        status="failed" if all_failed else "succeeded",
        request_snapshot=request_snapshot,
        response_meta=response_meta,
        error_message="所有 seed 来源都失败，无法解析参考链接。" if all_failed else None,
    )

    if all_failed:
        raise RuntimeError("所有 seed 来源都失败，无法解析参考链接。")

    return references
