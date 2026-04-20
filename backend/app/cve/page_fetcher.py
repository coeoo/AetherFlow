from __future__ import annotations

from typing import Any

import httpx

from app import http_client
from app.cve.source_trace import record_source_fetch


def fetch_page(session, *, run, url: str) -> dict[str, Any]:
    request_snapshot = {"url": url}
    response: httpx.Response | None = None

    try:
        response = http_client.get(
            url,
            timeout=10.0,
            follow_redirects=True,
            headers={"User-Agent": "AetherFlow/0.1"},
        )
        response.raise_for_status()
        snapshot = {
            "url": str(response.url),
            "status_code": response.status_code,
            "content_type": response.headers.get("content-type", ""),
            "content": response.text,
        }
        record_source_fetch(
            session,
            run=run,
            source_type="cve_page_fetch",
            source_ref=url,
            status="succeeded",
            request_snapshot=request_snapshot,
            response_meta={
                "final_url": snapshot["url"],
                "status_code": snapshot["status_code"],
                "content_type": snapshot["content_type"],
            },
        )
        return snapshot
    except Exception as exc:
        response_meta: dict[str, object] = {}
        if response is not None:
            response_meta["final_url"] = str(response.url)
            response_meta["status_code"] = response.status_code
            response_meta["content_type"] = response.headers.get("content-type", "")
        record_source_fetch(
            session,
            run=run,
            source_type="cve_page_fetch",
            source_ref=url,
            status="failed",
            request_snapshot=request_snapshot,
            response_meta=response_meta,
            error_message=str(exc),
        )
        raise
