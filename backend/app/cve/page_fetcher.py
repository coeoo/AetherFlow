from __future__ import annotations

from typing import Any

import httpx


def fetch_page(url: str) -> dict[str, Any]:
    response = httpx.get(
        url,
        timeout=10.0,
        follow_redirects=True,
        headers={"User-Agent": "AetherFlow/0.1"},
    )
    response.raise_for_status()
    return {
        "url": str(response.url),
        "status_code": response.status_code,
        "content_type": response.headers.get("content-type", ""),
        "content": response.text,
    }
