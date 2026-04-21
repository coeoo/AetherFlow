from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol
from typing import runtime_checkable


@dataclass(frozen=True)
class PageLink:
    url: str
    text: str
    context: str
    is_cross_domain: bool
    estimated_target_role: str


@dataclass(frozen=True)
class BrowserPageSnapshot:
    url: str
    final_url: str
    status_code: int
    title: str
    raw_html: str
    accessibility_tree: str
    markdown_content: str
    links: list[PageLink]
    page_role_hint: str
    fetch_duration_ms: int


@runtime_checkable
class BrowserBackend(Protocol):
    async def start(self) -> None: ...

    async def stop(self) -> None: ...

    async def navigate(
        self, url: str, *, timeout_ms: int = 30_000
    ) -> BrowserPageSnapshot: ...
