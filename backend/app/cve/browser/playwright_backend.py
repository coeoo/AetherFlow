from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from time import perf_counter
from typing import TYPE_CHECKING
from typing import Any
from urllib.parse import urlparse

from app.cve.browser.a11y_pruner import prune_accessibility_tree
from app.cve.browser.base import BrowserBackend
from app.cve.browser.base import BrowserPageSnapshot
from app.cve.browser.base import PageLink
from app.cve.browser.markdown_extractor import extract_markdown_from_html
from app.cve.browser.page_role_classifier import classify_page_role

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from playwright.async_api import Browser
    from playwright.async_api import BrowserContext
    from playwright.async_api import Page
    from playwright.async_api import Playwright
    from playwright.async_api import Response


_LINK_EXTRACTION_SCRIPT = """
() => {
  const anchors = Array.from(document.querySelectorAll("a[href]"));
  return anchors.map((anchor) => {
    const href = anchor.href || anchor.getAttribute("href") || "";
    const text = (anchor.innerText || anchor.textContent || "").replace(/\\s+/g, " ").trim();
    const container = anchor.closest("li, p, td, th, article, section, div, main") || anchor.parentElement;
    const context = ((container?.innerText || container?.textContent || ""))
      .replace(/\\s+/g, " ")
      .trim();
    return { href, text, context };
  }).filter((item) => item.href);
}
"""

_A11Y_FALLBACK_SCRIPT = """
() => {
  const roleFor = (element) => {
    const tag = element.tagName.toLowerCase();
    if (/^h[1-6]$/.test(tag)) return "heading";
    if (tag === "a") return "link";
    if (tag === "p") return "paragraph";
    if (tag === "ul" || tag === "ol") return "list";
    if (tag === "li") return "listitem";
    if (tag === "table") return "table";
    if (tag === "tr") return "row";
    if (tag === "td" || tag === "th") return "cell";
    if (["span", "strong", "em", "label", "small"].includes(tag)) return "text";
    return "";
  };

  const normalize = (value) => (value || "").replace(/\\s+/g, " ").trim();

  const walk = (node) => {
    if (node.nodeType === Node.TEXT_NODE) {
      const text = normalize(node.textContent);
      return text ? { role: "text", name: text } : null;
    }

    if (node.nodeType !== Node.ELEMENT_NODE) {
      return null;
    }

    const role = roleFor(node);
    const children = Array.from(node.childNodes)
      .map((child) => walk(child))
      .filter(Boolean);

    if (!role) {
      if (children.length === 1) {
        return children[0];
      }
      if (children.length > 1) {
        return { role: "group", children };
      }
      return null;
    }

    const result = { role };
    const name = normalize(node.innerText || node.textContent || "");
    if (name) {
      result.name = name;
    }
    if (role === "link" && node.href) {
      result.url = node.href;
    }
    if (children.length) {
      result.children = children;
    }
    return result;
  };

  return walk(document.body);
}
"""


class PlaywrightPool:
    """管理固定数量 BrowserContext 的简单连接池。"""

    def __init__(
        self,
        *,
        pool_size: int = 3,
        headless: bool = True,
        cdp_endpoint: str = "",
    ):
        self._pool_size = max(1, pool_size)
        self._headless = headless
        self._cdp_endpoint = cdp_endpoint.strip()
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None
        self._contexts: list[BrowserContext] = []
        self._available: asyncio.Queue[BrowserContext] | None = None

    async def start(self) -> None:
        if self._browser is not None:
            return

        from playwright.async_api import async_playwright

        self._playwright = await async_playwright().start()
        chromium = self._playwright.chromium
        if self._cdp_endpoint:
            self._browser = await chromium.connect_over_cdp(self._cdp_endpoint)
        else:
            self._browser = await chromium.launch(headless=self._headless)

        self._available = asyncio.Queue(maxsize=self._pool_size)
        for _ in range(self._pool_size):
            context = await self._browser.new_context(ignore_https_errors=True)
            self._contexts.append(context)
            await self._available.put(context)

    @asynccontextmanager
    async def acquire(self) -> AsyncIterator[BrowserContext]:
        if self._available is None:
            raise RuntimeError("playwright_pool_not_started")
        context = await asyncio.wait_for(self._available.get(), timeout=60)
        try:
            yield context
        finally:
            await _close_context_pages(context)
            await self._available.put(context)

    async def stop(self) -> None:
        contexts = list(self._contexts)
        browser = self._browser
        playwright = self._playwright

        self._contexts = []
        self._browser = None
        self._playwright = None
        self._available = None

        for context in contexts:
            await _close_context_pages(context)
            await context.close()
        if browser is not None:
            await browser.close()
        if playwright is not None:
            await playwright.stop()


class PlaywrightBackend(BrowserBackend):
    def __init__(
        self,
        *,
        pool_size: int = 3,
        headless: bool = True,
        cdp_endpoint: str = "",
    ):
        self._pool = PlaywrightPool(
            pool_size=pool_size,
            headless=headless,
            cdp_endpoint=cdp_endpoint,
        )

    async def start(self) -> None:
        await self._pool.start()

    async def stop(self) -> None:
        await self._pool.stop()

    async def navigate(self, url: str, *, timeout_ms: int = 30_000) -> BrowserPageSnapshot:
        from playwright.async_api import TimeoutError as PlaywrightTimeoutError

        started_at = perf_counter()
        async with self._pool.acquire() as context:
            page = await context.new_page()
            response: Response | None = None
            try:
                try:
                    response = await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
                except PlaywrightTimeoutError:
                    # 规格要求页面超时时仍尽量用当前已加载内容构建快照。
                    response = None
                raw_accessibility = await _capture_accessibility_snapshot(page)
                raw_html = await page.content()
                links = await _extract_page_links(page, base_url=page.url or url)
                title = await page.title()
                final_url = page.url or url
            finally:
                await page.close()

        return BrowserPageSnapshot(
            url=url,
            final_url=final_url,
            status_code=_resolve_status_code(response),
            title=title,
            raw_html=raw_html,
            accessibility_tree=prune_accessibility_tree(raw_accessibility),
            markdown_content=extract_markdown_from_html(raw_html),
            links=links,
            page_role_hint=classify_page_role(final_url),
            fetch_duration_ms=int((perf_counter() - started_at) * 1000),
        )


async def _close_context_pages(context: BrowserContext) -> None:
    for page in list(context.pages):
        await page.close()


def _resolve_status_code(response: Response | None) -> int:
    if response is None:
        return 0
    return int(response.status)


async def _capture_accessibility_snapshot(page: Page) -> dict[str, Any]:
    accessibility = getattr(page, "accessibility", None)
    if accessibility is not None:
        try:
            snapshot = await accessibility.snapshot()
            if isinstance(snapshot, dict):
                return snapshot
        except Exception:
            pass

    fallback_snapshot = await page.evaluate(_A11Y_FALLBACK_SCRIPT)
    if isinstance(fallback_snapshot, dict):
        return fallback_snapshot
    return {}


async def _extract_page_links(page: Page, *, base_url: str) -> list[PageLink]:
    raw_links = await page.evaluate(_LINK_EXTRACTION_SCRIPT)
    if not isinstance(raw_links, list):
        return []

    page_domain = _normalize_domain(base_url)
    collected: list[PageLink] = []
    seen: set[tuple[str, str, str]] = set()

    for item in raw_links:
        if not isinstance(item, dict):
            continue
        link_url = str(item.get("href") or "").strip()
        if not link_url:
            continue
        text = _normalize_text(item.get("text"))
        context = _normalize_text(item.get("context"))[:300]
        dedupe_key = (link_url, text, context)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        collected.append(
            PageLink(
                url=link_url,
                text=text,
                context=context,
                is_cross_domain=_normalize_domain(link_url) != page_domain,
                estimated_target_role=classify_page_role(link_url),
            )
        )

    return collected


def _normalize_domain(url: str) -> str:
    return urlparse(url).netloc.lower()


def _normalize_text(value: object) -> str:
    return " ".join(str(value or "").split()).strip()
