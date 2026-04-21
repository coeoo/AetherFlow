from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from contextlib import contextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from threading import Thread

import pytest
from playwright.async_api import TimeoutError as PlaywrightTimeoutError

from app.cve.browser.a11y_pruner import MAX_A11Y_CHARS
from app.cve.browser.a11y_pruner import prune_accessibility_tree
from app.cve.browser.base import BrowserPageSnapshot
from app.cve.browser.base import BrowserBackend
from app.cve.browser.markdown_extractor import MAX_MARKDOWN_CHARS
from app.cve.browser.markdown_extractor import extract_markdown_from_html
from app.cve.browser.page_role_classifier import classify_page_role
from app.cve.browser.playwright_backend import PageLink
from app.cve.browser.playwright_backend import PlaywrightBackend
from app.cve.browser.playwright_backend import PlaywrightPool
from app.cve.browser.sync_bridge import SyncBrowserBridge


HTML_PAGE = """\
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Browser Infra Test</title>
  </head>
  <body>
    <main>
      <h1>CVE-2022-2509</h1>
      <p>GnuTLS Double Free vulnerability</p>
      <ul>
        <li>
          <a href="/tracker/CVE-2022-2509">Debian Tracker</a>
        </li>
        <li>
          <a href="https://github.com/user/repo/commit/abc1234">Upstream Fix</a>
        </li>
      </ul>
    </main>
  </body>
</html>
"""


class _SimpleHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        encoded = HTML_PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


@contextmanager
def _serve_test_page():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _SimpleHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/index.html"
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def test_playwright_pool_lifecycle_can_open_simple_page() -> None:
    async def _exercise() -> None:
        pool = PlaywrightPool(pool_size=1, headless=True)
        await pool.start()
        try:
            async with pool.acquire() as context:
                page = await context.new_page()
                with _serve_test_page() as url:
                    response = await page.goto(url, wait_until="domcontentloaded", timeout=30_000)
                    assert response is not None
                    assert response.status == 200
                    assert await page.title() == "Browser Infra Test"
        finally:
            await pool.stop()

    asyncio.run(_exercise())


def test_prune_accessibility_tree_keeps_semantic_nodes_and_limits_length() -> None:
    pruned = prune_accessibility_tree(
        {
            "role": "WebArea",
            "name": "root",
            "children": [
                {
                    "role": "heading",
                    "name": "CVE-2022-2509",
                },
                {
                    "role": "list",
                    "children": [
                        {
                            "role": "listitem",
                            "children": [
                                {
                                    "role": "link",
                                    "name": "upstream fix",
                                    "url": "https://gitlab.com/gnutls/gnutls/-/commit/ce37f9eb",
                                },
                                {
                                    "role": "text",
                                    "name": "Fixed in gnutls28 3.7.7-2",
                                },
                            ],
                        }
                    ],
                },
                {
                    "role": "img",
                    "name": "decorative",
                },
            ],
        }
    )

    assert 'heading "CVE-2022-2509"' in pruned
    assert 'link "upstream fix" -> https://gitlab.com/gnutls/gnutls/-/commit/ce37f9eb' in pruned
    assert "decorative" not in pruned
    assert len(pruned) <= MAX_A11Y_CHARS


def test_classify_page_role_returns_expected_role() -> None:
    assert (
        classify_page_role("https://security-tracker.debian.org/tracker/CVE-2022-2509")
        == "tracker_page"
    )
    assert classify_page_role("https://nvd.nist.gov/vuln/detail/CVE-2022-2509") == "advisory_page"
    assert classify_page_role("https://github.com/advisories/GHSA-abcd-1234") == "advisory_page"
    assert classify_page_role("https://github.com/user/repo/commit/abc123") == "commit_page"
    assert classify_page_role("https://gitlab.com/org/proj/-/merge_requests/42") == "commit_page"
    assert classify_page_role("https://example.com/file.patch") == "download_page"
    assert (
        classify_page_role("https://www.openwall.com/lists/oss-security/2022/08/01/1")
        == "mailing_list_page"
    )


@dataclass
class _FakeBrowserBackend(BrowserBackend):
    started: bool = False
    stopped: bool = False

    async def start(self) -> None:
        self.started = True

    async def stop(self) -> None:
        self.stopped = True

    async def navigate(self, url: str, *, timeout_ms: int = 30_000) -> BrowserPageSnapshot:
        return BrowserPageSnapshot(
            url=url,
            final_url=url,
            status_code=200,
            title="Fake Title",
            raw_html="<html><body>ok</body></html>",
            accessibility_tree='heading "Fake Title"',
            markdown_content="Fake Title",
            links=[],
            page_role_hint="unknown_page",
            fetch_duration_ms=12,
        )


def test_sync_browser_bridge_can_navigate_from_sync_context() -> None:
    backend = _FakeBrowserBackend()
    bridge = SyncBrowserBridge(backend)

    bridge.start()
    try:
        snapshot = bridge.navigate("https://example.com/page")
    finally:
        bridge.stop()

    assert backend.started is True
    assert backend.stopped is True
    assert snapshot.title == "Fake Title"
    assert snapshot.status_code == 200


def test_sync_browser_bridge_derives_submit_timeout_from_navigation_budget(monkeypatch) -> None:
    backend = _FakeBrowserBackend()
    bridge = SyncBrowserBridge(backend)
    bridge._loop = object()  # type: ignore[assignment]
    captured: dict[str, float] = {}

    def _fake_submit(self, coroutine, *, timeout_seconds: float = 60.0):
        captured["timeout_seconds"] = timeout_seconds
        coroutine.close()
        return BrowserPageSnapshot(
            url="https://example.com/page",
            final_url="https://example.com/page",
            status_code=200,
            title="Budgeted",
            raw_html="",
            accessibility_tree="",
            markdown_content="",
            links=[],
            page_role_hint="unknown_page",
            fetch_duration_ms=1,
        )

    monkeypatch.setattr(SyncBrowserBridge, "_submit", _fake_submit)

    bridge.navigate("https://example.com/page", timeout_ms=120_000)

    assert captured["timeout_seconds"] == pytest.approx(130.0)


def test_markdown_extractor_returns_truncated_markdown_text() -> None:
    markdown = extract_markdown_from_html(
        """
        <html>
          <body>
            <main>
              <h1>CVE-2022-2509</h1>
              <p>GnuTLS Double Free vulnerability</p>
              <a href="https://example.com/patch.diff">Patch</a>
            </main>
          </body>
        </html>
        """
    )

    assert "CVE-2022-2509" in markdown
    assert "GnuTLS Double Free vulnerability" in markdown
    assert len(markdown) <= MAX_MARKDOWN_CHARS


def test_playwright_backend_timeout_returns_partial_snapshot(monkeypatch) -> None:
    class _FakePage:
        def __init__(self) -> None:
            self.url = "https://example.com/partial"
            self.closed = False

        async def goto(self, url: str, *, wait_until: str, timeout: int):
            raise PlaywrightTimeoutError("timed out")

        async def content(self) -> str:
            return "<html><body><h1>Partial</h1></body></html>"

        async def title(self) -> str:
            return "Partial Title"

        async def close(self) -> None:
            self.closed = True

    class _FakeContext:
        def __init__(self, page: _FakePage) -> None:
            self._page = page

        async def new_page(self) -> _FakePage:
            return self._page

    fake_page = _FakePage()
    fake_context = _FakeContext(fake_page)

    @asynccontextmanager
    async def _fake_acquire():
        yield fake_context

    backend = PlaywrightBackend(pool_size=1, headless=True)
    monkeypatch.setattr(backend._pool, "acquire", _fake_acquire)

    async def _fake_capture_accessibility_snapshot(page):
        return {"role": "heading", "name": "Partial"}

    async def _fake_extract_page_links(page, *, base_url):
        return [
            PageLink(
                url="https://example.com/fix.patch",
                text="fix",
                context="partial context",
                is_cross_domain=False,
                estimated_target_role="download_page",
            )
        ]

    monkeypatch.setattr(
        "app.cve.browser.playwright_backend._capture_accessibility_snapshot",
        _fake_capture_accessibility_snapshot,
    )
    monkeypatch.setattr(
        "app.cve.browser.playwright_backend._extract_page_links",
        _fake_extract_page_links,
    )

    snapshot = asyncio.run(backend.navigate("https://example.com/original", timeout_ms=10))

    assert snapshot.url == "https://example.com/original"
    assert snapshot.final_url == "https://example.com/partial"
    assert snapshot.status_code == 0
    assert snapshot.title == "Partial Title"
    assert "Partial" in snapshot.raw_html
    assert snapshot.links[0].estimated_target_role == "download_page"
    assert fake_page.closed is True


def test_playwright_backend_navigate_returns_snapshot() -> None:
    async def _exercise() -> None:
        backend = PlaywrightBackend(pool_size=1, headless=True)
        await backend.start()
        try:
            with _serve_test_page() as url:
                snapshot = await backend.navigate(url)
        finally:
            await backend.stop()

        assert snapshot.status_code == 200
        assert snapshot.title == "Browser Infra Test"
        assert snapshot.url == url
        assert snapshot.final_url == url
        assert snapshot.page_role_hint == "unknown_page"
        assert snapshot.fetch_duration_ms >= 0
        assert snapshot.raw_html
        assert snapshot.markdown_content
        assert len(snapshot.links) >= 2

    asyncio.run(_exercise())
