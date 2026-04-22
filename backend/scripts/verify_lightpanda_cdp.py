from __future__ import annotations

import argparse
import asyncio
import json
from time import perf_counter
from typing import Any

from playwright.async_api import Error as PlaywrightError
from playwright.async_api import TimeoutError as PlaywrightTimeoutError
from playwright.async_api import async_playwright

from app.cve.browser.playwright_backend import _LINK_EXTRACTION_SCRIPT

DEFAULT_TEST_URL = "https://httpbin.org/html"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m backend.scripts.verify_lightpanda_cdp",
        description="验证通过 CDP 端点连接 Lightpanda 的可行性。",
    )
    parser.add_argument(
        "--endpoint",
        required=True,
        help="CDP WebSocket 端点，例如 ws://localhost:9222/devtools/browser/xxx",
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_TEST_URL,
        help=f"连接后要打开的页面，默认 {DEFAULT_TEST_URL}。",
    )
    parser.add_argument(
        "--timeout-ms",
        type=int,
        default=15_000,
        help="单步超时，默认 15000ms。",
    )
    return parser.parse_args(argv)


async def _measure_step(name: str, action) -> dict[str, Any]:
    started_at = perf_counter()
    try:
        payload = await action()
        return {
            "step": name,
            "ok": True,
            "duration_ms": int((perf_counter() - started_at) * 1000),
            "details": payload,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "step": name,
            "ok": False,
            "duration_ms": int((perf_counter() - started_at) * 1000),
            "error_type": type(exc).__name__,
            "error": str(exc),
        }


async def _run_verification(
    *,
    endpoint: str,
    url: str,
    timeout_ms: int,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "endpoint": endpoint,
        "url": url,
        "timeout_ms": timeout_ms,
        "steps": [],
    }
    playwright = None
    browser = None
    context = None
    page = None

    async def connect_browser():
        nonlocal playwright, browser
        playwright = await async_playwright().start()
        browser = await playwright.chromium.connect_over_cdp(endpoint, timeout=timeout_ms)
        return {"browser_connected": True}

    connect_result = await _measure_step("connect_over_cdp", connect_browser)
    report["steps"].append(connect_result)
    if not connect_result["ok"]:
        report["summary"] = "CDP 连接失败"
        return report

    try:
        context = browser.contexts[0] if browser and browser.contexts else await browser.new_context(ignore_https_errors=True)
        page = await context.new_page()
        page.set_default_timeout(timeout_ms)

        async def goto_page():
            response = await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            return {
                "final_url": page.url,
                "status_code": response.status if response is not None else None,
            }

        async def capture_a11y():
            snapshot = await page.accessibility.snapshot()
            return {
                "has_snapshot": snapshot is not None,
                "root_role": snapshot.get("role") if isinstance(snapshot, dict) else None,
            }

        async def capture_content():
            html = await page.content()
            return {
                "content_length": len(html),
            }

        async def extract_links():
            links = await page.evaluate(_LINK_EXTRACTION_SCRIPT)
            extracted = links if isinstance(links, list) else []
            return {
                "link_count": len(extracted),
                "sample_links": extracted[:5],
            }

        for step_name, action in [
            ("goto_page", goto_page),
            ("accessibility_snapshot", capture_a11y),
            ("page_content", capture_content),
            ("link_extraction", extract_links),
        ]:
            step_result = await _measure_step(step_name, action)
            report["steps"].append(step_result)
            if not step_result["ok"]:
                report["summary"] = f"{step_name} 失败"
                return report

        report["summary"] = "验证通过"
        return report
    finally:
        if page is not None:
            await page.close()
        if context is not None:
            await context.close()
        if browser is not None:
            await browser.close()
        if playwright is not None:
            await playwright.stop()


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        report = asyncio.run(
            _run_verification(
                endpoint=args.endpoint,
                url=args.url,
                timeout_ms=args.timeout_ms,
            )
        )
    except (PlaywrightError, PlaywrightTimeoutError, OSError) as exc:
        report = {
            "endpoint": args.endpoint,
            "url": args.url,
            "timeout_ms": args.timeout_ms,
            "summary": "验证启动失败",
            "error_type": type(exc).__name__,
            "error": str(exc),
        }
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 1

    print(json.dumps(report, ensure_ascii=False, indent=2))
    failed_steps = [step for step in report.get("steps", []) if not step.get("ok")]
    return 0 if not failed_steps else 1


if __name__ == "__main__":
    raise SystemExit(main())
