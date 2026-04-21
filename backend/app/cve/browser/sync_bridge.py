from __future__ import annotations

import asyncio
import logging
from concurrent.futures import Future
from threading import Event
from threading import Thread
from typing import Coroutine
from typing import TypeVar

from app.cve.browser.base import BrowserBackend
from app.cve.browser.base import BrowserPageSnapshot


_T = TypeVar("_T")
_logger = logging.getLogger(__name__)


class SyncBrowserBridge:
    """在独立线程事件循环中运行 async 浏览器操作，暴露同步接口。"""

    def __init__(self, backend: BrowserBackend):
        self._backend = backend
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: Thread | None = None
        self._loop_ready = Event()

    def start(self) -> None:
        if self._thread is not None and self._thread.is_alive():
            return

        self._loop_ready.clear()
        self._thread = Thread(
            target=self._run_event_loop,
            name="cve-browser-bridge",
            daemon=True,
        )
        self._thread.start()
        if not self._loop_ready.wait(timeout=10):
            raise RuntimeError("browser_bridge_loop_start_timeout")
        self._submit(self._backend.start())

    def navigate(self, url: str, *, timeout_ms: int = 30_000) -> BrowserPageSnapshot:
        if self._loop is None:
            raise RuntimeError("browser_bridge_not_started")
        return self._submit(
            self._backend.navigate(url, timeout_ms=timeout_ms),
            timeout_seconds=_resolve_submit_timeout_seconds(timeout_ms),
        )

    def stop(self) -> None:
        loop = self._loop
        thread = self._thread
        if loop is None or thread is None:
            return

        try:
            self._submit(self._backend.stop(), timeout_seconds=10.0)
        except Exception:
            _logger.warning("浏览器后端 stop 超时或失败，继续关闭事件循环", exc_info=True)
        finally:
            self._loop = None
            self._thread = None
            loop.call_soon_threadsafe(loop.stop)
            thread.join(timeout=5)

    def _run_event_loop(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        self._loop_ready.set()
        try:
            loop.run_forever()
        finally:
            pending = asyncio.all_tasks(loop)
            for task in pending:
                task.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.close()

    def _submit(self, coroutine: Coroutine[object, object, _T], *, timeout_seconds: float = 60.0) -> _T:
        loop = self._loop
        if loop is None:
            raise RuntimeError("browser_bridge_not_started")
        future: Future[_T] = asyncio.run_coroutine_threadsafe(coroutine, loop)
        return future.result(timeout=timeout_seconds)


def _resolve_submit_timeout_seconds(timeout_ms: int) -> float:
    """桥接层等待时间要略大于浏览器导航超时，避免桥接先于浏览器报超时。"""
    return max(timeout_ms / 1000 + 10, 60.0)
