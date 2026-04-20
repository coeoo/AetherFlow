from __future__ import annotations

import importlib.util
import os
from threading import Lock
from typing import Any

import httpx


_SOCKS_PROXY_ENV_KEYS = ("ALL_PROXY", "all_proxy")
_SOCKS_IMPORT_ERROR_MARKER = "Using SOCKS proxy"
_PROXY_ENV_LOCK = Lock()


def _has_socksio() -> bool:
    return importlib.util.find_spec("socksio") is not None


def _has_socks_proxy_env() -> bool:
    for key in _SOCKS_PROXY_ENV_KEYS:
        value = str(os.environ.get(key) or "").strip().lower()
        if value.startswith("socks"):
            return True
    return False


def _pop_socks_proxy_env() -> dict[str, str]:
    removed: dict[str, str] = {}
    for key in _SOCKS_PROXY_ENV_KEYS:
        value = os.environ.get(key)
        if value is None:
            continue
        if str(value).strip().lower().startswith("socks"):
            removed[key] = value
            os.environ.pop(key, None)
    return removed


def _restore_socks_proxy_env(removed: dict[str, str]) -> None:
    for key, value in removed.items():
        os.environ[key] = value


def _should_retry_without_socks_proxy(exc: ImportError, kwargs: dict[str, Any]) -> bool:
    if _SOCKS_IMPORT_ERROR_MARKER not in str(exc):
        return False
    if kwargs.get("trust_env") is False:
        return False
    if kwargs.get("proxy") is not None:
        return False
    if _has_socksio():
        return False
    return _has_socks_proxy_env()


def request(method: str, url: str, **kwargs):
    try:
        return httpx.request(method, url, **kwargs)
    except ImportError as exc:
        if not _should_retry_without_socks_proxy(exc, kwargs):
            raise

    # 缺少 socksio 时，临时移除 ALL_PROXY/all_proxy，让 httpx 回退到
    # HTTP_PROXY/HTTPS_PROXY 或直连，避免整个流程在 Client 初始化阶段失败。
    with _PROXY_ENV_LOCK:
        removed = _pop_socks_proxy_env()
        try:
            return httpx.request(method, url, **kwargs)
        finally:
            _restore_socks_proxy_env(removed)


def get(url: str, **kwargs):
    return request("GET", url, **kwargs)


def post(url: str, **kwargs):
    return request("POST", url, **kwargs)
