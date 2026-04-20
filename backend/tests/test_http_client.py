import os

import pytest

from app import http_client


def test_request_retries_without_socks_all_proxy_when_socksio_missing(monkeypatch) -> None:
    calls: list[dict[str, str | None]] = []

    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:7890")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:7890")
    monkeypatch.setenv("ALL_PROXY", "socks5h://127.0.0.1:7890")
    monkeypatch.setenv("all_proxy", "socks5h://127.0.0.1:7890")
    monkeypatch.setattr(http_client, "_has_socksio", lambda: False)

    def _fake_request(method: str, url: str, **kwargs):
        calls.append(
            {
                "method": method,
                "url": url,
                "ALL_PROXY": os.environ.get("ALL_PROXY"),
                "all_proxy": os.environ.get("all_proxy"),
            }
        )
        if len(calls) == 1:
            raise ImportError(
                "Using SOCKS proxy, but the 'socksio' package is not installed."
            )
        return {"ok": True, "url": url, "method": method, "kwargs": kwargs}

    monkeypatch.setattr(http_client.httpx, "request", _fake_request)

    response = http_client.request("GET", "https://example.com", timeout=10.0)

    assert response["ok"] is True
    assert len(calls) == 2
    assert calls[0]["ALL_PROXY"] == "socks5h://127.0.0.1:7890"
    assert calls[0]["all_proxy"] == "socks5h://127.0.0.1:7890"
    assert calls[1]["ALL_PROXY"] is None
    assert calls[1]["all_proxy"] is None
    assert os.environ["ALL_PROXY"] == "socks5h://127.0.0.1:7890"
    assert os.environ["all_proxy"] == "socks5h://127.0.0.1:7890"


def test_request_does_not_retry_for_non_socks_import_error(monkeypatch) -> None:
    monkeypatch.setenv("ALL_PROXY", "socks5h://127.0.0.1:7890")
    monkeypatch.setattr(http_client, "_has_socksio", lambda: False)

    def _fake_request(method: str, url: str, **kwargs):
        raise ImportError("another import problem")

    monkeypatch.setattr(http_client.httpx, "request", _fake_request)

    with pytest.raises(ImportError, match="another import problem"):
        http_client.request("GET", "https://example.com")
