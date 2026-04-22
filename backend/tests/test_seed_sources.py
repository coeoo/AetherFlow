import json

import httpx


def _make_response(*, url: str, status_code: int, json_data=None, content: bytes | None = None) -> httpx.Response:
    request = httpx.Request("GET", url)
    if json_data is not None:
        return httpx.Response(status_code, json=json_data, request=request)
    return httpx.Response(status_code, content=content or b"", request=request)


def test_cve_official_source_merges_cna_and_cve_program_references(monkeypatch) -> None:
    from app.cve.seed_sources import fetch_seed_source

    cve_id = "CVE-2024-3094"
    url = f"https://cveawg.mitre.org/api/cve/{cve_id}"

    def _fake_http_get(got_url: str, **kwargs) -> httpx.Response:
        assert got_url == url
        assert kwargs["timeout"] == 10.0
        return _make_response(
            url=got_url,
            status_code=200,
            json_data={
                "containers": {
                    "cna": {
                        "references": [
                            {"url": " https://example.com/cna/advisory "},
                            {"url": "https://example.com/shared#cna"},
                        ]
                    },
                    "cveProgram": {
                        "references": [
                            {"url": "https://example.com/shared#program"},
                            {"url": "https://example.com/program/ref"},
                        ]
                    },
                }
            },
        )

    monkeypatch.setattr("app.cve.seed_sources.http_client.get", _fake_http_get)

    result = fetch_seed_source("cve_official", cve_id=cve_id)
    assert result.status == "success"
    # 官方来源内部要求去重并保持 container 顺序：cna -> cveProgram
    assert result.references == [
        "https://example.com/cna/advisory",
        "https://example.com/shared",
        "https://example.com/program/ref",
    ]
    assert result.reference_count == 3
    assert result.status_code == 200
    assert result.error_kind is None
    assert result.error_message is None


def test_source_result_marks_not_found_without_error(monkeypatch) -> None:
    from app.cve.seed_sources import fetch_seed_source

    cve_id = "CVE-2099-0001"
    url = f"https://api.osv.dev/v1/vulns/{cve_id}"

    def _fake_http_get(got_url: str, **kwargs) -> httpx.Response:
        assert got_url == url
        assert kwargs["timeout"] == 10.0
        return _make_response(url=got_url, status_code=404, json_data={"code": 5, "message": "not found"})

    monkeypatch.setattr("app.cve.seed_sources.http_client.get", _fake_http_get)

    result = fetch_seed_source("osv", cve_id=cve_id)
    assert result.status == "not_found"
    assert result.references == []
    assert result.reference_count == 0
    assert result.status_code == 404
    assert result.error_kind is None
    assert result.error_message is None


def test_source_result_classifies_http_and_json_failures(monkeypatch) -> None:
    from app.cve.seed_sources import fetch_seed_source

    cve_id = "CVE-2024-3094"
    nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    official_url = f"https://cveawg.mitre.org/api/cve/{cve_id}"

    def _fake_http_get(got_url: str, **kwargs) -> httpx.Response:
        assert kwargs["timeout"] == 10.0
        if got_url == nvd_url:
            # 503 -> http_error
            return _make_response(url=got_url, status_code=503, content=b"unavailable")
        if got_url == official_url:
            # 200 但 JSON 非法 -> json_error
            return _make_response(url=got_url, status_code=200, content=b"{")
        raise AssertionError(f"未知 URL: {got_url}")

    monkeypatch.setattr("app.cve.seed_sources.http_client.get", _fake_http_get)

    http_failed = fetch_seed_source("nvd", cve_id=cve_id)
    assert http_failed.status == "failed"
    assert http_failed.status_code == 503
    assert http_failed.error_kind == "http_error"
    assert "503" in (http_failed.error_message or "")

    json_failed = fetch_seed_source("cve_official", cve_id=cve_id)
    assert json_failed.status == "failed"
    assert json_failed.status_code == 200
    assert json_failed.error_kind == "json_error"
    assert json_failed.error_message


def test_source_result_classifies_network_failures(monkeypatch) -> None:
    from app.cve.seed_sources import fetch_seed_source

    cve_id = "CVE-2024-3094"
    url = f"https://api.github.com/advisories?cve_id={cve_id}&per_page=20"

    def _fake_http_get(got_url: str, **kwargs) -> httpx.Response:
        assert got_url == url
        assert kwargs["timeout"] == 10.0
        raise httpx.ConnectError("connect failed", request=httpx.Request("GET", got_url))

    monkeypatch.setattr("app.cve.seed_sources.http_client.get", _fake_http_get)

    result = fetch_seed_source("github_advisory", cve_id=cve_id)
    assert result.status == "failed"
    assert result.status_code is None
    assert result.error_kind == "network_error"
    assert "connect failed" in (result.error_message or "")
