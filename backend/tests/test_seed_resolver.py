import httpx

from app.cve.seed_resolver import resolve_seed_references
from app.cve.service import create_cve_run
from app.models import SourceFetchRecord


def test_resolve_seed_references_records_success_trace(db_session, monkeypatch) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.commit()

    cve_id = run.cve_id
    request_urls = {
        "cve_official": f"https://cveawg.mitre.org/api/cve/{cve_id}",
        "osv": f"https://api.osv.dev/v1/vulns/{cve_id}",
        "github_advisory": f"https://api.github.com/advisories?cve_id={cve_id}&per_page=20",
        "nvd": f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
    }

    called: list[str] = []

    def _fake_http_get(url: str, **kwargs) -> httpx.Response:
        assert kwargs["timeout"] == 10.0
        called.append(url)
        request = httpx.Request("GET", url)
        if url == request_urls["cve_official"]:
            return httpx.Response(
                200,
                json={
                    "containers": {
                        "cna": {
                            "references": [
                                {"url": "https://example.com/official/advisory"},
                                {"url": "https://example.com/shared#official"},
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
                request=request,
            )
        if url == request_urls["osv"]:
            return httpx.Response(
                200,
                json={
                    "references": [
                        {"url": "https://example.com/osv/ref"},
                        {"url": "https://example.com/shared#osv"},
                    ]
                },
                request=request,
            )
        if url == request_urls["github_advisory"]:
            return httpx.Response(
                200,
                json=[
                    {
                        "html_url": "https://example.com/github/advisory",
                        "references": [
                            "https://example.com/shared#gh",
                            {"url": "https://example.com/github/ref"},
                        ],
                    }
                ],
                request=request,
            )
        if url == request_urls["nvd"]:
            return httpx.Response(
                200,
                json={
                    "vulnerabilities": [
                        {
                            "cve": {
                                "references": [
                                    {"url": "https://example.com/nvd/ref"},
                                    {"url": "https://example.com/shared"},
                                ]
                            }
                        }
                    ]
                },
                request=request,
            )
        raise AssertionError(f"未知 URL: {url}")

    monkeypatch.setattr("app.cve.seed_sources.http_client.get", _fake_http_get)

    references = resolve_seed_references(db_session, run=run, cve_id=run.cve_id)
    db_session.commit()

    # 去重 key：urldefrag(url).url，且输出按固定来源顺序分段 + 来源内保序
    assert [ref.url for ref in references] == [
        "https://example.com/official/advisory",
        "https://example.com/shared",
        "https://example.com/program/ref",
        "https://example.com/osv/ref",
        "https://example.com/github/advisory",
        "https://example.com/github/ref",
        "https://example.com/nvd/ref",
    ]

    assert called == [
        request_urls["cve_official"],
        request_urls["osv"],
        request_urls["github_advisory"],
        request_urls["nvd"],
    ]

    records = db_session.query(SourceFetchRecord).all()
    assert len(records) == 1
    record = records[0]
    assert record.scene_name == "cve"
    assert record.source_id == run.run_id
    assert record.source_type == "cve_seed_resolve"
    assert record.source_ref == run.cve_id
    assert record.status == "succeeded"
    assert record.request_snapshot_json == {
        "cve_id": run.cve_id,
        "sources": ["cve_official", "osv", "github_advisory", "nvd"],
        "request_urls": request_urls,
    }
    assert record.response_meta_json["status_code"] == 200
    assert record.response_meta_json["reference_count"] == len(references)
    assert record.response_meta_json["source_results"] == [
        {
            "source": "cve_official",
            "status": "success",
            "status_code": 200,
            "reference_count": 3,
            "error_kind": None,
            "error_message": None,
        },
        {
            "source": "osv",
            "status": "success",
            "status_code": 200,
            "reference_count": 2,
            "error_kind": None,
            "error_message": None,
        },
        {
            "source": "github_advisory",
            "status": "success",
            "status_code": 200,
            "reference_count": 3,
            "error_kind": None,
            "error_message": None,
        },
        {
            "source": "nvd",
            "status": "success",
            "status_code": 200,
            "reference_count": 2,
            "error_kind": None,
            "error_message": None,
        },
    ]
    assert record.error_message is None


def test_resolve_seed_references_returns_empty_when_sources_succeed_but_no_references(
    db_session, monkeypatch
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.commit()

    cve_id = run.cve_id
    request_urls = {
        "cve_official": f"https://cveawg.mitre.org/api/cve/{cve_id}",
        "osv": f"https://api.osv.dev/v1/vulns/{cve_id}",
        "github_advisory": f"https://api.github.com/advisories?cve_id={cve_id}&per_page=20",
        "nvd": f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
    }

    def _fake_http_get(url: str, **kwargs) -> httpx.Response:
        assert kwargs["timeout"] == 10.0
        request = httpx.Request("GET", url)
        if url == request_urls["cve_official"]:
            return httpx.Response(404, json={"code": 5, "message": "not found"}, request=request)
        if url == request_urls["osv"]:
            return httpx.Response(200, json={"references": []}, request=request)
        if url == request_urls["github_advisory"]:
            return httpx.Response(200, json=[], request=request)
        if url == request_urls["nvd"]:
            return httpx.Response(200, json={"vulnerabilities": []}, request=request)
        raise AssertionError(f"未知 URL: {url}")

    monkeypatch.setattr("app.cve.seed_sources.http_client.get", _fake_http_get)

    references = resolve_seed_references(db_session, run=run, cve_id=run.cve_id)
    assert references == []

    db_session.commit()

    records = db_session.query(SourceFetchRecord).all()
    assert len(records) == 1
    record = records[0]
    assert record.scene_name == "cve"
    assert record.source_id == run.run_id
    assert record.source_type == "cve_seed_resolve"
    assert record.source_ref == run.cve_id
    assert record.status == "succeeded"
    assert record.response_meta_json["status_code"] == 200
    assert record.response_meta_json["reference_count"] == 0
    assert record.error_message is None


def test_resolve_seed_references_raises_only_when_all_sources_failed(
    db_session, monkeypatch
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.commit()

    cve_id = run.cve_id
    request_urls = {
        "cve_official": f"https://cveawg.mitre.org/api/cve/{cve_id}",
        "osv": f"https://api.osv.dev/v1/vulns/{cve_id}",
        "github_advisory": f"https://api.github.com/advisories?cve_id={cve_id}&per_page=20",
        "nvd": f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
    }

    def _fake_http_get(url: str, **kwargs) -> httpx.Response:
        assert kwargs["timeout"] == 10.0
        request = httpx.Request("GET", url)
        if url == request_urls["cve_official"]:
            return httpx.Response(503, content=b"unavailable", request=request)
        if url == request_urls["osv"]:
            raise httpx.ConnectError("connect failed", request=request)
        if url == request_urls["github_advisory"]:
            return httpx.Response(200, content=b"{", request=request)
        if url == request_urls["nvd"]:
            return httpx.Response(500, content=b"err", request=request)
        raise AssertionError(f"未知 URL: {url}")

    monkeypatch.setattr("app.cve.seed_sources.http_client.get", _fake_http_get)

    try:
        resolve_seed_references(db_session, run=run, cve_id=run.cve_id)
    except RuntimeError as exc:
        assert "所有" in str(exc)
    else:
        raise AssertionError("预期 resolve_seed_references 抛出 RuntimeError")

    db_session.commit()

    records = db_session.query(SourceFetchRecord).all()
    assert len(records) == 1
    record = records[0]
    assert record.status == "failed"
    assert record.response_meta_json["status_code"] == 503
    assert record.response_meta_json["source_results"][0]["source"] == "cve_official"
    assert record.error_message
