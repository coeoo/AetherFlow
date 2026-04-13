import httpx

from app.cve.seed_resolver import resolve_seed_references
from app.cve.service import create_cve_run
from app.models import SourceFetchRecord


def test_resolve_seed_references_records_success_trace(db_session, monkeypatch) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.commit()

    def _fake_http_get(url: str, **kwargs) -> httpx.Response:
        request = httpx.Request("GET", url)
        return httpx.Response(
            200,
            json={
                "vulnerabilities": [
                    {
                        "cve": {
                            "references": [
                                {"url": "https://example.com/advisory"},
                                {"url": "https://example.com/patch"},
                            ]
                        }
                    }
                ]
            },
            request=request,
        )

    monkeypatch.setattr("app.cve.seed_resolver.httpx.get", _fake_http_get)

    references = resolve_seed_references(db_session, run=run, cve_id=run.cve_id)
    db_session.commit()

    assert references == [
        "https://example.com/advisory",
        "https://example.com/patch",
    ]

    records = db_session.query(SourceFetchRecord).all()
    assert len(records) == 1
    record = records[0]
    assert record.scene_name == "cve"
    assert record.source_id == run.run_id
    assert record.source_type == "cve_seed_resolve"
    assert record.source_ref == run.cve_id
    assert record.status == "succeeded"
    assert record.request_snapshot_json["cve_id"] == run.cve_id
    assert record.response_meta_json["reference_count"] == 2
    assert record.error_message is None


def test_resolve_seed_references_records_failure_trace(
    db_session, monkeypatch
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.commit()

    def _fake_http_get(url: str, **kwargs) -> httpx.Response:
        request = httpx.Request("GET", url)
        return httpx.Response(503, request=request)

    monkeypatch.setattr("app.cve.seed_resolver.httpx.get", _fake_http_get)

    try:
        resolve_seed_references(db_session, run=run, cve_id=run.cve_id)
    except httpx.HTTPStatusError as exc:
        assert exc.response.status_code == 503
    else:
        raise AssertionError("预期 resolve_seed_references 抛出 HTTPStatusError")

    db_session.commit()

    records = db_session.query(SourceFetchRecord).all()
    assert len(records) == 1
    record = records[0]
    assert record.scene_name == "cve"
    assert record.source_id == run.run_id
    assert record.source_type == "cve_seed_resolve"
    assert record.source_ref == run.cve_id
    assert record.status == "failed"
    assert record.request_snapshot_json["cve_id"] == run.cve_id
    assert record.response_meta_json["status_code"] == 503
    assert "503 Service Unavailable" in record.error_message
