import httpx

from app.cve.page_fetcher import fetch_page
from app.cve.service import create_cve_run
from app.models import SourceFetchRecord


def test_fetch_page_records_success_trace(db_session, monkeypatch) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.commit()

    def _fake_http_get(url: str, **kwargs) -> httpx.Response:
        request = httpx.Request("GET", url)
        return httpx.Response(
            200,
            text="patch: https://example.com/fix.patch",
            headers={"content-type": "text/html; charset=utf-8"},
            request=request,
        )

    monkeypatch.setattr("app.cve.page_fetcher.httpx.get", _fake_http_get)

    snapshot = fetch_page(db_session, run=run, url="https://example.com/advisory")
    db_session.commit()

    assert snapshot["url"] == "https://example.com/advisory"
    assert snapshot["status_code"] == 200
    assert snapshot["content_type"] == "text/html; charset=utf-8"

    records = db_session.query(SourceFetchRecord).all()
    assert len(records) == 1
    record = records[0]
    assert record.scene_name == "cve"
    assert record.source_id == run.run_id
    assert record.source_type == "cve_page_fetch"
    assert record.source_ref == "https://example.com/advisory"
    assert record.status == "succeeded"
    assert record.request_snapshot_json["url"] == "https://example.com/advisory"
    assert record.response_meta_json["final_url"] == "https://example.com/advisory"
    assert record.response_meta_json["status_code"] == 200
    assert record.response_meta_json["content_type"] == "text/html; charset=utf-8"
    assert record.error_message is None


def test_fetch_page_records_failure_trace(db_session, monkeypatch) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.commit()

    def _fake_http_get(url: str, **kwargs) -> httpx.Response:
        request = httpx.Request("GET", url)
        return httpx.Response(404, request=request)

    monkeypatch.setattr("app.cve.page_fetcher.httpx.get", _fake_http_get)

    try:
        fetch_page(db_session, run=run, url="https://example.com/missing")
    except httpx.HTTPStatusError as exc:
        assert exc.response.status_code == 404
    else:
        raise AssertionError("预期 fetch_page 抛出 HTTPStatusError")

    db_session.commit()

    records = db_session.query(SourceFetchRecord).all()
    assert len(records) == 1
    record = records[0]
    assert record.scene_name == "cve"
    assert record.source_id == run.run_id
    assert record.source_type == "cve_page_fetch"
    assert record.source_ref == "https://example.com/missing"
    assert record.status == "failed"
    assert record.request_snapshot_json["url"] == "https://example.com/missing"
    assert record.response_meta_json["status_code"] == 404
    assert "404 Not Found" in record.error_message
