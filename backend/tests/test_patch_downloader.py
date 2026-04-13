import httpx

from app.cve.patch_downloader import download_patch_candidate
from app.cve.service import create_cve_run
from app.models import Artifact, SourceFetchRecord


def test_download_patch_candidate_rejects_html_commit_page(
    db_session, monkeypatch
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.commit()

    def _fake_http_get(url: str, **kwargs) -> httpx.Response:
        request = httpx.Request("GET", url)
        return httpx.Response(
            200,
            text="<html><body>commit page</body></html>",
            headers={"content-type": "text/html; charset=utf-8"},
            request=request,
        )

    monkeypatch.setattr("app.cve.patch_downloader.httpx.get", _fake_http_get)

    patch = download_patch_candidate(
        db_session,
        run=run,
        candidate={
            "candidate_url": "https://github.com/example/repo/commit/abc123",
            "patch_type": "patch",
        },
    )
    db_session.commit()

    assert patch.download_status == "failed"
    assert patch.artifact_id is None
    assert patch.patch_meta_json["error"] == "下载内容不是有效的 patch/diff"
    assert patch.patch_meta_json["content_type"] == "text/html; charset=utf-8"

    records = db_session.query(SourceFetchRecord).all()
    assert len(records) == 1
    record = records[0]
    assert record.scene_name == "cve"
    assert record.source_id == run.run_id
    assert record.source_type == "cve_patch_download"
    assert record.source_ref == "https://github.com/example/repo/commit/abc123"
    assert record.status == "failed"
    assert record.request_snapshot_json["candidate_url"] == (
        "https://github.com/example/repo/commit/abc123"
    )
    assert (
        record.request_snapshot_json["download_url"]
        == "https://github.com/example/repo/commit/abc123.patch"
    )
    assert record.request_snapshot_json["patch_type"] == "patch"
    assert record.response_meta_json["content_type"] == "text/html; charset=utf-8"
    assert "下载内容不是有效的 patch/diff" in record.error_message


def test_download_patch_candidate_converts_github_commit_url_and_persists_artifact(
    db_session, monkeypatch, tmp_path
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.commit()
    monkeypatch.setenv("AETHERFLOW_ARTIFACT_ROOT", str(tmp_path))
    requested_urls: list[str] = []
    patch_text = "diff --git a/a.txt b/a.txt\n+hello\n"

    def _fake_http_get(url: str, **kwargs) -> httpx.Response:
        requested_urls.append(url)
        request = httpx.Request("GET", url)
        return httpx.Response(
            200,
            text=patch_text,
            headers={"content-type": "text/x-patch"},
            request=request,
        )

    monkeypatch.setattr("app.cve.patch_downloader.httpx.get", _fake_http_get)

    patch = download_patch_candidate(
        db_session,
        run=run,
        candidate={
            "candidate_url": "https://github.com/example/repo/commit/abc123",
            "patch_type": "patch",
        },
    )
    db_session.commit()

    assert requested_urls == ["https://github.com/example/repo/commit/abc123.patch"]
    assert patch.download_status == "downloaded"
    assert patch.artifact_id is not None
    assert patch.patch_meta_json["download_url"] == requested_urls[0]

    artifact = db_session.get(Artifact, patch.artifact_id)
    assert artifact is not None
    assert artifact.source_url == "https://github.com/example/repo/commit/abc123"
    assert artifact.metadata_json["download_url"] == requested_urls[0]
    assert artifact.metadata_json["run_id"] == str(run.run_id)

    records = db_session.query(SourceFetchRecord).all()
    assert len(records) == 1
    record = records[0]
    assert record.scene_name == "cve"
    assert record.source_id == run.run_id
    assert record.source_type == "cve_patch_download"
    assert record.source_ref == "https://github.com/example/repo/commit/abc123"
    assert record.status == "succeeded"
    assert record.request_snapshot_json["candidate_url"] == (
        "https://github.com/example/repo/commit/abc123"
    )
    assert record.request_snapshot_json["download_url"] == requested_urls[0]
    assert record.request_snapshot_json["patch_type"] == "patch"
    assert record.response_meta_json["status_code"] == 200
    assert record.response_meta_json["content_type"] == "text/x-patch"
