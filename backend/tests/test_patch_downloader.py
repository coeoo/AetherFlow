import httpx
import logging
from types import SimpleNamespace
from uuid import uuid4

from app.cve import patch_downloader
from app.cve.patch_downloader import download_patch_candidate
from app.cve.service import create_cve_run
from app.models import Artifact, SourceFetchRecord


def test_kernel_commit_patch_download_strategy_falls_back_to_github_mirrors(
    monkeypatch, caplog
) -> None:
    requested_urls: list[str] = []
    requested_accepts: list[str] = []
    kernel_sha = "0123456789abcdef0123456789abcdef01234567"
    candidate_url = (
        "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/"
        f"?id={kernel_sha}"
    )
    stable_api_url = f"https://api.github.com/repos/stable/linux/commits/{kernel_sha}"
    torvalds_api_url = f"https://api.github.com/repos/torvalds/linux/commits/{kernel_sha}"
    patch_text = "diff --git a/kernel/a.c b/kernel/a.c\n+hello\n"

    def _fake_http_get(url: str, **kwargs) -> httpx.Response:
        requested_urls.append(url)
        requested_accepts.append(dict(kwargs.get("headers") or {}).get("Accept", ""))
        request = httpx.Request("GET", url)
        if url == stable_api_url:
            return httpx.Response(
                404,
                text="not found",
                headers={"content-type": "text/plain; charset=utf-8"},
                request=request,
            )
        assert url == torvalds_api_url
        return httpx.Response(
            200,
            text=patch_text,
            headers={"content-type": "text/x-patch"},
            request=request,
        )

    monkeypatch.setattr("app.cve.patch_downloader.http_client.get", _fake_http_get)

    with caplog.at_level(logging.INFO, logger="app.cve.patch_downloader"):
        response, download_url, attempts = patch_downloader._download_with_strategies(
            candidate_url, "patch"
        )

    assert response.text == patch_text
    assert download_url == torvalds_api_url
    assert requested_urls == [stable_api_url, torvalds_api_url]
    assert requested_accepts == [
        "application/vnd.github.patch",
        "application/vnd.github.patch",
    ]
    assert attempts[0]["url"] == stable_api_url
    assert attempts[0]["status"] == "failed"
    assert attempts[0]["error_kind"] == "not_found"
    assert attempts[0]["repository"] == "stable/linux"
    assert attempts[0]["media_type"] == "application/vnd.github.patch"
    assert attempts[1]["url"] == torvalds_api_url
    assert attempts[1]["status"] == "succeeded"
    assert attempts[1]["repository"] == "torvalds/linux"
    assert "开始下载 patch 候选" in caplog.text
    assert "patch 候选下载失败" in caplog.text
    assert "patch 候选下载成功" in caplog.text
    assert "github_kernel_torvalds_linux_api_patch" in caplog.text


def test_kernel_commit_patch_uses_github_token_for_api_headers(monkeypatch) -> None:
    captured_headers: list[dict[str, str]] = []
    kernel_sha = "0123456789abcdef0123456789abcdef01234567"
    candidate_url = (
        "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/"
        f"?id={kernel_sha}"
    )
    api_url = f"https://api.github.com/repos/stable/linux/commits/{kernel_sha}"
    patch_text = "diff --git a/kernel/a.c b/kernel/a.c\n+hello\n"

    monkeypatch.setenv("GITHUB_TOKEN", "unit_test_token")

    def _fake_http_get(url: str, **kwargs) -> httpx.Response:
        headers = dict(kwargs.get("headers") or {})
        captured_headers.append(headers)
        request = httpx.Request("GET", url)
        assert url == api_url
        return httpx.Response(
            200,
            text=patch_text,
            headers={"content-type": "text/x-patch"},
            request=request,
        )

    monkeypatch.setattr("app.cve.patch_downloader.http_client.get", _fake_http_get)

    _, download_url, _ = patch_downloader._download_with_strategies(candidate_url, "patch")

    assert download_url == api_url
    assert captured_headers[0]["Accept"] == "application/vnd.github.patch"
    assert captured_headers[0]["Authorization"] == "Bearer unit_test_token"


def test_kernel_commit_patch_prefers_github_api_patch_with_token_and_redacts_token(
    monkeypatch, caplog
) -> None:
    requested_calls: list[dict[str, object]] = []
    kernel_sha = "0123456789abcdef0123456789abcdef01234567"
    github_token = "unit_test_token"
    candidate_url = (
        "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/"
        f"?id={kernel_sha}"
    )
    api_url = f"https://api.github.com/repos/stable/linux/commits/{kernel_sha}"
    patch_text = "diff --git a/kernel/a.c b/kernel/a.c\n+hello\n"

    def _fake_http_get(url: str, **kwargs) -> httpx.Response:
        requested_calls.append({"url": url, "headers": dict(kwargs["headers"])})
        request = httpx.Request("GET", url)
        assert url == api_url
        return httpx.Response(
            200,
            text=patch_text,
            headers={"content-type": "text/x-patch"},
            request=request,
        )

    monkeypatch.setenv("GITHUB_TOKEN", github_token)
    monkeypatch.setattr("app.cve.patch_downloader.http_client.get", _fake_http_get)

    with caplog.at_level(logging.INFO, logger="app.cve.patch_downloader"):
        response, download_url, attempts = patch_downloader._download_with_strategies(
            candidate_url, "patch"
        )

    assert response.text == patch_text
    assert download_url == api_url
    assert [call["url"] for call in requested_calls] == [api_url]
    assert requested_calls[0]["headers"]["Accept"] == "application/vnd.github.patch"
    assert requested_calls[0]["headers"]["Authorization"] == f"Bearer {github_token}"
    assert attempts[0]["strategy"] == "github_kernel_stable_linux_api_patch"
    assert attempts[0]["status"] == "succeeded"
    assert github_token not in caplog.text
    assert f"Bearer {github_token}" not in caplog.text


def test_kernel_commit_patch_falls_back_from_github_api_patch_to_api_diff(
    monkeypatch,
) -> None:
    requested_calls: list[dict[str, object]] = []
    kernel_sha = "0123456789abcdef0123456789abcdef01234567"
    candidate_url = (
        "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/"
        f"?id={kernel_sha}"
    )
    api_url = f"https://api.github.com/repos/stable/linux/commits/{kernel_sha}"
    patch_text = "diff --git a/kernel/a.c b/kernel/a.c\n+hello\n"

    def _fake_http_get(url: str, **kwargs) -> httpx.Response:
        request = httpx.Request("GET", url)
        headers = dict(kwargs["headers"])
        requested_calls.append({"url": url, "headers": headers})
        if headers["Accept"] == "application/vnd.github.patch":
            return httpx.Response(
                500,
                text="server error",
                headers={"content-type": "text/plain; charset=utf-8"},
                request=request,
            )
        assert headers["Accept"] == "application/vnd.github.diff"
        return httpx.Response(
            200,
            text=patch_text,
            headers={"content-type": "text/plain; charset=utf-8"},
            request=request,
        )

    monkeypatch.setenv("GITHUB_TOKEN", "unit_test_token")
    monkeypatch.setattr("app.cve.patch_downloader.http_client.get", _fake_http_get)

    response, download_url, attempts = patch_downloader._download_with_strategies(
        candidate_url, "patch"
    )

    assert response.text == patch_text
    assert download_url == api_url
    assert [call["url"] for call in requested_calls] == [api_url, api_url]
    assert [call["headers"]["Accept"] for call in requested_calls] == [
        "application/vnd.github.patch",
        "application/vnd.github.diff",
    ]
    assert [attempt["strategy"] for attempt in attempts] == [
        "github_kernel_stable_linux_api_patch",
        "github_kernel_stable_linux_api_diff",
    ]
    assert attempts[0]["error_kind"] == "http_error"
    assert attempts[1]["status"] == "succeeded"


def test_kernel_commit_patch_continues_from_stable_not_found_to_torvalds_linux(
    monkeypatch,
) -> None:
    requested_calls: list[dict[str, object]] = []
    kernel_sha = "0123456789abcdef0123456789abcdef01234567"
    candidate_url = (
        "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/"
        f"?id={kernel_sha}"
    )
    stable_api_url = f"https://api.github.com/repos/stable/linux/commits/{kernel_sha}"
    stable_patch_url = f"https://github.com/stable/linux/commit/{kernel_sha}.patch"
    stable_diff_url = f"https://github.com/stable/linux/commit/{kernel_sha}.diff"
    torvalds_api_url = f"https://api.github.com/repos/torvalds/linux/commits/{kernel_sha}"
    patch_text = "diff --git a/kernel/a.c b/kernel/a.c\n+hello\n"

    def _fake_http_get(url: str, **kwargs) -> httpx.Response:
        headers = dict(kwargs["headers"])
        requested_calls.append({"url": url, "accept": headers["Accept"]})
        request = httpx.Request("GET", url)
        if url in {stable_api_url, stable_patch_url, stable_diff_url}:
            return httpx.Response(
                404,
                text="not found",
                headers={"content-type": "text/plain; charset=utf-8"},
                request=request,
            )
        assert url == torvalds_api_url
        assert headers["Accept"] == "application/vnd.github.patch"
        return httpx.Response(
            200,
            text=patch_text,
            headers={"content-type": "text/x-patch"},
            request=request,
        )

    monkeypatch.setenv("GITHUB_TOKEN", "unit_test_token")
    monkeypatch.setattr("app.cve.patch_downloader.http_client.get", _fake_http_get)

    response, download_url, attempts = patch_downloader._download_with_strategies(
        candidate_url, "patch"
    )

    assert response.text == patch_text
    assert download_url == torvalds_api_url
    assert requested_calls == [
        {"url": stable_api_url, "accept": "application/vnd.github.patch"},
        {"url": torvalds_api_url, "accept": "application/vnd.github.patch"},
    ]
    assert attempts[0]["strategy"] == "github_kernel_stable_linux_api_patch"
    assert attempts[0]["error_kind"] == "not_found"
    assert attempts[1]["strategy"] == "github_kernel_torvalds_linux_api_patch"
    assert attempts[1]["status"] == "succeeded"


def test_download_patch_candidate_records_successful_fallback_url_in_patch_metadata(
    monkeypatch,
) -> None:
    run = SimpleNamespace(run_id=uuid4())
    artifact = SimpleNamespace(artifact_id=uuid4())
    kernel_sha = "0123456789abcdef0123456789abcdef01234567"
    candidate_url = (
        "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/"
        f"?id={kernel_sha}"
    )
    fallback_patch_url = f"https://api.github.com/repos/stable/linux/commits/{kernel_sha}"
    patch_text = "diff --git a/kernel/a.c b/kernel/a.c\n+hello\n"

    class FakeSession:
        def __init__(self) -> None:
            self.added_objects: list[object] = []

        def add(self, value: object) -> None:
            self.added_objects.append(value)

        def flush(self) -> None:
            return None

    def _fake_http_get(url: str, **kwargs) -> httpx.Response:
        request = httpx.Request("GET", url)
        if url == candidate_url:
            return httpx.Response(
                200,
                text="""
                <!doctype html>
                <html><title>Making sure you're not a bot!</title>
                <body>Anubis is a challenge to protect the server.</body></html>
                """,
                headers={"content-type": "text/html; charset=utf-8"},
                request=request,
            )
        assert url == fallback_patch_url
        return httpx.Response(
            200,
            text=patch_text,
            headers={"content-type": "text/x-patch"},
            request=request,
        )

    monkeypatch.setattr("app.cve.patch_downloader.http_client.get", _fake_http_get)
    monkeypatch.setattr("app.cve.patch_downloader.save_text_artifact", lambda *args, **kwargs: artifact)
    monkeypatch.setattr("app.cve.patch_downloader.record_source_fetch", lambda *args, **kwargs: None)

    patch = download_patch_candidate(
        FakeSession(),
        run=run,
        candidate={
            "candidate_url": candidate_url,
            "patch_type": "patch",
            "discovery_rule": "kernel_commit_patch",
        },
    )

    assert patch.download_status == "downloaded"
    assert patch.patch_meta_json["download_url"] == fallback_patch_url


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

    monkeypatch.setattr("app.cve.patch_downloader.http_client.get", _fake_http_get)

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

    monkeypatch.setattr("app.cve.patch_downloader.http_client.get", _fake_http_get)

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


def test_download_patch_candidate_retries_timeout_and_records_attempts(
    db_session, monkeypatch, tmp_path
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2026-31952")
    db_session.commit()
    monkeypatch.setenv("AETHERFLOW_ARTIFACT_ROOT", str(tmp_path))
    monkeypatch.setattr("app.cve.patch_downloader._RETRY_DELAYS_SECONDS", (0, 0))
    requested_urls: list[str] = []
    patch_text = "diff --git a/a.txt b/a.txt\n+hello\n"

    def _fake_http_get(url: str, **kwargs) -> httpx.Response:
        requested_urls.append(url)
        if len(requested_urls) < 3:
            raise httpx.ReadTimeout("timed out")
        request = httpx.Request("GET", url)
        return httpx.Response(
            200,
            text=patch_text,
            headers={"content-type": "text/plain; charset=utf-8"},
            request=request,
        )

    monkeypatch.setattr("app.cve.patch_downloader.http_client.get", _fake_http_get)

    patch = download_patch_candidate(
        db_session,
        run=run,
        candidate={
            "candidate_url": "https://github.com/example/repo/commit/abc123",
            "patch_type": "patch",
        },
    )
    db_session.commit()

    assert requested_urls == ["https://github.com/example/repo/commit/abc123.patch"] * 3
    assert patch.download_status == "downloaded"
    assert patch.patch_meta_json["attempts"][0]["error_kind"] == "timeout"
    assert patch.patch_meta_json["attempts"][1]["error_kind"] == "timeout"
    assert patch.patch_meta_json["attempts"][2]["status"] == "succeeded"


def test_download_patch_candidate_classifies_github_rate_limit(
    db_session, monkeypatch
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2026-33317")
    db_session.commit()
    monkeypatch.setattr("app.cve.patch_downloader._RETRY_DELAYS_SECONDS", (0, 0))

    def _fake_http_get(url: str, **kwargs) -> httpx.Response:
        request = httpx.Request("GET", url)
        return httpx.Response(
            403,
            text='{"message":"API rate limit exceeded"}',
            headers={"content-type": "application/json; charset=utf-8"},
            request=request,
        )

    monkeypatch.setattr("app.cve.patch_downloader.http_client.get", _fake_http_get)

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
    assert patch.patch_meta_json["error_kind"] == "rate_limited"
    assert patch.patch_meta_json["attempts"][0]["status_code"] == 403


def test_download_patch_candidate_falls_back_from_kernel_bot_challenge_to_github_mirrors(
    db_session, monkeypatch, tmp_path
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2026-40001")
    db_session.commit()
    monkeypatch.setenv("AETHERFLOW_ARTIFACT_ROOT", str(tmp_path))
    requested_urls: list[str] = []
    kernel_sha = "0123456789abcdef0123456789abcdef01234567"
    candidate_url = (
        "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/"
        f"?id={kernel_sha}"
    )
    stable_api_url = f"https://api.github.com/repos/stable/linux/commits/{kernel_sha}"
    torvalds_api_url = f"https://api.github.com/repos/torvalds/linux/commits/{kernel_sha}"
    patch_text = "diff --git a/kernel/a.c b/kernel/a.c\n+hello\n"

    def _fake_http_get(url: str, **kwargs) -> httpx.Response:
        requested_urls.append(url)
        request = httpx.Request("GET", url)
        if url == candidate_url:
            return httpx.Response(
                200,
                text="""
                <!doctype html>
                <html><title>Making sure you're not a bot!</title>
                <body>Anubis is a challenge to protect the server.</body></html>
                """,
                headers={"content-type": "text/html; charset=utf-8"},
                request=request,
            )
        if url == stable_api_url:
            return httpx.Response(
                404,
                text="not found",
                headers={"content-type": "text/plain; charset=utf-8"},
                request=request,
            )
        assert url == torvalds_api_url
        return httpx.Response(
            200,
            text=patch_text,
            headers={"content-type": "text/x-patch"},
            request=request,
        )

    monkeypatch.setattr("app.cve.patch_downloader.http_client.get", _fake_http_get)

    patch = download_patch_candidate(
        db_session,
        run=run,
        candidate={
            "candidate_url": candidate_url,
            "patch_type": "patch",
            "discovery_rule": "kernel_commit_patch",
        },
    )
    db_session.commit()

    assert requested_urls == [stable_api_url, torvalds_api_url]
    assert patch.download_status == "downloaded"
    assert patch.patch_meta_json["download_url"] == torvalds_api_url
    assert patch.patch_meta_json["attempts"][0]["url"] == stable_api_url
    assert patch.patch_meta_json["attempts"][0]["status"] == "failed"
    assert patch.patch_meta_json["attempts"][0]["error_kind"] == "not_found"
    assert patch.patch_meta_json["attempts"][0]["media_type"] == "application/vnd.github.patch"
    assert patch.patch_meta_json["attempts"][1]["url"] == torvalds_api_url
    assert patch.patch_meta_json["attempts"][1]["status"] == "succeeded"
    assert patch.patch_meta_json["attempts"][1]["repository"] == "torvalds/linux"
