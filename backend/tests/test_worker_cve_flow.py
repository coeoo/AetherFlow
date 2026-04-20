from pathlib import Path

import httpx
from sqlalchemy import select

from app.models import (
    Artifact,
    CVERun,
    CVEPatchArtifact,
    SourceFetchRecord,
    TaskAttempt,
    TaskJob,
)
from app.db.session import create_session_factory
from app.worker.runtime import process_once


def test_post_run_then_worker_once_then_get_summary_returns_terminal_state(
    client, db_session, test_database_url, monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("AETHERFLOW_ARTIFACT_ROOT", str(tmp_path))
    monkeypatch.setattr(
        "app.cve.runtime.plan_frontier",
        lambda seed_references: seed_references,
    )
    monkeypatch.setattr(
        "app.cve.runtime.analyze_page",
        lambda snapshot: [
            {
                "candidate_url": "https://example.com/fix.patch",
                "patch_type": "patch",
            }
        ],
    )
    patch_text = "diff --git a/app.py b/app.py\n+patched = True\n"
    cve_id = "CVE-2024-3094"
    request_urls = {
        "cve_official": f"https://cveawg.mitre.org/api/cve/{cve_id}",
        "osv": f"https://api.osv.dev/v1/vulns/{cve_id}",
        "github_advisory": f"https://api.github.com/advisories?cve_id={cve_id}&per_page=20",
        "nvd": f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}",
    }

    def _fake_http_get(url: str, **kwargs) -> httpx.Response:
        request = httpx.Request("GET", url)
        if url == request_urls["cve_official"]:
            return httpx.Response(
                200,
                json={
                    "containers": {
                        "cna": {
                            "references": [
                                {"url": "https://example.com/advisory"},
                            ]
                        }
                    }
                },
                request=request,
            )
        if url == request_urls["osv"]:
            return httpx.Response(
                404,
                json={"code": 5, "message": "not found"},
                request=request,
            )
        if url == request_urls["github_advisory"]:
            return httpx.Response(200, json=[], request=request)
        if url == request_urls["nvd"]:
            return httpx.Response(200, json={"vulnerabilities": []}, request=request)
        if url == "https://example.com/advisory":
            return httpx.Response(
                200,
                text="https://example.com/fix.patch",
                headers={"content-type": "text/html; charset=utf-8"},
                request=request,
            )
        return httpx.Response(
            200,
            text=patch_text,
            headers={"content-type": "text/x-patch"},
            request=request,
        )

    monkeypatch.setattr("app.cve.seed_sources.http_client.get", _fake_http_get)
    monkeypatch.setattr("app.cve.page_fetcher.http_client.get", _fake_http_get)
    monkeypatch.setattr("app.cve.patch_downloader.http_client.get", _fake_http_get)

    response = client.post("/api/v1/cve/runs", json={"cve_id": cve_id})
    run_id = response.json()["data"]["run_id"]

    session_factory = create_session_factory(test_database_url)
    processed = process_once(session_factory, worker_name="worker-e2e")
    assert processed is True

    detail = client.get(f"/api/v1/cve/runs/{run_id}")
    assert detail.status_code == 200
    body = detail.json()["data"]
    assert body["status"] == "succeeded"
    assert body["stop_reason"] == "patches_downloaded"
    assert body["summary"]["patch_found"] is True
    assert body["summary"]["patch_count"] == 1
    seed_trace = next(item for item in body["source_traces"] if item["step"] == "cve_seed_resolve")
    assert seed_trace["request_snapshot"] == {
        "cve_id": cve_id,
        "sources": ["cve_official", "osv", "github_advisory", "nvd"],
        "request_urls": request_urls,
    }
    assert seed_trace["response_meta"]["source_results"] == [
        {
            "source": "cve_official",
            "status": "success",
            "status_code": 200,
            "reference_count": 1,
            "error_kind": None,
            "error_message": None,
        },
        {
            "source": "osv",
            "status": "not_found",
            "status_code": 404,
            "reference_count": 0,
            "error_kind": None,
            "error_message": None,
        },
        {
            "source": "github_advisory",
            "status": "not_found",
            "status_code": 200,
            "reference_count": 0,
            "error_kind": None,
            "error_message": None,
        },
        {
            "source": "nvd",
            "status": "not_found",
            "status_code": 200,
            "reference_count": 0,
            "error_kind": None,
            "error_message": None,
        },
    ]

    db_session.expire_all()
    run = db_session.get(CVERun, run_id)
    assert run is not None
    patch = db_session.execute(
        select(CVEPatchArtifact).where(CVEPatchArtifact.run_id == run.run_id)
    ).scalar_one()
    assert patch.download_status == "downloaded"
    assert patch.artifact_id is not None

    artifact = db_session.get(Artifact, patch.artifact_id)
    assert artifact is not None
    assert artifact.storage_path.endswith("fix.patch")
    assert Path(artifact.storage_path).read_text(encoding="utf-8") == patch_text

    fetch_records = db_session.execute(
        select(SourceFetchRecord)
        .where(SourceFetchRecord.source_id == run.run_id)
        .order_by(SourceFetchRecord.created_at, SourceFetchRecord.fetch_id)
    ).scalars()
    assert {record.source_type for record in fetch_records} == {
        "cve_seed_resolve",
        "cve_patch_download",
        "cve_page_fetch",
    }


def test_worker_once_marks_run_failed_when_seed_resolution_returns_empty(
    client, db_session, test_database_url, monkeypatch
) -> None:
    monkeypatch.setattr(
        "app.cve.runtime.resolve_seed_references",
        lambda session, *, run, cve_id: [],
    )

    response = client.post("/api/v1/cve/runs", json={"cve_id": "CVE-2024-3094"})
    run_id = response.json()["data"]["run_id"]

    session_factory = create_session_factory(test_database_url)
    processed = process_once(session_factory, worker_name="worker-e2e")
    assert processed is True

    detail = client.get(f"/api/v1/cve/runs/{run_id}")
    assert detail.status_code == 200
    body = detail.json()["data"]
    assert body["status"] == "failed"
    assert body["stop_reason"] == "no_seed_references"
    assert body["summary"]["patch_found"] is False

    db_session.expire_all()
    run = db_session.get(CVERun, run_id)
    assert run is not None
    job = db_session.get(TaskJob, run.job_id)
    assert job is not None
    assert job.status == "failed"

    attempt = db_session.execute(
        select(TaskAttempt).where(TaskAttempt.job_id == run.job_id)
    ).scalar_one()
    assert attempt.status == "failed"
    assert attempt.error_message == "场景运行失败: no_seed_references"


def test_worker_once_marks_run_terminal_when_seed_resolution_raises(
    client, db_session, test_database_url, monkeypatch
) -> None:
    def _raise_seed_error(cve_id: str) -> list[str]:
        raise RuntimeError("nvd timeout")

    monkeypatch.setattr(
        "app.cve.runtime.resolve_seed_references",
        lambda session, *, run, cve_id: _raise_seed_error(cve_id),
    )

    response = client.post("/api/v1/cve/runs", json={"cve_id": "CVE-2024-3094"})
    run_id = response.json()["data"]["run_id"]

    session_factory = create_session_factory(test_database_url)
    processed = process_once(session_factory, worker_name="worker-e2e")
    assert processed is True

    detail = client.get(f"/api/v1/cve/runs/{run_id}")
    assert detail.status_code == 200
    body = detail.json()["data"]
    assert body["status"] == "failed"
    assert body["phase"] == "resolve_seeds"
    assert body["stop_reason"] == "resolve_seeds_failed"
    assert body["summary"]["patch_found"] is False
    assert body["summary"]["error"] == "nvd timeout"
    assert body["progress"]["current_phase"] == "resolve_seeds"
    assert body["progress"]["completed_steps"] == 0
    assert body["progress"]["total_steps"] == 6
    assert body["progress"]["terminal"] is True

    db_session.expire_all()
    run = db_session.get(CVERun, run_id)
    assert run is not None
    assert run.phase == "resolve_seeds"

    job = db_session.get(TaskJob, run.job_id)
    assert job is not None
    assert job.status == "failed"
    assert job.last_error == "场景运行失败: resolve_seeds_failed"

    attempt = db_session.execute(
        select(TaskAttempt).where(TaskAttempt.job_id == run.job_id)
    ).scalar_one()
    assert attempt.status == "failed"
    assert attempt.error_message == "场景运行失败: resolve_seeds_failed"


def test_worker_once_preserves_llm_fallback_summary_when_patch_download_failed(
    client, db_session, test_database_url, monkeypatch
) -> None:
    monkeypatch.setenv("AETHERFLOW_CVE_LLM_FALLBACK_ENABLED", "true")
    monkeypatch.setattr(
        "app.cve.runtime.resolve_seed_references",
        lambda session, *, run, cve_id: ["https://example.com/advisory"],
    )
    monkeypatch.setattr(
        "app.cve.runtime.plan_frontier",
        lambda seed_references: seed_references,
    )
    monkeypatch.setattr(
        "app.cve.runtime.fetch_page",
        lambda session, *, run, url: {
            "url": url,
            "content": "patch: https://example.com/fix.patch",
        },
    )
    monkeypatch.setattr(
        "app.cve.runtime.analyze_page",
        lambda snapshot: [
            {
                "candidate_url": "https://example.com/fix.patch",
                "patch_type": "patch",
            }
        ],
    )

    def _failed_download(session, *, run, candidate):
        patch = CVEPatchArtifact(
            run_id=run.run_id,
            candidate_url=candidate["candidate_url"],
            patch_type=candidate["patch_type"],
            download_status="failed",
            patch_meta_json={"error": "403 forbidden"},
        )
        session.add(patch)
        session.flush()
        return patch

    monkeypatch.setattr("app.cve.runtime.download_patch_candidate", _failed_download)
    monkeypatch.setattr(
        "app.cve.runtime.maybe_run_cve_llm_fallback",
        lambda *args, **kwargs: {
            "llm_fallback_triggered": True,
            "llm_trigger_reason": "patch_download_failed",
            "llm_invocation_status": "succeeded",
            "llm_decision": "select_candidate",
            "llm_selected_candidate_key": "https://example.com/fix.patch",
            "llm_selected_candidate_url": "https://example.com/fix.patch",
            "llm_confidence_band": "low",
            "llm_reason_summary": "建议优先人工复核该候选。",
            "llm_model": "demo-model",
            "llm_provider": "openai_compatible",
            "llm_verdict_source": "llm_fallback",
            "llm_input_candidate_count": 1,
            "llm_input_source_count": 1,
        },
    )

    response = client.post("/api/v1/cve/runs", json={"cve_id": "CVE-2024-3094"})
    run_id = response.json()["data"]["run_id"]

    session_factory = create_session_factory(test_database_url)
    processed = process_once(session_factory, worker_name="worker-e2e")
    assert processed is True

    detail = client.get(f"/api/v1/cve/runs/{run_id}")
    assert detail.status_code == 200
    body = detail.json()["data"]
    assert body["status"] == "failed"
    assert body["stop_reason"] == "patch_download_failed"
    assert body["summary"]["llm_fallback_triggered"] is True
    assert body["summary"]["llm_decision"] == "select_candidate"
    assert body["summary"]["llm_selected_candidate_url"] == "https://example.com/fix.patch"


def test_worker_follows_debian_tracker_chain_to_gitlab_commit_patch(
    client, db_session, test_database_url, monkeypatch, tmp_path
) -> None:
    monkeypatch.setenv("AETHERFLOW_ARTIFACT_ROOT", str(tmp_path))
    monkeypatch.setattr(
        "app.cve.runtime.resolve_seed_references",
        lambda session, *, run, cve_id: ["https://www.debian.org/security/2022/dsa-5203"],
    )

    patch_text = "diff --git a/lib/file.c b/lib/file.c\n+patched = true\n"

    def _fake_http_get(url: str, **kwargs) -> httpx.Response:
        request = httpx.Request("GET", url)
        if url == "https://www.debian.org/security/2022/dsa-5203":
            return httpx.Response(
                200,
                text=(
                    '<html><body>'
                    '<a href="https://security-tracker.debian.org/tracker/gnutls28">'
                    "security tracker"
                    "</a>"
                    "</body></html>"
                ),
                headers={"content-type": "text/html; charset=utf-8"},
                request=request,
            )
        if url == "https://security-tracker.debian.org/tracker/gnutls28":
            return httpx.Response(
                200,
                text=(
                    '<html><body>'
                    '<a href="https://security-tracker.debian.org/tracker/CVE-2022-2509">'
                    "CVE-2022-2509"
                    "</a>"
                    "</body></html>"
                ),
                headers={"content-type": "text/html; charset=utf-8"},
                request=request,
            )
        if url == "https://security-tracker.debian.org/tracker/CVE-2022-2509":
            return httpx.Response(
                200,
                text=(
                    '<html><body>'
                    '<a href="https://gitlab.com/gnutls/gnutls/-/commit/'
                    'ce37f9eb265dbe9b6d597f5767449e8ee95848e2">'
                    "fix commit"
                    "</a>"
                    "</body></html>"
                ),
                headers={"content-type": "text/html; charset=utf-8"},
                request=request,
            )
        if url == "https://gitlab.com/gnutls/gnutls/-/commit/ce37f9eb265dbe9b6d597f5767449e8ee95848e2.patch":
            return httpx.Response(
                200,
                text=patch_text,
                headers={"content-type": "text/x-patch"},
                request=request,
            )
        raise AssertionError(f"未预期的 URL: {url}")

    monkeypatch.setattr("app.cve.page_fetcher.http_client.get", _fake_http_get)
    monkeypatch.setattr("app.cve.patch_downloader.http_client.get", _fake_http_get)

    response = client.post("/api/v1/cve/runs", json={"cve_id": "CVE-2022-2509"})
    run_id = response.json()["data"]["run_id"]

    session_factory = create_session_factory(test_database_url)
    processed = process_once(session_factory, worker_name="worker-e2e")
    assert processed is True

    detail = client.get(f"/api/v1/cve/runs/{run_id}")
    assert detail.status_code == 200
    body = detail.json()["data"]
    assert body["status"] == "succeeded"
    assert body["stop_reason"] == "patches_downloaded"
    assert body["summary"]["primary_patch_url"] == (
        "https://gitlab.com/gnutls/gnutls/-/commit/ce37f9eb265dbe9b6d597f5767449e8ee95848e2.patch"
    )

    fetched_urls = [
        item["url"]
        for item in body["source_traces"]
        if item["step"] == "cve_page_fetch" and item["status"] == "succeeded"
    ]
    assert set(fetched_urls) == {
        "https://www.debian.org/security/2022/dsa-5203",
        "https://security-tracker.debian.org/tracker/gnutls28",
        "https://security-tracker.debian.org/tracker/CVE-2022-2509",
    }
