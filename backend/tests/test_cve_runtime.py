from pathlib import Path

import httpx

from app.cve.runtime import execute_cve_run, plan_frontier
from app.cve.service import create_cve_run
from app.models import Artifact, CVEPatchArtifact, CVERun, SourceFetchRecord


def test_execute_cve_run_fails_with_no_seed_references(db_session, monkeypatch) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.commit()

    monkeypatch.setattr(
        "app.cve.runtime.resolve_seed_references",
        lambda session, *, run, cve_id: [],
    )

    execute_cve_run(db_session, run_id=run.run_id)
    db_session.commit()

    reloaded_run = db_session.get(CVERun, run.run_id)
    assert reloaded_run is not None
    assert reloaded_run.status == "failed"
    assert reloaded_run.stop_reason == "no_seed_references"


def test_execute_cve_run_downloads_patch_and_updates_summary(
    db_session, monkeypatch, tmp_path
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.commit()
    monkeypatch.setenv("AETHERFLOW_ARTIFACT_ROOT", str(tmp_path))

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
    patch_text = "diff --git a/app.py b/app.py\n+patched = True\n"

    def _fake_http_get(url: str, **kwargs) -> httpx.Response:
        request = httpx.Request("GET", url)
        return httpx.Response(
            200,
            text=patch_text,
            headers={"content-type": "text/x-patch"},
            request=request,
        )

    monkeypatch.setattr("app.cve.patch_downloader.httpx.get", _fake_http_get)

    execute_cve_run(db_session, run_id=run.run_id)
    db_session.commit()

    reloaded_run = db_session.get(CVERun, run.run_id)
    assert reloaded_run is not None
    assert reloaded_run.status == "succeeded"
    assert reloaded_run.stop_reason == "patches_downloaded"
    assert reloaded_run.summary_json["patch_found"] is True
    assert reloaded_run.summary_json["patch_count"] == 1
    assert reloaded_run.summary_json["primary_patch_url"] == "https://example.com/fix.patch"

    patch = (
        db_session.query(CVEPatchArtifact)
        .filter(CVEPatchArtifact.run_id == run.run_id)
        .one()
    )
    assert patch.download_status == "downloaded"
    assert patch.artifact_id is not None

    artifact = db_session.get(Artifact, patch.artifact_id)
    assert artifact is not None
    assert artifact.source_url == "https://example.com/fix.patch"
    assert artifact.content_type == "text/x-patch"
    assert artifact.metadata_json["download_url"] == "https://example.com/fix.patch"
    assert artifact.metadata_json["run_id"] == str(run.run_id)
    assert Path(artifact.storage_path).exists()
    assert Path(artifact.storage_path).read_text(encoding="utf-8") == patch_text


def test_execute_cve_run_marks_patch_download_failure(db_session, monkeypatch) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.commit()

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
            patch_meta_json={"reason": "network"},
        )
        session.add(patch)
        session.flush()
        return patch

    monkeypatch.setattr("app.cve.runtime.download_patch_candidate", _failed_download)

    execute_cve_run(db_session, run_id=run.run_id)
    db_session.commit()

    reloaded_run = db_session.get(CVERun, run.run_id)
    assert reloaded_run is not None
    assert reloaded_run.status == "failed"
    assert reloaded_run.stop_reason == "patch_download_failed"
    assert reloaded_run.summary_json["patch_found"] is False
    assert reloaded_run.summary_json["patch_count"] == 0


def test_execute_cve_run_marks_failure_when_seed_resolution_raises(
    db_session, monkeypatch
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.commit()

    def _raise_seed_error(cve_id: str) -> list[str]:
        raise RuntimeError("nvd timeout")

    monkeypatch.setattr(
        "app.cve.runtime.resolve_seed_references",
        lambda session, *, run, cve_id: _raise_seed_error(cve_id),
    )

    execute_cve_run(db_session, run_id=run.run_id)
    db_session.commit()

    reloaded_run = db_session.get(CVERun, run.run_id)
    assert reloaded_run is not None
    assert reloaded_run.status == "failed"
    assert reloaded_run.phase == "resolve_seeds"
    assert reloaded_run.stop_reason == "resolve_seeds_failed"
    assert reloaded_run.summary_json["patch_found"] is False
    assert reloaded_run.summary_json["patch_count"] == 0
    assert reloaded_run.summary_json["error"] == "nvd timeout"


def test_execute_cve_run_marks_failure_when_page_analysis_raises(
    db_session, monkeypatch
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.commit()

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
            "content": "commit: https://example.com/repo/commit/1",
        },
    )

    def _raise_analysis_error(snapshot):
        raise RuntimeError("html parser crashed")

    monkeypatch.setattr("app.cve.runtime.analyze_page", _raise_analysis_error)

    execute_cve_run(db_session, run_id=run.run_id)
    db_session.commit()

    reloaded_run = db_session.get(CVERun, run.run_id)
    assert reloaded_run is not None
    assert reloaded_run.status == "failed"
    assert reloaded_run.phase == "analyze_page"
    assert reloaded_run.stop_reason == "analyze_page_failed"
    assert reloaded_run.summary_json["patch_found"] is False
    assert reloaded_run.summary_json["patch_count"] == 0
    assert reloaded_run.summary_json["error"] == "html parser crashed"


def test_plan_frontier_deduplicates_urls_and_limits_page_count() -> None:
    frontier = plan_frontier(
        [
            "https://example.com/a#top",
            "https://example.com/b",
            "https://example.com/a",
            "   ",
            "https://example.com/c",
            "https://example.com/d",
            "https://example.com/e",
            "https://example.com/f",
            "https://example.com/g",
            "https://example.com/h",
            "https://example.com/i",
            "https://example.com/j",
            "https://example.com/k",
        ]
    )

    assert frontier == [
        "https://example.com/a",
        "https://example.com/b",
        "https://example.com/c",
        "https://example.com/d",
        "https://example.com/e",
        "https://example.com/f",
        "https://example.com/g",
        "https://example.com/h",
        "https://example.com/i",
        "https://example.com/j",
    ]


def test_execute_cve_run_writes_source_fetch_records_without_breaking_summary(
    db_session, monkeypatch, tmp_path
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.commit()
    monkeypatch.setenv("AETHERFLOW_ARTIFACT_ROOT", str(tmp_path))
    patch_text = "diff --git a/app.py b/app.py\n+patched = True\n"
    request_urls = {
        "cve_official": f"https://cveawg.mitre.org/api/cve/{run.cve_id}",
        "osv": f"https://api.osv.dev/v1/vulns/{run.cve_id}",
        "github_advisory": f"https://api.github.com/advisories?cve_id={run.cve_id}&per_page=20",
        "nvd": f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={run.cve_id}",
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
                                {"url": "https://example.com/advisory#dup"},
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
                text="patch: https://example.com/fix.patch",
                headers={"content-type": "text/html; charset=utf-8"},
                request=request,
            )
        return httpx.Response(
            200,
            text=patch_text,
            headers={"content-type": "text/x-patch"},
            request=request,
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
    monkeypatch.setattr("app.cve.seed_sources.httpx.get", _fake_http_get)
    monkeypatch.setattr("app.cve.page_fetcher.httpx.get", _fake_http_get)
    monkeypatch.setattr("app.cve.patch_downloader.httpx.get", _fake_http_get)

    execute_cve_run(db_session, run_id=run.run_id)
    db_session.commit()

    reloaded_run = db_session.get(CVERun, run.run_id)
    assert reloaded_run is not None
    assert reloaded_run.status == "succeeded"
    assert reloaded_run.stop_reason == "patches_downloaded"
    assert reloaded_run.summary_json["patch_found"] is True
    assert reloaded_run.summary_json["patch_count"] == 1
    assert reloaded_run.summary_json["primary_patch_url"] == "https://example.com/fix.patch"

    records = (
        db_session.query(SourceFetchRecord)
        .order_by(SourceFetchRecord.created_at, SourceFetchRecord.fetch_id)
        .all()
    )
    assert len(records) == 3
    assert {record.source_type for record in records} == {
        "cve_seed_resolve",
        "cve_patch_download",
        "cve_page_fetch",
    }
    seed_record = next(record for record in records if record.source_type == "cve_seed_resolve")
    assert seed_record.request_snapshot_json == {
        "cve_id": run.cve_id,
        "sources": ["cve_official", "osv", "github_advisory", "nvd"],
        "request_urls": request_urls,
    }
    assert seed_record.response_meta_json["reference_count"] == 1
    assert seed_record.response_meta_json["source_results"] == [
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


def test_execute_cve_run_deduplicates_patch_candidates_across_pages(
    db_session, monkeypatch
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.commit()
    seen_candidates: list[str] = []

    monkeypatch.setattr(
        "app.cve.runtime.resolve_seed_references",
        lambda session, *, run, cve_id: [
            "https://example.com/advisory-a",
            "https://example.com/advisory-b",
        ],
    )
    monkeypatch.setattr(
        "app.cve.runtime.fetch_page",
        lambda session, *, run, url: {"url": url, "content": f"patch {url}"},
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

    def _fake_download(session, *, run, candidate):
        seen_candidates.append(candidate["candidate_url"])
        patch = CVEPatchArtifact(
            run_id=run.run_id,
            candidate_url=candidate["candidate_url"],
            patch_type=candidate["patch_type"],
            download_status="downloaded",
            patch_meta_json={"download_url": candidate["candidate_url"]},
        )
        session.add(patch)
        session.flush()
        return patch

    monkeypatch.setattr("app.cve.runtime.download_patch_candidate", _fake_download)

    execute_cve_run(db_session, run_id=run.run_id)
    db_session.commit()

    assert seen_candidates == ["https://example.com/fix.patch"]
