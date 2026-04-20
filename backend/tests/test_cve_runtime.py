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

    monkeypatch.setattr("app.cve.patch_downloader.http_client.get", _fake_http_get)

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


def test_execute_cve_run_persists_discovery_metadata_into_patch_meta_json(
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

    def _fake_http_get(url: str, **kwargs) -> httpx.Response:
        request = httpx.Request("GET", url)
        return httpx.Response(
            200,
            text="diff --git a/app.py b/app.py\n+patched = True\n",
            headers={"content-type": "text/x-patch"},
            request=request,
        )

    monkeypatch.setattr("app.cve.patch_downloader.http_client.get", _fake_http_get)

    execute_cve_run(db_session, run_id=run.run_id)
    db_session.commit()

    patch = (
        db_session.query(CVEPatchArtifact)
        .filter(CVEPatchArtifact.run_id == run.run_id)
        .one()
    )
    assert patch.patch_meta_json["discovered_from_url"] == "https://example.com/advisory"
    assert patch.patch_meta_json["discovered_from_host"] == "example.com"
    assert patch.patch_meta_json["discovery_rule"] == "matcher"
    assert patch.patch_meta_json["canonical_candidate_key"] == "https://example.com/fix.patch"
    assert patch.patch_meta_json["evidence_source_count"] == 1
    assert patch.patch_meta_json["discovery_sources"] == [
        {
            "source_url": "https://example.com/advisory",
            "source_host": "example.com",
            "discovery_rule": "matcher",
            "source_kind": "page",
            "order": 0,
        }
    ]


def test_execute_cve_run_accumulates_multiple_discovery_sources_for_same_candidate(
    db_session, monkeypatch
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.commit()
    downloaded_candidates: list[dict[str, object]] = []

    monkeypatch.setattr(
        "app.cve.runtime.resolve_seed_references",
        lambda session, *, run, cve_id: [
            "https://github.com/acme/project/commit/abc1234",
            "https://example.com/advisory",
        ],
    )
    monkeypatch.setattr(
        "app.cve.runtime.fetch_page",
        lambda session, *, run, url: {
            "url": url,
            "content": "commit: https://github.com/acme/project/commit/abc1234.patch",
        },
    )
    monkeypatch.setattr(
        "app.cve.runtime.analyze_page",
        lambda snapshot: [
            {
                "candidate_url": "https://github.com/acme/project/commit/abc1234.patch",
                "patch_type": "github_commit_patch",
            }
        ],
    )

    def _fake_download(session, *, run, candidate):
        downloaded_candidates.append(candidate)
        patch = CVEPatchArtifact(
            run_id=run.run_id,
            candidate_url=str(candidate["candidate_url"]),
            patch_type=str(candidate["patch_type"]),
            download_status="downloaded",
            patch_meta_json={
                "discovered_from_url": candidate["discovered_from_url"],
                "discovered_from_host": candidate["discovered_from_host"],
                "discovery_rule": candidate["discovery_rule"],
                "canonical_candidate_key": candidate["canonical_candidate_key"],
                "discovery_sources": candidate["discovery_sources"],
                "evidence_source_count": candidate["evidence_source_count"],
            },
        )
        session.add(patch)
        session.flush()
        return patch

    monkeypatch.setattr("app.cve.runtime.download_patch_candidate", _fake_download)

    execute_cve_run(db_session, run_id=run.run_id)
    db_session.commit()

    reloaded_run = db_session.get(CVERun, run.run_id)
    assert reloaded_run is not None
    assert reloaded_run.summary_json["primary_family_source_url"] == (
        "https://github.com/acme/project/commit/abc1234"
    )
    assert reloaded_run.summary_json["primary_family_source_host"] == "github.com"
    assert reloaded_run.summary_json["primary_family_evidence_source_count"] == 2
    assert reloaded_run.summary_json["primary_family_related_source_hosts"] == [
        "github.com",
        "example.com",
    ]

    assert downloaded_candidates == [
        {
            "candidate_url": "https://github.com/acme/project/commit/abc1234.patch",
            "patch_type": "github_commit_patch",
            "discovered_from_url": "https://github.com/acme/project/commit/abc1234",
            "discovered_from_host": "github.com",
            "discovery_rule": "matcher",
            "canonical_candidate_key": "https://github.com/acme/project/commit/abc1234",
            "evidence_source_count": 2,
            "discovery_sources": [
                {
                    "source_url": "https://github.com/acme/project/commit/abc1234",
                    "source_host": "github.com",
                    "discovery_rule": "matcher",
                    "source_kind": "seed",
                    "order": 0,
                },
                {
                    "source_url": "https://example.com/advisory",
                    "source_host": "example.com",
                    "discovery_rule": "matcher",
                    "source_kind": "page",
                    "order": 1,
                },
            ],
        }
    ]


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


def test_plan_frontier_skips_direct_patch_matches_before_limiting_pages() -> None:
    frontier = plan_frontier(
        [
            "https://example.com/a#top",
            "https://github.com/acme/project/commit/abc1234",
            "https://example.com/b",
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


def test_plan_frontier_prioritizes_debian_tracker_and_announce_pages() -> None:
    frontier = plan_frontier(
        [
            "https://access.redhat.com/downloads",
            "https://access.redhat.com/security/cve/CVE-2022-2509",
            "https://nvd.nist.gov/vuln/detail/CVE-2022-2509",
            "https://lists.debian.org/debian-lts-announce/2022/08/msg00002.html",
            "https://www.debian.org/security/2022/dsa-5203",
            "https://security-tracker.debian.org/tracker/CVE-2022-2509",
        ]
    )

    assert frontier == [
        "https://security-tracker.debian.org/tracker/CVE-2022-2509",
        "https://www.debian.org/security/2022/dsa-5203",
        "https://lists.debian.org/debian-lts-announce/2022/08/msg00002.html",
        "https://nvd.nist.gov/vuln/detail/CVE-2022-2509",
        "https://access.redhat.com/security/cve/CVE-2022-2509",
        "https://access.redhat.com/downloads",
    ]


def test_execute_cve_run_consumes_direct_seed_candidates_beyond_page_budget(
    db_session, monkeypatch
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.commit()
    downloaded_candidates: list[str] = []

    monkeypatch.setattr(
        "app.cve.runtime.resolve_seed_references",
        lambda session, *, run, cve_id: [
            *[f"https://example.com/advisory-{index}" for index in range(12)],
            "https://github.com/acme/project/commit/abc1234",
        ],
    )
    monkeypatch.setattr(
        "app.cve.runtime.fetch_page",
        lambda session, *, run, url: {"url": url, "content": "no patch here"},
    )
    monkeypatch.setattr("app.cve.runtime.analyze_page", lambda snapshot: [])

    def _fake_download(session, *, run, candidate):
        downloaded_candidates.append(candidate["candidate_url"])
        patch = CVEPatchArtifact(
            run_id=run.run_id,
            candidate_url=candidate["candidate_url"],
            patch_type=candidate["patch_type"],
            download_status="downloaded",
            patch_meta_json={
                "download_url": candidate["candidate_url"],
                "discovered_from_url": candidate["discovered_from_url"],
                "discovered_from_host": candidate["discovered_from_host"],
                "discovery_rule": candidate["discovery_rule"],
            },
        )
        session.add(patch)
        session.flush()
        return patch

    monkeypatch.setattr("app.cve.runtime.download_patch_candidate", _fake_download)

    execute_cve_run(db_session, run_id=run.run_id)
    db_session.commit()

    reloaded_run = db_session.get(CVERun, run.run_id)
    assert reloaded_run is not None
    assert reloaded_run.status == "succeeded"
    assert reloaded_run.stop_reason == "patches_downloaded"
    assert reloaded_run.summary_json["primary_patch_url"] == (
        "https://github.com/acme/project/commit/abc1234.patch"
    )
    assert downloaded_candidates == [
        "https://github.com/acme/project/commit/abc1234.patch"
    ]


def test_execute_cve_run_tolerates_failed_page_fetch_when_other_pages_produce_patch_candidates(
    db_session, monkeypatch
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.commit()

    monkeypatch.setattr(
        "app.cve.runtime.resolve_seed_references",
        lambda session, *, run, cve_id: [
            "https://example.com/broken-advisory",
            "https://example.com/working-advisory",
        ],
    )

    def _fake_fetch_page(session, *, run, url):
        if url.endswith("broken-advisory"):
            raise RuntimeError("404 gone")
        return {"url": url, "content": "patch: https://example.com/fix.patch"}

    monkeypatch.setattr("app.cve.runtime.fetch_page", _fake_fetch_page)
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

    reloaded_run = db_session.get(CVERun, run.run_id)
    assert reloaded_run is not None
    assert reloaded_run.status == "succeeded"
    assert reloaded_run.stop_reason == "patches_downloaded"
    assert reloaded_run.summary_json["patch_count"] == 1


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
    monkeypatch.setattr("app.cve.seed_sources.http_client.get", _fake_http_get)
    monkeypatch.setattr("app.cve.page_fetcher.http_client.get", _fake_http_get)
    monkeypatch.setattr("app.cve.patch_downloader.http_client.get", _fake_http_get)

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


def test_execute_cve_run_does_not_trigger_llm_fallback_when_disabled(
    db_session, monkeypatch
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.commit()
    fallback_called = False

    monkeypatch.delenv("AETHERFLOW_CVE_LLM_FALLBACK_ENABLED", raising=False)
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
        lambda session, *, run, url: {"url": url, "content": "no patch here"},
    )
    monkeypatch.setattr("app.cve.runtime.analyze_page", lambda snapshot: [])

    def _unexpected_fallback(*args, **kwargs):
        nonlocal fallback_called
        fallback_called = True
        return {
            "llm_fallback_triggered": True,
        }

    monkeypatch.setattr("app.cve.runtime.maybe_run_cve_llm_fallback", _unexpected_fallback)

    execute_cve_run(db_session, run_id=run.run_id)
    db_session.commit()

    reloaded_run = db_session.get(CVERun, run.run_id)
    assert reloaded_run is not None
    assert reloaded_run.stop_reason == "no_patch_candidates"
    assert reloaded_run.summary_json == {
        "patch_found": False,
        "patch_count": 0,
    }
    assert fallback_called is False


def test_execute_cve_run_triggers_llm_fallback_for_no_patch_candidates(
    db_session, monkeypatch
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.commit()

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
            "content": "vendor advisory without explicit patch link",
        },
    )
    monkeypatch.setattr("app.cve.runtime.analyze_page", lambda snapshot: [])

    monkeypatch.setattr(
        "app.cve.runtime.maybe_run_cve_llm_fallback",
        lambda *args, **kwargs: {
            "llm_fallback_triggered": True,
            "llm_trigger_reason": "no_patch_candidates",
            "llm_invocation_status": "succeeded",
            "llm_decision": "needs_human_review",
            "llm_confidence_band": "low",
            "llm_reason_summary": "规则链没有形成候选，建议人工复核现有来源页。",
            "llm_model": "demo-model",
            "llm_provider": "openai_compatible",
            "llm_verdict_source": "llm_fallback",
            "llm_input_candidate_count": 0,
            "llm_input_source_count": 2,
        },
    )

    execute_cve_run(db_session, run_id=run.run_id)
    db_session.commit()

    reloaded_run = db_session.get(CVERun, run.run_id)
    assert reloaded_run is not None
    assert reloaded_run.status == "failed"
    assert reloaded_run.stop_reason == "no_patch_candidates"
    assert reloaded_run.summary_json == {
        "patch_found": False,
        "patch_count": 0,
        "llm_fallback_triggered": True,
        "llm_trigger_reason": "no_patch_candidates",
        "llm_invocation_status": "succeeded",
        "llm_decision": "needs_human_review",
        "llm_confidence_band": "low",
        "llm_reason_summary": "规则链没有形成候选，建议人工复核现有来源页。",
        "llm_model": "demo-model",
        "llm_provider": "openai_compatible",
        "llm_verdict_source": "llm_fallback",
        "llm_input_candidate_count": 0,
        "llm_input_source_count": 2,
    }


def test_execute_cve_run_persists_skipped_llm_fallback_audit_when_provider_config_missing(
    db_session, monkeypatch
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.commit()

    monkeypatch.setenv("AETHERFLOW_CVE_LLM_FALLBACK_ENABLED", "true")
    monkeypatch.delenv("LLM_BASE_URL", raising=False)
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    monkeypatch.delenv("LLM_DEFAULT_MODEL", raising=False)
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
            "content": "vendor advisory without explicit patch link",
        },
    )
    monkeypatch.setattr("app.cve.runtime.analyze_page", lambda snapshot: [])

    execute_cve_run(db_session, run_id=run.run_id)
    db_session.commit()

    reloaded_run = db_session.get(CVERun, run.run_id)
    assert reloaded_run is not None
    assert reloaded_run.status == "failed"
    assert reloaded_run.stop_reason == "no_patch_candidates"
    assert reloaded_run.summary_json == {
        "patch_found": False,
        "patch_count": 0,
        "llm_fallback_triggered": True,
        "llm_trigger_reason": "no_patch_candidates",
        "llm_invocation_status": "skipped",
        "llm_skip_reason": "missing_provider_config",
        "llm_reason_summary": "LLM fallback 已开启，但缺少必需的模型配置，已跳过。",
        "llm_model": "",
        "llm_provider": "openai_compatible",
        "llm_verdict_source": "llm_fallback",
        "llm_input_candidate_count": 0,
        "llm_input_source_count": 2,
    }


def test_execute_cve_run_triggers_llm_fallback_for_patch_download_failed(
    db_session, monkeypatch
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.commit()

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
            "llm_reason_summary": "现有候选里这个 patch 最值得人工复核。",
            "llm_model": "demo-model",
            "llm_provider": "openai_compatible",
            "llm_verdict_source": "llm_fallback",
            "llm_input_candidate_count": 1,
            "llm_input_source_count": 1,
        },
    )

    execute_cve_run(db_session, run_id=run.run_id)
    db_session.commit()

    reloaded_run = db_session.get(CVERun, run.run_id)
    assert reloaded_run is not None
    assert reloaded_run.status == "failed"
    assert reloaded_run.stop_reason == "patch_download_failed"
    assert reloaded_run.summary_json == {
        "patch_found": False,
        "patch_count": 0,
        "llm_fallback_triggered": True,
        "llm_trigger_reason": "patch_download_failed",
        "llm_invocation_status": "succeeded",
        "llm_decision": "select_candidate",
        "llm_selected_candidate_key": "https://example.com/fix.patch",
        "llm_selected_candidate_url": "https://example.com/fix.patch",
        "llm_confidence_band": "low",
        "llm_reason_summary": "现有候选里这个 patch 最值得人工复核。",
        "llm_model": "demo-model",
        "llm_provider": "openai_compatible",
        "llm_verdict_source": "llm_fallback",
        "llm_input_candidate_count": 1,
        "llm_input_source_count": 1,
    }
