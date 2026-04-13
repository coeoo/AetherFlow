from pathlib import Path

import httpx

from app.cve.service import create_cve_run
from app.models import Artifact, CVEPatchArtifact, CVERun
from app.cve.runtime import execute_cve_run


def test_execute_cve_run_fails_with_no_seed_references(db_session, monkeypatch) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.commit()

    monkeypatch.setattr(
        "app.cve.runtime.resolve_seed_references",
        lambda cve_id: [],
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
        lambda cve_id: ["https://example.com/advisory"],
    )
    monkeypatch.setattr(
        "app.cve.runtime.plan_frontier",
        lambda seed_references: seed_references,
    )
    monkeypatch.setattr(
        "app.cve.runtime.fetch_page",
        lambda url: {"url": url, "content": "patch: https://example.com/fix.patch"},
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
        lambda cve_id: ["https://example.com/advisory"],
    )
    monkeypatch.setattr(
        "app.cve.runtime.plan_frontier",
        lambda seed_references: seed_references,
    )
    monkeypatch.setattr(
        "app.cve.runtime.fetch_page",
        lambda url: {"url": url, "content": "patch: https://example.com/fix.patch"},
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
        _raise_seed_error,
    )

    execute_cve_run(db_session, run_id=run.run_id)
    db_session.commit()

    reloaded_run = db_session.get(CVERun, run.run_id)
    assert reloaded_run is not None
    assert reloaded_run.status == "failed"
    assert reloaded_run.phase == "finalize_run"
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
        lambda cve_id: ["https://example.com/advisory"],
    )
    monkeypatch.setattr(
        "app.cve.runtime.plan_frontier",
        lambda seed_references: seed_references,
    )
    monkeypatch.setattr(
        "app.cve.runtime.fetch_page",
        lambda url: {"url": url, "content": "commit: https://example.com/repo/commit/1"},
    )

    def _raise_analysis_error(snapshot):
        raise RuntimeError("html parser crashed")

    monkeypatch.setattr("app.cve.runtime.analyze_page", _raise_analysis_error)

    execute_cve_run(db_session, run_id=run.run_id)
    db_session.commit()

    reloaded_run = db_session.get(CVERun, run.run_id)
    assert reloaded_run is not None
    assert reloaded_run.status == "failed"
    assert reloaded_run.phase == "finalize_run"
    assert reloaded_run.stop_reason == "analyze_page_failed"
    assert reloaded_run.summary_json["patch_found"] is False
    assert reloaded_run.summary_json["patch_count"] == 0
    assert reloaded_run.summary_json["error"] == "html parser crashed"
