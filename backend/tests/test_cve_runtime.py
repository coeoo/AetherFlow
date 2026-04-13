from app.cve.service import create_cve_run
from app.models import CVEPatchArtifact, CVERun
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

    def _fake_download(session, *, run, candidate):
        patch = CVEPatchArtifact(
            run_id=run.run_id,
            candidate_url=candidate["candidate_url"],
            patch_type=candidate["patch_type"],
            download_status="downloaded",
            patch_meta_json={"source": "test"},
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
    assert reloaded_run.summary_json["patch_found"] is True
    assert reloaded_run.summary_json["patch_count"] == 1
    assert reloaded_run.summary_json["primary_patch_url"] == "https://example.com/fix.patch"


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
