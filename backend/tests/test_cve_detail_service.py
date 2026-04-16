from pathlib import Path

from app.cve.detail_service import get_cve_run_detail
from app.cve.service import create_cve_run
from app.models import Artifact, CVEPatchArtifact


def test_get_cve_run_detail_groups_patches_into_fix_families_by_discovered_from_url(
    db_session, tmp_path
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    run.status = "succeeded"
    run.phase = "finalize_run"
    run.stop_reason = "patches_downloaded"
    run.summary_json = {"patch_found": True, "patch_count": 2}
    db_session.flush()

    primary_patch_path = tmp_path / "primary.patch"
    primary_patch_path.write_text("diff --git a/a b/a\n+primary\n", encoding="utf-8")
    primary_artifact = Artifact(
        artifact_kind="patch",
        scene_name="cve",
        source_url="https://example.com/fix-1.patch",
        storage_path=str(primary_patch_path),
        content_type="text/x-patch",
        checksum="sha256-primary",
        metadata_json={},
    )
    secondary_artifact = Artifact(
        artifact_kind="patch",
        scene_name="cve",
        source_url="https://example.com/fix-2.patch",
        storage_path=str(tmp_path / "missing.patch"),
        content_type="text/x-patch",
        checksum="sha256-secondary",
        metadata_json={},
    )
    db_session.add_all([primary_artifact, secondary_artifact])
    db_session.flush()

    primary_patch = CVEPatchArtifact(
        run_id=run.run_id,
        candidate_url="https://example.com/fix-1.patch",
        patch_type="patch",
        download_status="downloaded",
        artifact_id=primary_artifact.artifact_id,
        patch_meta_json={
            "download_url": "https://example.com/fix-1.patch",
            "discovered_from_url": "https://example.com/advisory",
            "discovered_from_host": "example.com",
            "discovery_rule": "matcher",
        },
    )
    secondary_patch = CVEPatchArtifact(
        run_id=run.run_id,
        candidate_url="https://example.com/fix-2.patch",
        patch_type="diff",
        download_status="failed",
        artifact_id=secondary_artifact.artifact_id,
        patch_meta_json={
            "download_url": "https://example.com/fix-2.patch",
            "discovered_from_url": "https://example.com/advisory",
            "discovered_from_host": "example.com",
            "discovery_rule": "matcher",
        },
    )
    db_session.add_all([primary_patch, secondary_patch])
    db_session.commit()

    detail = get_cve_run_detail(db_session, run_id=run.run_id)

    assert detail is not None
    assert detail["fix_families"] == [
        {
            "family_key": "family:https://example.com/advisory",
            "title": "example.com",
            "source_url": "https://example.com/advisory",
            "source_host": "example.com",
            "discovery_rule": "matcher",
            "patch_count": 2,
            "downloaded_patch_count": 1,
            "primary_patch_id": str(primary_patch.patch_id),
            "patch_ids": [str(primary_patch.patch_id), str(secondary_patch.patch_id)],
            "patch_types": ["patch", "diff"],
        }
    ]


def test_get_cve_run_detail_falls_back_to_candidate_url_when_discovery_metadata_missing(
    db_session, tmp_path
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.flush()

    patch_path = tmp_path / "fallback.patch"
    patch_path.write_text("diff --git a/a b/a\n+fallback\n", encoding="utf-8")
    artifact = Artifact(
        artifact_kind="patch",
        scene_name="cve",
        source_url="https://fallback.example.com/fix.patch",
        storage_path=str(patch_path),
        content_type="text/x-patch",
        checksum="sha256-fallback",
        metadata_json={},
    )
    db_session.add(artifact)
    db_session.flush()

    patch = CVEPatchArtifact(
        run_id=run.run_id,
        candidate_url="https://fallback.example.com/fix.patch",
        patch_type="patch",
        download_status="downloaded",
        artifact_id=artifact.artifact_id,
        patch_meta_json={"download_url": "https://fallback.example.com/fix.patch"},
    )
    db_session.add(patch)
    db_session.commit()

    detail = get_cve_run_detail(db_session, run_id=run.run_id)

    assert detail is not None
    assert detail["fix_families"] == [
        {
            "family_key": "family:https://fallback.example.com/fix.patch",
            "title": "fallback.example.com",
            "source_url": "https://fallback.example.com/fix.patch",
            "source_host": "fallback.example.com",
            "discovery_rule": "unknown",
            "patch_count": 1,
            "downloaded_patch_count": 1,
            "primary_patch_id": str(patch.patch_id),
            "patch_ids": [str(patch.patch_id)],
            "patch_types": ["patch"],
        }
    ]
