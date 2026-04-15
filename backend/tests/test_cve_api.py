import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select

from app.cve.service import create_cve_run
from app.models import Artifact, CVEPatchArtifact, CVERun, SourceFetchRecord, TaskJob


def test_post_cve_runs_creates_queued_run_and_task_job(client, db_session) -> None:
    response = client.post("/api/v1/cve/runs", json={"cve_id": "CVE-2024-3094"})

    assert response.status_code == 200
    body = response.json()
    assert body["code"] == 0
    assert body["message"] == "success"
    assert body["data"]["cve_id"] == "CVE-2024-3094"
    assert body["data"]["status"] == "queued"
    assert body["data"]["phase"] == "resolve_seeds"

    run_id = uuid.UUID(body["data"]["run_id"])
    run = db_session.get(CVERun, run_id)
    assert run is not None
    assert run.cve_id == "CVE-2024-3094"
    assert run.status == "queued"
    assert run.phase == "resolve_seeds"

    job = db_session.get(TaskJob, run.job_id)
    assert job is not None
    assert job.scene_name == "cve"
    assert job.job_type == "cve_patch_fast_first"
    assert job.trigger_kind == "manual"
    assert job.status == "queued"


def test_post_cve_runs_rejects_invalid_cve_id(client) -> None:
    response = client.post("/api/v1/cve/runs", json={"cve_id": "bad-id"})

    assert response.status_code == 422


def test_get_cve_run_returns_minimal_summary(client, seeded_cve_run) -> None:
    response = client.get(f"/api/v1/cve/runs/{seeded_cve_run.run_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["code"] == 0
    assert body["message"] == "success"
    assert body["data"]["run_id"] == str(seeded_cve_run.run_id)
    assert body["data"]["cve_id"] == "CVE-2024-3094"
    assert body["data"]["status"] == "queued"
    assert body["data"]["phase"] == "resolve_seeds"
    assert body["data"]["stop_reason"] is None
    assert body["data"]["summary"] == {}


def test_get_cve_run_returns_404_for_missing_run(client) -> None:
    response = client.get(f"/api/v1/cve/runs/{uuid.uuid4()}")

    assert response.status_code == 404


def test_get_cve_runs_returns_recent_history_sorted_desc(client, db_session) -> None:
    older_run = create_cve_run(db_session, cve_id="CVE-2023-1111")
    newer_run = create_cve_run(db_session, cve_id="CVE-2024-2222")

    older_run.status = "failed"
    older_run.phase = "fetch_page"
    older_run.stop_reason = "fetch_failed"
    older_run.summary_json = {
        "patch_found": False,
        "patch_count": 0,
    }
    older_run.created_at = datetime(2026, 4, 13, 8, 0, tzinfo=UTC)

    newer_run.status = "succeeded"
    newer_run.phase = "finalize_run"
    newer_run.stop_reason = "patches_downloaded"
    newer_run.summary_json = {
        "patch_found": True,
        "patch_count": 1,
        "primary_patch_url": "https://example.com/fix.patch",
    }
    newer_run.created_at = older_run.created_at + timedelta(minutes=5)
    db_session.commit()

    response = client.get("/api/v1/cve/runs")

    assert response.status_code == 200
    assert response.json()["data"] == [
        {
            "run_id": str(newer_run.run_id),
            "cve_id": "CVE-2024-2222",
            "status": "succeeded",
            "phase": "finalize_run",
            "stop_reason": "patches_downloaded",
            "summary": {
                "patch_found": True,
                "patch_count": 1,
                "primary_patch_url": "https://example.com/fix.patch",
            },
            "created_at": "2026-04-13T08:05:00+00:00",
        },
        {
            "run_id": str(older_run.run_id),
            "cve_id": "CVE-2023-1111",
            "status": "failed",
            "phase": "fetch_page",
            "stop_reason": "fetch_failed",
            "summary": {
                "patch_found": False,
                "patch_count": 0,
            },
            "created_at": "2026-04-13T08:00:00+00:00",
        },
    ]


def test_get_cve_run_returns_detail_payload_with_progress_traces_and_patches(
    client, db_session, tmp_path
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    run.status = "succeeded"
    run.phase = "finalize_run"
    run.stop_reason = "patches_downloaded"
    run.summary_json = {
        "patch_found": True,
        "patch_count": 1,
        "primary_patch_url": "https://example.com/fix.patch",
    }
    db_session.flush()

    patch_path = tmp_path / "fix.patch"
    patch_path.write_text("diff --git a/app.py b/app.py\n+patched = True\n", encoding="utf-8")
    artifact = Artifact(
        artifact_kind="patch",
        scene_name="cve",
        source_url="https://example.com/fix.patch",
        storage_path=str(patch_path),
        content_type="text/x-patch",
        checksum="sha256-demo",
        metadata_json={},
    )
    db_session.add(artifact)
    db_session.flush()

    db_session.add_all(
        [
            SourceFetchRecord(
                scene_name="cve",
                source_id=run.run_id,
                source_type="cve_seed_resolve",
                source_ref=run.cve_id,
                status="succeeded",
                request_snapshot_json={"cve_id": run.cve_id},
                response_meta_json={"reference_count": 2},
            ),
            SourceFetchRecord(
                scene_name="cve",
                source_id=run.run_id,
                source_type="cve_page_fetch",
                source_ref="https://example.com/advisory",
                status="succeeded",
                request_snapshot_json={"url": "https://example.com/advisory"},
                response_meta_json={
                    "final_url": "https://example.com/advisory",
                    "status_code": 200,
                    "content_type": "text/html",
                },
            ),
            SourceFetchRecord(
                scene_name="cve",
                source_id=run.run_id,
                source_type="cve_patch_download",
                source_ref="https://example.com/fix.patch",
                status="succeeded",
                request_snapshot_json={"candidate_url": "https://example.com/fix.patch"},
                response_meta_json={
                    "download_url": "https://example.com/fix.patch",
                    "status_code": 200,
                    "content_type": "text/x-patch",
                },
            ),
            CVEPatchArtifact(
                run_id=run.run_id,
                candidate_url="https://example.com/fix.patch",
                patch_type="patch",
                download_status="downloaded",
                artifact_id=artifact.artifact_id,
                patch_meta_json={
                    "download_url": "https://example.com/fix.patch",
                    "content_type": "text/x-patch",
                },
            ),
        ]
    )
    db_session.commit()
    patch = db_session.execute(
        select(CVEPatchArtifact).where(CVEPatchArtifact.run_id == run.run_id)
    ).scalar_one()

    response = client.get(f"/api/v1/cve/runs/{run.run_id}")

    assert response.status_code == 200
    body = response.json()
    assert body["data"]["run_id"] == str(run.run_id)
    assert body["data"]["progress"] == {
        "current_phase": "finalize_run",
        "completed_steps": 6,
        "total_steps": 6,
        "terminal": True,
    }
    assert len(body["data"]["recent_progress"]) == 3
    assert {item["step"] for item in body["data"]["recent_progress"]} == {
        "cve_seed_resolve",
        "cve_page_fetch",
        "cve_patch_download",
    }
    assert len(body["data"]["source_traces"]) == 3
    traces_by_step = {item["step"]: item for item in body["data"]["source_traces"]}
    assert traces_by_step["cve_page_fetch"]["url"] == "https://example.com/advisory"
    assert body["data"]["patches"] == [
        {
            "patch_id": str(patch.patch_id),
            "candidate_url": "https://example.com/fix.patch",
            "patch_type": "patch",
            "download_status": "downloaded",
            "artifact_id": str(artifact.artifact_id),
            "duplicate_count": 1,
            "content_available": True,
            "content_type": "text/x-patch",
            "download_url": "https://example.com/fix.patch",
        }
    ]


def test_get_patch_content_returns_diff_text_for_downloaded_patch(
    client, db_session, tmp_path
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.flush()

    patch_path = tmp_path / "fix.patch"
    patch_text = "diff --git a/app.py b/app.py\n+patched = True\n"
    patch_path.write_text(patch_text, encoding="utf-8")
    artifact = Artifact(
        artifact_kind="patch",
        scene_name="cve",
        source_url="https://example.com/fix.patch",
        storage_path=str(patch_path),
        content_type="text/x-patch",
        checksum="sha256-demo",
        metadata_json={},
    )
    db_session.add(artifact)
    db_session.flush()

    db_session.add(
        CVEPatchArtifact(
            run_id=run.run_id,
            candidate_url="https://example.com/fix.patch",
            patch_type="patch",
            download_status="downloaded",
            artifact_id=artifact.artifact_id,
            patch_meta_json={},
        )
    )
    db_session.commit()
    patch = db_session.execute(
        select(CVEPatchArtifact).where(CVEPatchArtifact.run_id == run.run_id)
    ).scalar_one()

    response = client.get(
        f"/api/v1/cve/runs/{run.run_id}/patch-content",
        params={"patch_id": str(patch.patch_id)},
    )

    assert response.status_code == 200
    assert response.json()["data"] == {
        "patch_id": str(patch.patch_id),
        "candidate_url": "https://example.com/fix.patch",
        "content": patch_text,
    }


def test_get_cve_run_failed_detail_uses_failed_phase_for_progress(client, db_session) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    run.status = "failed"
    run.phase = "fetch_page"
    run.stop_reason = "fetch_failed"
    run.summary_json = {"patch_found": False, "patch_count": 0}
    db_session.commit()

    response = client.get(f"/api/v1/cve/runs/{run.run_id}")

    assert response.status_code == 200
    assert response.json()["data"]["progress"] == {
        "current_phase": "fetch_page",
        "completed_steps": 2,
        "total_steps": 6,
        "terminal": True,
    }


def test_get_patch_content_returns_404_when_artifact_is_missing(
    client, db_session
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.flush()
    db_session.add(
        CVEPatchArtifact(
            run_id=run.run_id,
            candidate_url="https://example.com/missing.patch",
            patch_type="patch",
            download_status="failed",
            patch_meta_json={},
        )
    )
    db_session.commit()
    patch = db_session.execute(
        select(CVEPatchArtifact).where(CVEPatchArtifact.run_id == run.run_id)
    ).scalar_one()

    response = client.get(
        f"/api/v1/cve/runs/{run.run_id}/patch-content",
        params={"patch_id": str(patch.patch_id)},
    )

    assert response.status_code == 404


def test_get_patch_content_returns_representative_match_when_duplicate_candidate_urls_exist(
    client, db_session, tmp_path
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    db_session.flush()

    missing_path = tmp_path / "missing.patch"
    readable_path = tmp_path / "readable.patch"
    readable_text = "diff --git a/app.py b/app.py\n+preferred\n"
    readable_path.write_text(readable_text, encoding="utf-8")

    missing_artifact = Artifact(
        artifact_kind="patch",
        scene_name="cve",
        source_url="https://example.com/fix.patch",
        storage_path=str(missing_path),
        content_type="text/x-patch",
        checksum="sha256-missing",
        metadata_json={},
    )
    readable_artifact = Artifact(
        artifact_kind="patch",
        scene_name="cve",
        source_url="https://example.com/fix.patch",
        storage_path=str(readable_path),
        content_type="text/x-patch",
        checksum="sha256-readable",
        metadata_json={},
    )
    db_session.add_all([missing_artifact, readable_artifact])
    db_session.flush()

    db_session.add_all(
        [
            CVEPatchArtifact(
                run_id=run.run_id,
                candidate_url="https://example.com/fix.patch",
                patch_type="patch",
                download_status="downloaded",
                artifact_id=missing_artifact.artifact_id,
                patch_meta_json={},
            ),
            CVEPatchArtifact(
                run_id=run.run_id,
                candidate_url="https://example.com/fix.patch",
                patch_type="patch",
                download_status="downloaded",
                artifact_id=readable_artifact.artifact_id,
                patch_meta_json={},
            ),
        ]
    )
    db_session.commit()
    readable_patch = db_session.execute(
        select(CVEPatchArtifact).where(
            CVEPatchArtifact.run_id == run.run_id,
            CVEPatchArtifact.artifact_id == readable_artifact.artifact_id,
        )
    ).scalar_one()

    response = client.get(
        f"/api/v1/cve/runs/{run.run_id}/patch-content",
        params={"patch_id": str(readable_patch.patch_id)},
    )

    assert response.status_code == 200
    assert response.json()["data"] == {
        "patch_id": str(readable_patch.patch_id),
        "candidate_url": "https://example.com/fix.patch",
        "content": readable_text,
    }


def test_get_cve_run_detail_deduplicates_duplicate_patch_urls(client, db_session, tmp_path) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    run.status = "succeeded"
    run.phase = "finalize_run"
    run.stop_reason = "patches_downloaded"
    run.summary_json = {"patch_found": True, "patch_count": 1}
    db_session.flush()

    readable_path = tmp_path / "readable.patch"
    readable_path.write_text("diff --git a/app.py b/app.py\n+preferred\n", encoding="utf-8")
    readable_artifact = Artifact(
        artifact_kind="patch",
        scene_name="cve",
        source_url="https://example.com/fix.patch",
        storage_path=str(readable_path),
        content_type="text/x-patch",
        checksum="sha256-readable",
        metadata_json={},
    )
    missing_artifact = Artifact(
        artifact_kind="patch",
        scene_name="cve",
        source_url="https://example.com/fix.patch",
        storage_path=str(tmp_path / "missing.patch"),
        content_type="text/x-patch",
        checksum="sha256-missing",
        metadata_json={},
    )
    db_session.add_all([missing_artifact, readable_artifact])
    db_session.flush()

    db_session.add_all(
        [
            CVEPatchArtifact(
                run_id=run.run_id,
                candidate_url="https://example.com/fix.patch",
                patch_type="patch",
                download_status="downloaded",
                artifact_id=missing_artifact.artifact_id,
                patch_meta_json={"download_url": "https://example.com/fix.patch"},
            ),
            CVEPatchArtifact(
                run_id=run.run_id,
                candidate_url="https://example.com/fix.patch",
                patch_type="patch",
                download_status="downloaded",
                artifact_id=readable_artifact.artifact_id,
                patch_meta_json={"download_url": "https://example.com/fix.patch"},
            ),
        ]
    )
    db_session.commit()
    readable_patch = db_session.execute(
        select(CVEPatchArtifact).where(
            CVEPatchArtifact.run_id == run.run_id,
            CVEPatchArtifact.artifact_id == readable_artifact.artifact_id,
        )
    ).scalar_one()

    response = client.get(f"/api/v1/cve/runs/{run.run_id}")

    assert response.status_code == 200
    assert response.json()["data"]["patches"] == [
        {
            "patch_id": str(readable_patch.patch_id),
            "candidate_url": "https://example.com/fix.patch",
            "patch_type": "patch",
            "download_status": "downloaded",
            "artifact_id": str(readable_artifact.artifact_id),
            "duplicate_count": 2,
            "content_available": True,
            "content_type": "text/x-patch",
            "download_url": "https://example.com/fix.patch",
        }
    ]


def test_get_cve_run_patch_marks_content_unavailable_when_file_is_missing(
    client, db_session, tmp_path
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    run.status = "succeeded"
    run.phase = "finalize_run"
    run.stop_reason = "patches_downloaded"
    run.summary_json = {"patch_found": True, "patch_count": 1}
    db_session.flush()

    missing_path = tmp_path / "missing.patch"
    artifact = Artifact(
        artifact_kind="patch",
        scene_name="cve",
        source_url="https://example.com/missing.patch",
        storage_path=str(missing_path),
        content_type="text/x-patch",
        checksum="sha256-missing",
        metadata_json={},
    )
    db_session.add(artifact)
    db_session.flush()
    db_session.add(
        CVEPatchArtifact(
            run_id=run.run_id,
            candidate_url="https://example.com/missing.patch",
            patch_type="patch",
            download_status="downloaded",
            artifact_id=artifact.artifact_id,
            patch_meta_json={"download_url": "https://example.com/missing.patch"},
        )
    )
    db_session.commit()

    response = client.get(f"/api/v1/cve/runs/{run.run_id}")

    assert response.status_code == 200
    assert response.json()["data"]["patches"][0]["content_available"] is False
