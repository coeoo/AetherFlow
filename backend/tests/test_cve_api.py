import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path

from sqlalchemy import select

from app.cve.search_graph_service import (
    record_search_decision,
    record_search_edge,
    record_search_node,
)
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
    assert job.job_type == "cve_patch_agent_graph"
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
        "primary_family_source_url": "https://www.openwall.com/lists/oss-security/2024/03/29/4",
        "primary_family_source_host": "www.openwall.com",
        "primary_family_evidence_source_count": 3,
        "primary_family_related_source_hosts": ["www.openwall.com"],
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
                "primary_family_source_url": "https://www.openwall.com/lists/oss-security/2024/03/29/4",
                "primary_family_source_host": "www.openwall.com",
                "primary_family_evidence_source_count": 3,
                "primary_family_related_source_hosts": ["www.openwall.com"],
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
    job = db_session.get(TaskJob, run.job_id)
    assert job is not None
    job.job_type = "cve_patch_agent_graph"
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
                request_snapshot_json={
                    "cve_id": run.cve_id,
                    "sources": ["cve_official", "osv", "github_advisory", "nvd"],
                    "request_urls": {
                        "cve_official": f"https://cveawg.mitre.org/api/cve/{run.cve_id}",
                        "osv": f"https://api.osv.dev/v1/vulns/{run.cve_id}",
                        "github_advisory": f"https://api.github.com/advisories?cve_id={run.cve_id}&per_page=20",
                        "nvd": f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={run.cve_id}",
                    },
                },
                response_meta_json={
                    "status_code": 200,
                    "reference_count": 2,
                    "source_results": [
                        {
                            "source": "cve_official",
                            "status": "success",
                            "status_code": 200,
                            "reference_count": 2,
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
                    ],
                },
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
    assert body["data"]["progress"]["current_phase"] == "finalize_run"
    assert body["data"]["progress"]["completed_steps"] == 7
    assert body["data"]["progress"]["total_steps"] == 7
    assert body["data"]["progress"]["terminal"] is True
    assert body["data"]["progress"]["percent"] == 100
    assert body["data"]["progress"]["status_label"] == "已完成"
    assert body["data"]["progress"]["latest_signal"] == "已完成补丁下载，结果可以开始复查。"
    assert body["data"]["progress"]["visited_trace_count"] == 3
    assert body["data"]["progress"]["downloaded_patch_count"] == 1
    assert body["data"]["progress"]["failed_trace_count"] == 0
    assert body["data"]["progress"]["active_url"] == "https://example.com/fix.patch"
    assert body["data"]["progress"]["last_updated_at"] is not None
    assert body["data"]["progress"]["last_meaningful_update_at"] is not None
    assert len(body["data"]["recent_progress"]) == 3
    assert {item["step"] for item in body["data"]["recent_progress"]} == {
        "cve_seed_resolve",
        "cve_page_fetch",
        "cve_patch_download",
    }
    assert len(body["data"]["source_traces"]) == 3
    traces_by_step = {item["step"]: item for item in body["data"]["source_traces"]}
    assert traces_by_step["cve_page_fetch"]["url"] == "https://example.com/advisory"
    assert traces_by_step["cve_seed_resolve"]["response_meta"]["source_results"] == [
        {
            "source": "cve_official",
            "status": "success",
            "status_code": 200,
            "reference_count": 2,
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


def test_get_cve_run_detail_includes_search_graph_fields(client, db_session) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    run.status = "running"
    run.phase = "agent_decide"
    db_session.flush()

    root_node = record_search_node(
        db_session,
        run_id=run.run_id,
        url="https://security-tracker.debian.org/tracker/CVE-2024-3094",
        depth=0,
        host="security-tracker.debian.org",
        page_role="frontier_page",
        fetch_status="queued",
        heuristic_features={"frontier_score": 10},
        flush=True,
    )
    child_node = record_search_node(
        db_session,
        run_id=run.run_id,
        url="https://example.com/advisory",
        depth=1,
        host="example.com",
        page_role="bridge_page",
        fetch_status="fetched",
        heuristic_features={"frontier_score": 7},
        flush=True,
    )
    record_search_edge(
        db_session,
        run_id=run.run_id,
        from_node_id=root_node.node_id,
        to_node_id=child_node.node_id,
        edge_type="follow_link",
        selected_by="agent",
        flush=True,
    )
    record_search_decision(
        db_session,
        run_id=run.run_id,
        node_id=child_node.node_id,
        decision_type="expand_frontier",
        input_payload={"frontier_count": 1},
        output_payload={"selected_urls": ["https://example.com/advisory"]},
        validated=True,
        model_name="gpt-5",
        flush=True,
    )
    db_session.commit()

    response = client.get(f"/api/v1/cve/runs/{run.run_id}")

    assert response.status_code == 200
    payload = response.json()["data"]
    assert payload["search_graph"]["nodes"] == [
        {
            "node_id": str(root_node.node_id),
            "url": "https://security-tracker.debian.org/tracker/CVE-2024-3094",
            "depth": 0,
            "host": "security-tracker.debian.org",
            "page_role": "frontier_page",
            "fetch_status": "queued",
        },
        {
            "node_id": str(child_node.node_id),
            "url": "https://example.com/advisory",
            "depth": 1,
            "host": "example.com",
            "page_role": "bridge_page",
            "fetch_status": "fetched",
        },
    ]
    assert payload["search_graph"]["edges"] == [
        {
            "from_node_id": str(root_node.node_id),
            "to_node_id": str(child_node.node_id),
            "edge_type": "follow_link",
            "selected_by": "agent",
        }
    ]
    assert payload["frontier_status"] == {
        "total_nodes": 2,
        "max_depth": 1,
        "active_node_count": 1,
    }
    assert payload["progress"]["current_phase"] == "agent_decide"
    assert payload["progress"]["completed_steps"] > 0
    assert payload["progress"]["total_steps"] >= 7
    assert payload["progress"]["percent"] > 0
    assert payload["progress"]["status_label"] == "Agent 决策中"
    assert payload["decision_history"] == [
        {
            "decision_type": "expand_frontier",
            "validated": True,
            "model_name": "gpt-5",
            "node_id": str(child_node.node_id),
        }
    ]


def test_get_cve_run_detail_keeps_legacy_progress_contract_for_fast_first_run(
    client, db_session
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    run.status = "succeeded"
    run.phase = "finalize_run"
    run.stop_reason = "patches_downloaded"
    run.summary_json = {"patch_found": True, "patch_count": 1}
    db_session.commit()

    response = client.get(f"/api/v1/cve/runs/{run.run_id}")

    assert response.status_code == 200
    progress = response.json()["data"]["progress"]
    assert progress["current_phase"] == "finalize_run"
    assert progress["completed_steps"] == 6
    assert progress["total_steps"] == 6


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
    progress = response.json()["data"]["progress"]
    assert progress["current_phase"] == "fetch_page"
    assert progress["completed_steps"] == 2
    assert progress["total_steps"] == 6
    assert progress["terminal"] is True
    assert progress["percent"] == 40
    assert progress["status_label"] == "已失败"
    assert progress["latest_signal"] == "运行在抓取页面阶段失败。"
    assert progress["visited_trace_count"] == 0
    assert progress["downloaded_patch_count"] == 0
    assert progress["failed_trace_count"] == 0
    assert progress["active_url"] is None


def test_get_cve_run_detail_returns_llm_fallback_summary_fields(client, db_session) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    run.status = "failed"
    run.phase = "download_patches"
    run.stop_reason = "patch_download_failed"
    run.summary_json = {
        "patch_found": False,
        "patch_count": 0,
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
    }
    db_session.commit()

    response = client.get(f"/api/v1/cve/runs/{run.run_id}")

    assert response.status_code == 200
    assert response.json()["data"]["summary"] == {
        "patch_found": False,
        "patch_count": 0,
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
