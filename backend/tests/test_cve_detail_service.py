from pathlib import Path

from app.cve.detail_service import get_cve_run_detail
from app.cve.search_graph_service import (
    record_search_decision,
    record_search_edge,
    record_search_node,
)
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
    assert len(detail["fix_families"]) == 1
    family = detail["fix_families"][0]
    assert family["family_key"] == "family:https://example.com/advisory"
    assert family["title"] == "example.com"
    assert family["source_url"] == "https://example.com/advisory"
    assert family["source_host"] == "example.com"
    assert family["discovery_rule"] == "matcher"
    assert family["patch_count"] == 2
    assert family["downloaded_patch_count"] == 1
    assert family["primary_patch_id"] == str(primary_patch.patch_id)
    assert set(family["patch_ids"]) == {str(primary_patch.patch_id), str(secondary_patch.patch_id)}
    assert set(family["patch_types"]) == {"patch", "diff"}
    assert family["evidence_source_count"] == 1
    assert family["related_source_hosts"] == ["example.com"]
    assert family["evidence_sources"] == [
        {
            "source_url": "https://example.com/advisory",
            "source_host": "example.com",
            "discovery_rule": "matcher",
            "source_kind": "page",
            "order": 0,
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
            "evidence_source_count": 1,
            "related_source_hosts": ["fallback.example.com"],
            "evidence_sources": [
                {
                    "source_url": "https://fallback.example.com/fix.patch",
                    "source_host": "fallback.example.com",
                    "discovery_rule": "unknown",
                    "source_kind": "candidate",
                    "order": 0,
                }
            ],
        }
    ]


def test_get_cve_run_detail_merges_distinct_evidence_sources_within_same_family(
    db_session, tmp_path
) -> None:
    run = create_cve_run(db_session, cve_id="CVE-2024-3094")
    run.status = "succeeded"
    run.phase = "finalize_run"
    run.stop_reason = "patches_downloaded"
    db_session.flush()

    patch_path = tmp_path / "fix.patch"
    patch_path.write_text("diff --git a/a b/a\n+patched\n", encoding="utf-8")
    artifact = Artifact(
        artifact_kind="patch",
        scene_name="cve",
        source_url="https://example.com/fix.patch",
        storage_path=str(patch_path),
        content_type="text/x-patch",
        checksum="sha256-fix",
        metadata_json={},
    )
    db_session.add(artifact)
    db_session.flush()

    patch = CVEPatchArtifact(
        run_id=run.run_id,
        candidate_url="https://example.com/fix.patch",
        patch_type="patch",
        download_status="downloaded",
        artifact_id=artifact.artifact_id,
        patch_meta_json={
            "download_url": "https://example.com/fix.patch",
            "discovered_from_url": "https://example.com/advisory",
            "discovered_from_host": "example.com",
            "discovery_rule": "matcher",
            "discovery_sources": [
                {
                    "source_url": "https://example.com/advisory",
                    "source_host": "example.com",
                    "discovery_rule": "matcher",
                    "source_kind": "page",
                    "order": 0,
                },
                {
                    "source_url": "https://mirror.example.com/advisory",
                    "source_host": "mirror.example.com",
                    "discovery_rule": "matcher",
                    "source_kind": "page",
                    "order": 1,
                },
            ],
            "evidence_source_count": 2,
        },
    )
    db_session.add(patch)
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
            "patch_count": 1,
            "downloaded_patch_count": 1,
            "primary_patch_id": str(patch.patch_id),
            "patch_ids": [str(patch.patch_id)],
            "patch_types": ["patch"],
            "evidence_source_count": 2,
            "related_source_hosts": ["example.com", "mirror.example.com"],
            "evidence_sources": [
                {
                    "source_url": "https://example.com/advisory",
                    "source_host": "example.com",
                    "discovery_rule": "matcher",
                    "source_kind": "page",
                    "order": 0,
                },
                {
                    "source_url": "https://mirror.example.com/advisory",
                    "source_host": "mirror.example.com",
                    "discovery_rule": "matcher",
                    "source_kind": "page",
                    "order": 1,
                },
            ],
        }
    ]


def test_get_cve_run_detail_returns_search_graph_and_decision_history(db_session) -> None:
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
        anchor_text="advisory",
        link_context="link context",
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

    detail = get_cve_run_detail(db_session, run_id=run.run_id)

    assert detail is not None
    assert detail["search_graph"]["nodes"] == [
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
    assert detail["search_graph"]["edges"] == [
        {
            "from_node_id": str(root_node.node_id),
            "to_node_id": str(child_node.node_id),
            "edge_type": "follow_link",
            "selected_by": "agent",
        }
    ]
    assert detail["frontier_status"] == {
        "total_nodes": 2,
        "max_depth": 1,
        "active_node_count": 1,
    }
    assert detail["decision_history"] == [
        {
            "decision_type": "expand_frontier",
            "validated": True,
            "model_name": "gpt-5",
            "node_id": str(child_node.node_id),
        }
    ]
