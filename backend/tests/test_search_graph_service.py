import pytest
from sqlalchemy.exc import IntegrityError

from app.cve.search_graph_service import (
    record_candidate_artifact,
    record_search_decision,
    record_search_edge,
    record_search_node,
)
from app.models.cve import (
    CVERun,
    CVECandidateArtifact,
    CVESearchDecision,
    CVESearchEdge,
    CVESearchNode,
)
from app.models.platform import TaskJob


def _create_second_run(db_session):
    job = TaskJob(
        scene_name="cve",
        job_type="cve_patch_agent_graph",
        trigger_kind="manual",
        status="queued",
        payload_json={},
    )
    db_session.add(job)
    db_session.flush()
    run = CVERun(
        job_id=job.job_id,
        cve_id="CVE-2025-0001",
        status="queued",
        phase="resolve_seeds",
        summary_json={},
    )
    db_session.add(run)
    db_session.flush()
    return run


def test_record_search_node_and_edge_persists_graph_relationships(seeded_cve_run, db_session) -> None:
    run_id = seeded_cve_run.run_id

    from_node = record_search_node(
        db_session,
        run_id=run_id,
        url="https://example.com/a",
        depth=0,
        host="example.com",
        page_role="seed_reference",
        fetch_status="succeeded",
        content_excerpt="seed page",
        heuristic_features={"score": 0.9},
        flush=True,
    )
    to_node = record_search_node(
        db_session,
        run_id=run_id,
        url="https://example.com/b",
        depth=1,
        host="example.com",
        page_role="candidate_page",
        fetch_status="succeeded",
        heuristic_features={"score": 0.7},
        flush=True,
    )

    edge = record_search_edge(
        db_session,
        run_id=run_id,
        from_node_id=from_node.node_id,
        to_node_id=to_node.node_id,
        edge_type="follow_link",
        selected_by="heuristic",
        anchor_text="download patch",
        link_context="context around link",
        flush=True,
    )
    db_session.commit()

    assert isinstance(from_node, CVESearchNode)
    assert isinstance(to_node, CVESearchNode)
    assert isinstance(edge, CVESearchEdge)
    assert edge.run_id == run_id
    assert edge.from_node_id == from_node.node_id
    assert edge.to_node_id == to_node.node_id
    assert edge.anchor_text == "download patch"
    assert edge.link_context == "context around link"


def test_record_helpers_require_explicit_flush_to_get_server_generated_primary_key(
    seeded_cve_run, db_session
) -> None:
    node = record_search_node(
        db_session,
        run_id=seeded_cve_run.run_id,
        url="https://example.com/no-flush",
        depth=0,
        host="example.com",
        page_role="seed_reference",
        fetch_status="succeeded",
        heuristic_features={"score": 1.0},
    )

    assert node.node_id is None
    db_session.flush()
    assert node.node_id is not None


def test_record_search_decision_supports_nullable_node_id(seeded_cve_run, db_session) -> None:
    run_id = seeded_cve_run.run_id

    decision = record_search_decision(
        db_session,
        run_id=run_id,
        decision_type="expand_frontier",
        input_payload={"frontier_size": 3},
        output_payload={"selected": ["https://example.com/a"]},
        validated=True,
        node_id=None,
        model_name="gpt-5-mini",
        rejection_reason=None,
        flush=True,
    )
    db_session.commit()

    assert isinstance(decision, CVESearchDecision)
    assert decision.run_id == run_id
    assert decision.node_id is None
    assert decision.validated is True
    assert decision.input_json == {"frontier_size": 3}
    assert decision.output_json == {"selected": ["https://example.com/a"]}


def test_record_search_decision_rejects_node_from_other_run(seeded_cve_run, db_session) -> None:
    current_run_id = seeded_cve_run.run_id
    other_run = _create_second_run(db_session)
    other_node = record_search_node(
        db_session,
        run_id=other_run.run_id,
        url="https://example.com/other-node",
        depth=0,
        host="example.com",
        page_role="seed_reference",
        fetch_status="succeeded",
        flush=True,
    )

    with pytest.raises(ValueError, match="run_id"):
        record_search_decision(
            db_session,
            run_id=current_run_id,
            decision_type="expand_frontier",
            input_payload={},
            output_payload={},
            node_id=other_node.node_id,
        )


def test_record_candidate_artifact_supports_nullable_source_node_id(
    seeded_cve_run, db_session
) -> None:
    run_id = seeded_cve_run.run_id

    candidate = record_candidate_artifact(
        db_session,
        run_id=run_id,
        candidate_url="https://example.com/patch.diff",
        candidate_type="patch_url",
        canonical_key="example.com:patch.diff",
        download_status="pending",
        validation_status="unchecked",
        source_node_id=None,
        artifact_id=None,
        evidence={"discovered_from": "seed"},
        flush=True,
    )
    db_session.commit()

    assert isinstance(candidate, CVECandidateArtifact)
    assert candidate.run_id == run_id
    assert candidate.source_node_id is None
    assert candidate.canonical_key == "example.com:patch.diff"
    assert candidate.evidence_json == {"discovered_from": "seed"}


def test_record_candidate_artifact_enforces_run_and_canonical_key_uniqueness(
    seeded_cve_run, db_session
) -> None:
    run_id = seeded_cve_run.run_id

    record_candidate_artifact(
        db_session,
        run_id=run_id,
        candidate_url="https://example.com/patch.diff",
        candidate_type="patch_url",
        canonical_key="dup-key",
        download_status="pending",
        validation_status="unchecked",
        evidence={"source": "first"},
        flush=True,
    )

    with pytest.raises(IntegrityError):
        record_candidate_artifact(
            db_session,
            run_id=run_id,
            candidate_url="https://mirror.example.com/patch.diff",
            candidate_type="patch_url",
            canonical_key="dup-key",
            download_status="pending",
            validation_status="unchecked",
            evidence={"source": "second"},
            flush=True,
        )

    db_session.rollback()


def test_record_search_edge_rejects_cross_run_node_reference(seeded_cve_run, db_session) -> None:
    current_run_id = seeded_cve_run.run_id
    current_node = record_search_node(
        db_session,
        run_id=current_run_id,
        url="https://example.com/current",
        depth=0,
        host="example.com",
        page_role="seed_reference",
        fetch_status="succeeded",
        flush=True,
    )
    other_run = _create_second_run(db_session)
    other_node = record_search_node(
        db_session,
        run_id=other_run.run_id,
        url="https://example.com/other",
        depth=0,
        host="example.com",
        page_role="seed_reference",
        fetch_status="succeeded",
        flush=True,
    )

    with pytest.raises(ValueError, match="run_id"):
        record_search_edge(
            db_session,
            run_id=current_run_id,
            from_node_id=current_node.node_id,
            to_node_id=other_node.node_id,
            edge_type="follow_link",
            selected_by="heuristic",
        )


def test_record_candidate_artifact_rejects_source_node_from_other_run(
    seeded_cve_run, db_session
) -> None:
    current_run_id = seeded_cve_run.run_id
    other_run = _create_second_run(db_session)
    other_node = record_search_node(
        db_session,
        run_id=other_run.run_id,
        url="https://example.com/other-source",
        depth=0,
        host="example.com",
        page_role="seed_reference",
        fetch_status="succeeded",
        flush=True,
    )

    with pytest.raises(ValueError, match="run_id"):
        record_candidate_artifact(
            db_session,
            run_id=current_run_id,
            candidate_url="https://example.com/patch.diff",
            candidate_type="patch_url",
            canonical_key="cross-run-key",
            download_status="pending",
            validation_status="unchecked",
            source_node_id=other_node.node_id,
        )


@pytest.mark.parametrize(
    ("payload_field", "builder"),
    [
        (
            "heuristic_features",
            lambda session, run_id: record_search_node(
                session,
                run_id=run_id,
                url="https://example.com/json-node",
                depth=0,
                host="example.com",
                page_role="seed_reference",
                fetch_status="succeeded",
                heuristic_features={"bad": {1, 2}},
            ),
        ),
        (
            "input_payload",
            lambda session, run_id: record_search_decision(
                session,
                run_id=run_id,
                decision_type="expand_frontier",
                input_payload={"bad": {1, 2}},
                output_payload={},
            ),
        ),
        (
            "output_payload",
            lambda session, run_id: record_search_decision(
                session,
                run_id=run_id,
                decision_type="expand_frontier",
                input_payload={},
                output_payload={"bad": {1, 2}},
            ),
        ),
        (
            "evidence",
            lambda session, run_id: record_candidate_artifact(
                session,
                run_id=run_id,
                candidate_url="https://example.com/json-candidate",
                candidate_type="patch_url",
                canonical_key="json-check-key",
                download_status="pending",
                validation_status="unchecked",
                evidence={"bad": {1, 2}},
            ),
        ),
    ],
)
def test_record_helpers_reject_non_json_serializable_payload(
    seeded_cve_run, db_session, payload_field, builder
) -> None:
    with pytest.raises(TypeError, match=payload_field):
        builder(db_session, seeded_cve_run.run_id)
