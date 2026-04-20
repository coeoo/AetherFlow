from app.db.base import Base
from sqlalchemy import UniqueConstraint


def _foreign_key_signatures(table: object) -> set[tuple[tuple[str, ...], tuple[str, ...]]]:
    signatures: set[tuple[tuple[str, ...], tuple[str, ...]]] = set()
    for constraint in table.foreign_key_constraints:
        local_columns = tuple(element.parent.name for element in constraint.elements)
        target_columns = tuple(element.target_fullname for element in constraint.elements)
        signatures.add((local_columns, target_columns))
    return signatures


def _find_foreign_key(
    table: object,
    local_columns: tuple[str, ...],
    target_columns: tuple[str, ...],
) -> object | None:
    for constraint in table.foreign_key_constraints:
        current_local_columns = tuple(element.parent.name for element in constraint.elements)
        current_target_columns = tuple(element.target_fullname for element in constraint.elements)
        if current_local_columns == local_columns and current_target_columns == target_columns:
            return constraint
    return None


def test_cve_metadata_contains_patch_agent_graph_tables() -> None:
    assert {
        "cve_search_nodes",
        "cve_search_edges",
        "cve_search_decisions",
        "cve_candidate_artifacts",
    }.issubset(Base.metadata.tables)


def test_cve_search_nodes_keeps_run_binding_and_features() -> None:
    nodes = Base.metadata.tables["cve_search_nodes"]
    column_names = set(nodes.columns.keys())

    assert {
        "run_id",
        "url",
        "depth",
        "host",
        "page_role",
        "fetch_status",
        "content_excerpt",
        "heuristic_features_json",
    }.issubset(column_names)
    assert "cve_runs.run_id" in {
        foreign_key.target_fullname for foreign_key in nodes.c["run_id"].foreign_keys
    }
    unique_constraints = {
        constraint.name: tuple(column.name for column in constraint.columns)
        for constraint in nodes.constraints
        if isinstance(constraint, UniqueConstraint)
    }
    assert unique_constraints.get("uq_cve_search_nodes_run_node_id") == ("run_id", "node_id")


def test_cve_search_edges_link_node_graph() -> None:
    edges = Base.metadata.tables["cve_search_edges"]
    column_names = set(edges.columns.keys())

    assert {
        "run_id",
        "from_node_id",
        "to_node_id",
        "edge_type",
        "anchor_text",
        "link_context",
        "selected_by",
    }.issubset(column_names)
    foreign_key_signatures = _foreign_key_signatures(edges)
    assert (
        ("run_id", "from_node_id"),
        ("cve_search_nodes.run_id", "cve_search_nodes.node_id"),
    ) in foreign_key_signatures
    assert (
        ("run_id", "to_node_id"),
        ("cve_search_nodes.run_id", "cve_search_nodes.node_id"),
    ) in foreign_key_signatures


def test_cve_search_decisions_keeps_decision_audit_fields() -> None:
    decisions = Base.metadata.tables["cve_search_decisions"]
    column_names = set(decisions.columns.keys())

    assert {
        "run_id",
        "node_id",
        "decision_type",
        "model_name",
        "input_json",
        "output_json",
        "validated",
        "rejection_reason",
    }.issubset(column_names)
    assert decisions.c["validated"].nullable is False
    foreign_key_signatures = _foreign_key_signatures(decisions)
    assert (
        ("run_id", "node_id"),
        ("cve_search_nodes.run_id", "cve_search_nodes.node_id"),
    ) in foreign_key_signatures
    single_node_fk = _find_foreign_key(
        decisions,
        ("node_id",),
        ("cve_search_nodes.node_id",),
    )
    assert single_node_fk is not None
    assert single_node_fk.ondelete == "SET NULL"


def test_cve_candidate_artifacts_tracks_candidate_convergence() -> None:
    candidates = Base.metadata.tables["cve_candidate_artifacts"]
    column_names = set(candidates.columns.keys())

    assert {
        "run_id",
        "source_node_id",
        "candidate_url",
        "candidate_type",
        "canonical_key",
        "download_status",
        "validation_status",
        "artifact_id",
        "evidence_json",
    }.issubset(column_names)

    unique_constraint_names = {
        constraint.name for constraint in candidates.constraints if isinstance(constraint, UniqueConstraint)
    }
    assert "uq_cve_candidate_artifacts_run_canonical_key" in unique_constraint_names
    foreign_key_signatures = _foreign_key_signatures(candidates)
    assert (
        ("run_id", "source_node_id"),
        ("cve_search_nodes.run_id", "cve_search_nodes.node_id"),
    ) in foreign_key_signatures
    single_source_node_fk = _find_foreign_key(
        candidates,
        ("source_node_id",),
        ("cve_search_nodes.node_id",),
    )
    assert single_source_node_fk is not None
    assert single_source_node_fk.ondelete == "SET NULL"
    assert "artifacts.artifact_id" in {
        foreign_key.target_fullname for foreign_key in candidates.c["artifact_id"].foreign_keys
    }
