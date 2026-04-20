import os
import subprocess
from pathlib import Path
import sys
import uuid

import pytest
from sqlalchemy.exc import IntegrityError
from sqlalchemy import create_engine, inspect, text

from app.db.base import Base
from app import models  # noqa: F401


ROOT_DIR = Path(__file__).resolve().parents[2]
BACKEND_DIR = ROOT_DIR / "backend"
PYTHON_BIN = Path(sys.executable)


def reset_public_schema(database_url: str) -> None:
    engine = create_engine(database_url, future=True)

    with engine.begin() as connection:
        connection.execute(text("DROP SCHEMA IF EXISTS public CASCADE"))
        connection.execute(text("CREATE SCHEMA public"))

    engine.dispose()


def test_alembic_upgrade_head(test_database_url: str) -> None:
    reset_public_schema(test_database_url)

    env = os.environ | {"DATABASE_URL": test_database_url}
    result = subprocess.run(
        [str(PYTHON_BIN), "-m", "alembic", "upgrade", "head"],
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr

    engine = create_engine(test_database_url, future=True)
    try:
        table_names = set(inspect(engine).get_table_names())
    finally:
        engine.dispose()

    assert {
        "alembic_version",
        "task_jobs",
        "task_attempts",
        "task_attempt_artifacts",
        "delivery_targets",
        "delivery_records",
        "artifacts",
        "runtime_heartbeats",
        "source_fetch_records",
        "cve_runs",
        "cve_search_nodes",
        "cve_search_edges",
        "cve_search_decisions",
        "cve_candidate_artifacts",
        "cve_patch_artifacts",
        "announcement_sources",
        "announcement_runs",
        "announcement_documents",
        "announcement_intelligence_packages",
    }.issubset(table_names)


def test_platform_metadata_matches_bootstrap_contract() -> None:
    task_jobs = Base.metadata.tables["task_jobs"]
    task_attempts = Base.metadata.tables["task_attempts"]
    delivery_records = Base.metadata.tables["delivery_records"]

    check_constraint_names = {constraint.name for constraint in task_jobs.constraints}
    assert "ck_task_jobs_scene_name" in check_constraint_names

    task_job_index_names = {index.name for index in task_jobs.indexes}
    assert {
        "idx_task_jobs_scene_status",
        "idx_task_jobs_created_at",
        "idx_task_jobs_trigger_kind",
    }.issubset(task_job_index_names)

    unique_constraint_names = {constraint.name for constraint in task_attempts.constraints}
    assert "uq_task_attempts_job_attempt_no" in unique_constraint_names

    assert "delivery_kind" in delivery_records.c
    assert "scheduled_at" in delivery_records.c
    assert "updated_at" in delivery_records.c


def test_alembic_incremental_upgrade_adds_delivery_record_columns(test_database_url: str) -> None:
    reset_public_schema(test_database_url)

    env = os.environ | {"DATABASE_URL": test_database_url}
    upgrade_base = subprocess.run(
        [str(PYTHON_BIN), "-m", "alembic", "upgrade", "20260415_0003"],
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
    )
    assert upgrade_base.returncode == 0, upgrade_base.stderr

    engine = create_engine(test_database_url, future=True)
    try:
        base_tables = set(inspect(engine).get_table_names())
        base_columns = {column["name"] for column in inspect(engine).get_columns("delivery_records")}
    finally:
        engine.dispose()

    assert "delivery_kind" not in base_columns
    assert "scheduled_at" not in base_columns
    assert "updated_at" not in base_columns
    assert "cve_search_nodes" not in base_tables
    assert "cve_search_edges" not in base_tables
    assert "cve_search_decisions" not in base_tables
    assert "cve_candidate_artifacts" not in base_tables

    upgrade_head = subprocess.run(
        [str(PYTHON_BIN), "-m", "alembic", "upgrade", "head"],
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
    )
    assert upgrade_head.returncode == 0, upgrade_head.stderr

    engine = create_engine(test_database_url, future=True)
    try:
        upgraded_tables = set(inspect(engine).get_table_names())
        upgraded_columns = {column["name"] for column in inspect(engine).get_columns("delivery_records")}
    finally:
        engine.dispose()

    assert {"delivery_kind", "scheduled_at", "updated_at"}.issubset(upgraded_columns)
    assert {
        "cve_search_nodes",
        "cve_search_edges",
        "cve_search_decisions",
        "cve_candidate_artifacts",
    }.issubset(upgraded_tables)


def test_alembic_downgrade_removes_cve_patch_agent_graph_tables(test_database_url: str) -> None:
    reset_public_schema(test_database_url)

    env = os.environ | {"DATABASE_URL": test_database_url}
    upgrade_head = subprocess.run(
        [str(PYTHON_BIN), "-m", "alembic", "upgrade", "head"],
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
    )
    assert upgrade_head.returncode == 0, upgrade_head.stderr

    downgrade = subprocess.run(
        [str(PYTHON_BIN), "-m", "alembic", "downgrade", "20260417_0004"],
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
    )
    assert downgrade.returncode == 0, downgrade.stderr

    engine = create_engine(test_database_url, future=True)
    try:
        table_names = set(inspect(engine).get_table_names())
    finally:
        engine.dispose()

    assert "cve_runs" in table_names
    assert "cve_patch_artifacts" in table_names
    assert "cve_search_nodes" not in table_names
    assert "cve_search_edges" not in table_names
    assert "cve_search_decisions" not in table_names
    assert "cve_candidate_artifacts" not in table_names


def test_alembic_head_enforces_candidate_canonical_key_uniqueness(test_database_url: str) -> None:
    reset_public_schema(test_database_url)

    env = os.environ | {"DATABASE_URL": test_database_url}
    upgrade_head = subprocess.run(
        [str(PYTHON_BIN), "-m", "alembic", "upgrade", "head"],
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
    )
    assert upgrade_head.returncode == 0, upgrade_head.stderr

    job_id = uuid.uuid4()
    run_id = uuid.uuid4()
    canonical_key = "git.kernel.org:abc123"

    engine = create_engine(test_database_url, future=True)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO task_jobs (
                        job_id, scene_name, job_type, trigger_kind, status, payload_json
                    )
                    VALUES (
                        :job_id, 'cve', 'cve_patch_agent_graph', 'manual', 'queued', '{}'::jsonb
                    )
                    """
                ),
                {"job_id": job_id},
            )
            connection.execute(
                text(
                    """
                    INSERT INTO cve_runs (
                        run_id, job_id, cve_id, status, phase, summary_json
                    )
                    VALUES (
                        :run_id, :job_id, 'CVE-2024-3094', 'running', 'agent_decide', '{}'::jsonb
                    )
                    """
                ),
                {"run_id": run_id, "job_id": job_id},
            )
            connection.execute(
                text(
                    """
                    INSERT INTO cve_candidate_artifacts (
                        candidate_id,
                        run_id,
                        source_node_id,
                        candidate_url,
                        candidate_type,
                        canonical_key,
                        download_status,
                        validation_status,
                        artifact_id,
                        evidence_json
                    )
                    VALUES (
                        gen_random_uuid(),
                        :run_id,
                        NULL,
                        'https://example.com/patch.diff',
                        'patch_url',
                        :canonical_key,
                        'succeeded',
                        'valid',
                        NULL,
                        '{}'::jsonb
                    )
                    """
                ),
                {"run_id": run_id, "canonical_key": canonical_key},
            )

            with pytest.raises(IntegrityError):
                connection.execute(
                    text(
                        """
                        INSERT INTO cve_candidate_artifacts (
                            candidate_id,
                            run_id,
                            source_node_id,
                            candidate_url,
                            candidate_type,
                            canonical_key,
                            download_status,
                            validation_status,
                            artifact_id,
                            evidence_json
                        )
                        VALUES (
                            gen_random_uuid(),
                            :run_id,
                            NULL,
                            'https://example.com/patch-v2.diff',
                            'patch_url',
                            :canonical_key,
                            'pending',
                            'pending',
                            NULL,
                            '{}'::jsonb
                        )
                        """
                    ),
                    {"run_id": run_id, "canonical_key": canonical_key},
                )
    finally:
        engine.dispose()


def test_alembic_head_rejects_cross_run_decision_node_reference(test_database_url: str) -> None:
    reset_public_schema(test_database_url)

    env = os.environ | {"DATABASE_URL": test_database_url}
    upgrade_head = subprocess.run(
        [str(PYTHON_BIN), "-m", "alembic", "upgrade", "head"],
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
    )
    assert upgrade_head.returncode == 0, upgrade_head.stderr

    job_a_id = uuid.uuid4()
    run_a_id = uuid.uuid4()
    node_a_id = uuid.uuid4()
    job_b_id = uuid.uuid4()
    run_b_id = uuid.uuid4()

    engine = create_engine(test_database_url, future=True)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO task_jobs (
                        job_id, scene_name, job_type, trigger_kind, status, payload_json
                    )
                    VALUES
                        (:job_a_id, 'cve', 'cve_patch_agent_graph', 'manual', 'queued', '{}'::jsonb),
                        (:job_b_id, 'cve', 'cve_patch_agent_graph', 'manual', 'queued', '{}'::jsonb)
                    """
                ),
                {"job_a_id": job_a_id, "job_b_id": job_b_id},
            )
            connection.execute(
                text(
                    """
                    INSERT INTO cve_runs (
                        run_id, job_id, cve_id, status, phase, summary_json
                    )
                    VALUES
                        (:run_a_id, :job_a_id, 'CVE-2024-3094', 'running', 'agent_decide', '{}'::jsonb),
                        (:run_b_id, :job_b_id, 'CVE-2024-3094', 'running', 'agent_decide', '{}'::jsonb)
                    """
                ),
                {
                    "run_a_id": run_a_id,
                    "job_a_id": job_a_id,
                    "run_b_id": run_b_id,
                    "job_b_id": job_b_id,
                },
            )
            connection.execute(
                text(
                    """
                    INSERT INTO cve_search_nodes (
                        node_id,
                        run_id,
                        url,
                        depth,
                        host,
                        page_role,
                        fetch_status,
                        content_excerpt,
                        heuristic_features_json
                    )
                    VALUES (
                        :node_a_id,
                        :run_a_id,
                        'https://example.com/a',
                        0,
                        'example.com',
                        'bridge_page',
                        'succeeded',
                        NULL,
                        '{}'::jsonb
                    )
                    """
                ),
                {"node_a_id": node_a_id, "run_a_id": run_a_id},
            )

            with pytest.raises(IntegrityError):
                connection.execute(
                    text(
                        """
                        INSERT INTO cve_search_decisions (
                            decision_id,
                            run_id,
                            node_id,
                            decision_type,
                            model_name,
                            input_json,
                            output_json,
                            validated,
                            rejection_reason
                        )
                        VALUES (
                            gen_random_uuid(),
                            :run_b_id,
                            :node_a_id,
                            'expand_frontier',
                            'gpt-5-mini',
                            '{}'::jsonb,
                            '{}'::jsonb,
                            TRUE,
                            NULL
                        )
                        """
                    ),
                    {"run_b_id": run_b_id, "node_a_id": node_a_id},
                )
    finally:
        engine.dispose()


def test_alembic_head_keeps_decision_and_candidate_set_null_on_node_delete(test_database_url: str) -> None:
    reset_public_schema(test_database_url)

    env = os.environ | {"DATABASE_URL": test_database_url}
    upgrade_head = subprocess.run(
        [str(PYTHON_BIN), "-m", "alembic", "upgrade", "head"],
        cwd=BACKEND_DIR,
        env=env,
        capture_output=True,
        text=True,
    )
    assert upgrade_head.returncode == 0, upgrade_head.stderr

    job_id = uuid.uuid4()
    run_id = uuid.uuid4()
    node_id = uuid.uuid4()
    decision_id = uuid.uuid4()
    candidate_id = uuid.uuid4()

    engine = create_engine(test_database_url, future=True)
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO task_jobs (
                        job_id, scene_name, job_type, trigger_kind, status, payload_json
                    )
                    VALUES (
                        :job_id, 'cve', 'cve_patch_agent_graph', 'manual', 'queued', '{}'::jsonb
                    )
                    """
                ),
                {"job_id": job_id},
            )
            connection.execute(
                text(
                    """
                    INSERT INTO cve_runs (
                        run_id, job_id, cve_id, status, phase, summary_json
                    )
                    VALUES (
                        :run_id, :job_id, 'CVE-2024-3094', 'running', 'agent_decide', '{}'::jsonb
                    )
                    """
                ),
                {"run_id": run_id, "job_id": job_id},
            )
            connection.execute(
                text(
                    """
                    INSERT INTO cve_search_nodes (
                        node_id,
                        run_id,
                        url,
                        depth,
                        host,
                        page_role,
                        fetch_status,
                        content_excerpt,
                        heuristic_features_json
                    )
                    VALUES (
                        :node_id,
                        :run_id,
                        'https://example.com/a',
                        0,
                        'example.com',
                        'bridge_page',
                        'succeeded',
                        NULL,
                        '{}'::jsonb
                    )
                    """
                ),
                {"node_id": node_id, "run_id": run_id},
            )
            connection.execute(
                text(
                    """
                    INSERT INTO cve_search_decisions (
                        decision_id,
                        run_id,
                        node_id,
                        decision_type,
                        model_name,
                        input_json,
                        output_json,
                        validated,
                        rejection_reason
                    )
                    VALUES (
                        :decision_id,
                        :run_id,
                        :node_id,
                        'expand_frontier',
                        'gpt-5-mini',
                        '{}'::jsonb,
                        '{}'::jsonb,
                        TRUE,
                        NULL
                    )
                    """
                ),
                {"decision_id": decision_id, "run_id": run_id, "node_id": node_id},
            )
            connection.execute(
                text(
                    """
                    INSERT INTO cve_candidate_artifacts (
                        candidate_id,
                        run_id,
                        source_node_id,
                        candidate_url,
                        candidate_type,
                        canonical_key,
                        download_status,
                        validation_status,
                        artifact_id,
                        evidence_json
                    )
                    VALUES (
                        :candidate_id,
                        :run_id,
                        :node_id,
                        'https://example.com/patch.diff',
                        'patch_url',
                        'example.com:abc123',
                        'succeeded',
                        'valid',
                        NULL,
                        '{}'::jsonb
                    )
                    """
                ),
                {
                    "candidate_id": candidate_id,
                    "run_id": run_id,
                    "node_id": node_id,
                },
            )
            connection.execute(
                text(
                    """
                    DELETE FROM cve_search_nodes
                    WHERE run_id = :run_id AND node_id = :node_id
                    """
                ),
                {"run_id": run_id, "node_id": node_id},
            )
            decision_node_id = connection.execute(
                text(
                    """
                    SELECT node_id
                    FROM cve_search_decisions
                    WHERE decision_id = :decision_id
                    """
                ),
                {"decision_id": decision_id},
            ).scalar_one()
            candidate_source_node_id = connection.execute(
                text(
                    """
                    SELECT source_node_id
                    FROM cve_candidate_artifacts
                    WHERE candidate_id = :candidate_id
                    """
                ),
                {"candidate_id": candidate_id},
            ).scalar_one()

            assert decision_node_id is None
            assert candidate_source_node_id is None
    finally:
        engine.dispose()
