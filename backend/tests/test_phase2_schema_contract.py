from pathlib import Path

from app.config import load_settings
from app.db.base import Base
from app.db.session import create_engine_from_url, create_session_factory


def test_phase2_metadata_contains_runtime_tables() -> None:
    assert "task_attempt_artifacts" in Base.metadata.tables
    assert "runtime_heartbeats" in Base.metadata.tables


def test_artifact_table_remains_content_neutral() -> None:
    artifacts = Base.metadata.tables["artifacts"]

    assert "producer_attempt_id" not in artifacts.c


def test_task_attempt_artifacts_uses_composite_primary_key() -> None:
    table = Base.metadata.tables["task_attempt_artifacts"]
    primary_key_names = {column.name for column in table.primary_key.columns}

    assert primary_key_names == {"attempt_id", "artifact_id"}


def test_runtime_heartbeats_uses_role_and_instance_as_identity() -> None:
    table = Base.metadata.tables["runtime_heartbeats"]
    primary_key_names = {column.name for column in table.primary_key.columns}

    assert primary_key_names == {"role", "instance_name"}


def test_phase2_settings_include_runtime_defaults() -> None:
    settings = load_settings()
    root_dir = Path(__file__).resolve().parents[2]

    assert settings.database_url == ""
    assert settings.artifact_root == str((root_dir / "backend/.runtime/artifacts").resolve())
    assert settings.runtime_heartbeat_interval_seconds == 10
    assert settings.runtime_heartbeat_stale_seconds == 30
    assert settings.cve_llm_fallback_enabled is False
    assert settings.cve_llm_fallback_max_candidates == 8
    assert settings.cve_llm_fallback_max_sources == 12
    assert settings.cve_llm_fallback_max_source_chars == 2400
    assert settings.llm_base_url == ""
    assert settings.llm_api_key == ""
    assert settings.llm_default_model == ""
    assert settings.llm_timeout_seconds == 20


def test_default_artifact_root_is_stable_across_cwd(monkeypatch) -> None:
    root_dir = Path(__file__).resolve().parents[2]
    backend_dir = root_dir / "backend"
    monkeypatch.delenv("AETHERFLOW_ARTIFACT_ROOT", raising=False)

    monkeypatch.chdir(root_dir)
    from_root = load_settings().artifact_root

    monkeypatch.chdir(backend_dir)
    from_backend = load_settings().artifact_root

    expected = str((root_dir / "backend/.runtime/artifacts").resolve())
    assert from_root == expected
    assert from_backend == expected


def test_engine_and_session_factory_are_cached_by_database_url() -> None:
    database_url = "postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev"

    engine_a = create_engine_from_url(database_url)
    engine_b = create_engine_from_url(database_url)
    factory_a = create_session_factory(database_url)
    factory_b = create_session_factory(database_url)

    assert engine_a is engine_b
    assert factory_a is factory_b
