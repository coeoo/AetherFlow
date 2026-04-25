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


def test_phase2_settings_include_runtime_defaults(monkeypatch) -> None:
    root_dir = Path(__file__).resolve().parents[2]
    env_local_path = root_dir / ".env.local"
    original_content = env_local_path.read_text(encoding="utf-8") if env_local_path.exists() else None

    if env_local_path.exists():
        env_local_path.unlink()
    for key in (
        "LLM_BASE_URL",
        "LLM_API_KEY",
        "LLM_DEFAULT_MODEL",
        "LLM_REASONING_EFFORT",
    ):
        monkeypatch.delenv(key, raising=False)
    settings = load_settings()

    try:
        assert settings.database_url == ""
        assert settings.artifact_root == str((root_dir / "backend/.runtime/artifacts").resolve())
        assert settings.runtime_heartbeat_interval_seconds == 10
        assert settings.runtime_heartbeat_stale_seconds == 30
        assert settings.cve_browser_backend == "playwright"
        assert settings.cve_browser_pool_size == 3
        assert settings.cve_browser_headless is True
        assert settings.cve_browser_timeout_ms == 30_000
        assert settings.cve_browser_cdp_endpoint == ""
        assert settings.llm_base_url == ""
        assert settings.llm_api_key == ""
        assert settings.llm_default_model == ""
        assert settings.llm_reasoning_effort == ""
        assert settings.llm_timeout_seconds == 20
    finally:
        if original_content is not None:
            env_local_path.write_text(original_content, encoding="utf-8")


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


def test_load_settings_reads_root_env_local_without_overriding_existing_env(monkeypatch) -> None:
    root_dir = Path(__file__).resolve().parents[2]
    env_local_path = root_dir / ".env.local"
    original_content = env_local_path.read_text(encoding="utf-8") if env_local_path.exists() else None

    for key in (
        "LLM_BASE_URL",
        "LLM_API_KEY",
        "LLM_DEFAULT_MODEL",
        "LLM_REASONING_EFFORT",
    ):
        monkeypatch.delenv(key, raising=False)

    env_local_path.write_text(
        "\n".join(
            [
                "LLM_BASE_URL=https://example.com/compatible-mode/v1",
                "LLM_API_KEY=env-local-key",
                "LLM_DEFAULT_MODEL=qwen-test-model",
                "LLM_REASONING_EFFORT=high",
                "",
            ]
        ),
        encoding="utf-8",
    )
    try:
        settings = load_settings()

        assert settings.llm_base_url == "https://example.com/compatible-mode/v1"
        assert settings.llm_api_key == "env-local-key"
        assert settings.llm_default_model == "qwen-test-model"
        assert settings.llm_reasoning_effort == "high"

        monkeypatch.setenv("LLM_API_KEY", "runtime-env-key")
        settings_with_runtime_override = load_settings()
        assert settings_with_runtime_override.llm_api_key == "runtime-env-key"
    finally:
        if original_content is None:
            env_local_path.unlink(missing_ok=True)
        else:
            env_local_path.write_text(original_content, encoding="utf-8")


def test_engine_and_session_factory_are_cached_by_database_url() -> None:
    database_url = "postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev"

    engine_a = create_engine_from_url(database_url)
    engine_b = create_engine_from_url(database_url)
    factory_a = create_session_factory(database_url)
    factory_b = create_session_factory(database_url)

    assert engine_a is engine_b
    assert factory_a is factory_b
