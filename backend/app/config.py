from dataclasses import dataclass
import os
from pathlib import Path


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


DEFAULT_ARTIFACT_ROOT = str((_project_root() / "backend/.runtime/artifacts").resolve())


def _resolve_artifact_root(raw_path: str) -> str:
    candidate = Path(raw_path).expanduser()
    if candidate.is_absolute():
        return str(candidate.resolve())
    return str((_project_root() / candidate).resolve())


def _load_int_setting(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    return int(raw_value)


def _load_bool_setting(name: str, default: bool) -> bool:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default
    normalized = raw_value.strip().lower()
    return normalized in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    app_name: str = "AetherFlow API"
    database_url: str = ""
    artifact_root: str = DEFAULT_ARTIFACT_ROOT
    worker_name: str = "aetherflow-worker"
    runtime_heartbeat_interval_seconds: int = 10
    runtime_heartbeat_stale_seconds: int = 30
    cve_llm_fallback_enabled: bool = False
    cve_llm_fallback_max_candidates: int = 8
    cve_llm_fallback_max_sources: int = 12
    cve_llm_fallback_max_source_chars: int = 2400
    llm_base_url: str = ""
    llm_api_key: str = ""
    llm_default_model: str = ""
    llm_timeout_seconds: int = 20

    def __post_init__(self) -> None:
        object.__setattr__(self, "artifact_root", _resolve_artifact_root(self.artifact_root))


def load_settings() -> Settings:
    return Settings(
        app_name=os.getenv("AETHERFLOW_APP_NAME", "AetherFlow API"),
        database_url=os.getenv("AETHERFLOW_DATABASE_URL", os.getenv("DATABASE_URL", "")),
        artifact_root=os.getenv("AETHERFLOW_ARTIFACT_ROOT", DEFAULT_ARTIFACT_ROOT),
        worker_name=os.getenv("AETHERFLOW_WORKER_NAME", "aetherflow-worker"),
        runtime_heartbeat_interval_seconds=_load_int_setting(
            "AETHERFLOW_RUNTIME_HEARTBEAT_INTERVAL_SECONDS",
            10,
        ),
        runtime_heartbeat_stale_seconds=_load_int_setting(
            "AETHERFLOW_RUNTIME_HEARTBEAT_STALE_SECONDS",
            30,
        ),
        cve_llm_fallback_enabled=_load_bool_setting(
            "AETHERFLOW_CVE_LLM_FALLBACK_ENABLED",
            False,
        ),
        cve_llm_fallback_max_candidates=_load_int_setting(
            "AETHERFLOW_CVE_LLM_FALLBACK_MAX_CANDIDATES",
            8,
        ),
        cve_llm_fallback_max_sources=_load_int_setting(
            "AETHERFLOW_CVE_LLM_FALLBACK_MAX_SOURCES",
            12,
        ),
        cve_llm_fallback_max_source_chars=_load_int_setting(
            "AETHERFLOW_CVE_LLM_FALLBACK_MAX_SOURCE_CHARS",
            2400,
        ),
        llm_base_url=os.getenv("LLM_BASE_URL", "").strip(),
        llm_api_key=os.getenv("LLM_API_KEY", "").strip(),
        llm_default_model=os.getenv("LLM_DEFAULT_MODEL", "").strip(),
        llm_timeout_seconds=_load_int_setting("LLM_TIMEOUT_SECONDS", 20),
    )
