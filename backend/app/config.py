from dataclasses import dataclass
from pathlib import Path
import os


def _project_root() -> Path:
    return Path(__file__).resolve().parents[2]


DEFAULT_ARTIFACT_ROOT = str((_project_root() / "backend/.runtime/artifacts").resolve())


def _resolve_artifact_root(raw_path: str) -> str:
    candidate = Path(raw_path).expanduser()
    if candidate.is_absolute():
        return str(candidate.resolve())

    return str((_project_root() / candidate).resolve())


@dataclass(frozen=True)
class Settings:
    app_name: str = "AetherFlow API"
    database_url: str = ""
    artifact_root: str = DEFAULT_ARTIFACT_ROOT
    runtime_heartbeat_interval_seconds: int = 10
    runtime_heartbeat_stale_seconds: int = 30

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "artifact_root",
            _resolve_artifact_root(self.artifact_root),
        )


def _load_int_setting(name: str, default: int) -> int:
    raw_value = os.getenv(name)
    if raw_value is None:
        return default

    return int(raw_value)


def load_settings() -> Settings:
    return Settings(
        app_name=os.getenv("AETHERFLOW_APP_NAME", "AetherFlow API"),
        database_url=os.getenv("AETHERFLOW_DATABASE_URL", os.getenv("DATABASE_URL", "")),
        artifact_root=os.getenv("AETHERFLOW_ARTIFACT_ROOT", DEFAULT_ARTIFACT_ROOT),
        runtime_heartbeat_interval_seconds=_load_int_setting(
            "AETHERFLOW_RUNTIME_HEARTBEAT_INTERVAL_SECONDS",
            10,
        ),
        runtime_heartbeat_stale_seconds=_load_int_setting(
            "AETHERFLOW_RUNTIME_HEARTBEAT_STALE_SECONDS",
            30,
        ),
    )
