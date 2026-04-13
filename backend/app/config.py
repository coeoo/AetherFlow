from dataclasses import dataclass
import os
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    app_name: str = "AetherFlow API"
    database_url: str = ""
    artifact_root: str = ""
    worker_name: str = "aetherflow-worker"


def _resolve_artifact_root(value: str) -> str:
    base_dir = Path(__file__).resolve().parents[2]
    root = Path(value).expanduser()
    if not root.is_absolute():
        root = base_dir / root
    return str(root.resolve())


def load_settings() -> Settings:
    base_dir = Path(__file__).resolve().parents[2]
    default_artifact_root = base_dir / "backend" / ".runtime" / "artifacts"
    return Settings(
        app_name=os.getenv("AETHERFLOW_APP_NAME", "AetherFlow API"),
        database_url=os.getenv("AETHERFLOW_DATABASE_URL")
        or os.getenv("DATABASE_URL", ""),
        artifact_root=_resolve_artifact_root(
            os.getenv("AETHERFLOW_ARTIFACT_ROOT", str(default_artifact_root))
        ),
        worker_name=os.getenv("AETHERFLOW_WORKER_NAME", "aetherflow-worker"),
    )
