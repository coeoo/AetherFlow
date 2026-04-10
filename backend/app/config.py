from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Settings:
    app_name: str = "AetherFlow API"


def load_settings() -> Settings:
    return Settings(
        app_name=os.getenv("AETHERFLOW_APP_NAME", "AetherFlow API"),
    )
