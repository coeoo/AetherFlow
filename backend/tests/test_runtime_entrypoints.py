from pathlib import Path
import subprocess
import sys


ROOT_DIR = Path(__file__).resolve().parents[2]
BACKEND_GITIGNORE = ROOT_DIR / "backend/.gitignore"
DEV_COMPOSE = ROOT_DIR / "infra/docker-compose.dev.yml"


def test_worker_help_exits_zero() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "app.worker.main", "--help"],
        cwd="backend",
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_scheduler_help_exits_zero() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "app.scheduler.main", "--help"],
        cwd="backend",
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_dev_compose_does_not_pin_container_name() -> None:
    compose_text = DEV_COMPOSE.read_text(encoding="utf-8")

    assert "container_name:" not in compose_text


def test_backend_gitignore_covers_generated_artifacts() -> None:
    gitignore_text = BACKEND_GITIGNORE.read_text(encoding="utf-8")

    assert ".pytest_cache/" in gitignore_text
    assert "*.egg-info/" in gitignore_text
    assert "__pycache__/" in gitignore_text
    assert "*.pyc" in gitignore_text
