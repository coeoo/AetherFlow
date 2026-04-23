from pathlib import Path
import subprocess
import sys


ROOT_DIR = Path(__file__).resolve().parents[2]
BACKEND_DIR = ROOT_DIR / "backend"
BACKEND_GITIGNORE = ROOT_DIR / "backend/.gitignore"
DEV_COMPOSE = ROOT_DIR / "infra/docker-compose.dev.yml"
MAKEFILE = ROOT_DIR / "Makefile"


def test_worker_help_exits_zero() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "app.worker.main", "--help"],
        cwd=BACKEND_DIR,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_scheduler_help_exits_zero() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "app.scheduler.main", "--help"],
        cwd=BACKEND_DIR,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_acceptance_regression_gate_help_exits_zero() -> None:
    result = subprocess.run(
        [sys.executable, "-m", "scripts.acceptance_regression_gate", "--help"],
        cwd=BACKEND_DIR,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


def test_dev_compose_does_not_pin_container_name() -> None:
    compose_text = DEV_COMPOSE.read_text(encoding="utf-8")

    assert "container_name:" not in compose_text


def test_makefile_exposes_acceptance_gate_target() -> None:
    makefile_text = MAKEFILE.read_text(encoding="utf-8")

    assert "acceptance-gate:" in makefile_text


def test_backend_gitignore_covers_generated_artifacts() -> None:
    gitignore_text = BACKEND_GITIGNORE.read_text(encoding="utf-8")

    assert ".runtime/" in gitignore_text
    assert ".pytest_cache/" in gitignore_text
    assert "*.egg-info/" in gitignore_text
    assert "__pycache__/" in gitignore_text
    assert "*.pyc" in gitignore_text
