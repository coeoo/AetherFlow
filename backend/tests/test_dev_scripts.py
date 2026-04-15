from __future__ import annotations

import os
from pathlib import Path
import subprocess
import uuid


ROOT_DIR = Path(__file__).resolve().parents[2]
SCRIPTS_DIR = ROOT_DIR / "scripts"


def run_script(script_name: str, *args: str, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    merged_env = os.environ.copy()
    if env:
        merged_env.update(env)
    return subprocess.run(
        ["bash", str(SCRIPTS_DIR / script_name), *args],
        cwd=ROOT_DIR,
        capture_output=True,
        text=True,
        env=merged_env,
    )


def tmux_session_exists(session_name: str) -> bool:
    result = subprocess.run(
        ["tmux", "has-session", "-t", session_name],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def tmux_window_names(session_name: str) -> set[str]:
    result = subprocess.run(
        ["tmux", "list-windows", "-t", session_name, "-F", "#W"],
        capture_output=True,
        text=True,
        check=True,
    )
    return {line.strip() for line in result.stdout.splitlines() if line.strip()}


def kill_tmux_session(session_name: str) -> None:
    subprocess.run(
        ["tmux", "kill-session", "-t", session_name],
        capture_output=True,
        text=True,
    )


def test_dev_scripts_help_exit_zero() -> None:
    for script_name in (
        "dev_start.sh",
        "dev_stop.sh",
        "dev_status.sh",
        "dev_attach.sh",
    ):
        result = run_script(script_name, "--help")
        assert result.returncode == 0, result.stderr


def test_dev_start_and_status_manage_tmux_session() -> None:
    session_name = f"aetherflow-test-{uuid.uuid4().hex[:8]}"
    env = {
        "AETHERFLOW_DEV_TMUX_SESSION": session_name,
        "AETHERFLOW_DEV_POSTGRES_START_CMD": "true",
        "AETHERFLOW_DEV_POSTGRES_LOG_CMD": "printf postgres-ready && exec sleep 300",
        "AETHERFLOW_DEV_API_CMD": "printf api-ready && exec sleep 300",
        "AETHERFLOW_DEV_FRONTEND_CMD": "printf frontend-ready && exec sleep 300",
    }

    try:
        start_result = run_script("dev_start.sh", env=env)
        assert start_result.returncode == 0, start_result.stderr
        assert tmux_session_exists(session_name)
        assert tmux_window_names(session_name) == {"postgres", "api", "frontend"}

        status_result = run_script("dev_status.sh", env=env)
        assert status_result.returncode == 0, status_result.stderr
        assert "tmux_session=running" in status_result.stdout
        assert "postgres=running" in status_result.stdout
        assert "api=running" in status_result.stdout
        assert "frontend=running" in status_result.stdout
        assert "worker=disabled" in status_result.stdout
    finally:
        kill_tmux_session(session_name)


def test_dev_start_with_worker_and_stop_cleans_tmux_session() -> None:
    session_name = f"aetherflow-test-{uuid.uuid4().hex[:8]}"
    env = {
        "AETHERFLOW_DEV_TMUX_SESSION": session_name,
        "AETHERFLOW_DEV_POSTGRES_START_CMD": "true",
        "AETHERFLOW_DEV_POSTGRES_LOG_CMD": "printf postgres-ready && exec sleep 300",
        "AETHERFLOW_DEV_API_CMD": "printf api-ready && exec sleep 300",
        "AETHERFLOW_DEV_FRONTEND_CMD": "printf frontend-ready && exec sleep 300",
        "AETHERFLOW_DEV_WORKER_CMD": "printf worker-ready && exec sleep 300",
    }

    try:
        start_result = run_script("dev_start.sh", "--with-worker", env=env)
        assert start_result.returncode == 0, start_result.stderr
        assert "worker" in tmux_window_names(session_name)

        stop_result = run_script("dev_stop.sh", env=env)
        assert stop_result.returncode == 0, stop_result.stderr
        assert not tmux_session_exists(session_name)
    finally:
        kill_tmux_session(session_name)
