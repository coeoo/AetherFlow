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
        assert "本地开发会话已创建" in start_result.stdout
        assert f"tmux 会话: {session_name}" in start_result.stdout
        assert "API 地址: http://0.0.0.0:18080" in start_result.stdout
        assert "前端地址: http://0.0.0.0:0.0.0.0:18080" not in start_result.stdout
        assert "前端地址: http://0.0.0.0:5180" in start_result.stdout
        assert "附着会话: bash scripts/dev_attach.sh" in start_result.stdout
        assert "查看状态: bash scripts/dev_status.sh" in start_result.stdout
        assert "tmux_session=" in start_result.stdout

        status_result = run_script("dev_status.sh", env=env)
        assert status_result.returncode == 0, status_result.stderr
        assert "本地开发会话状态" in status_result.stdout
        assert f"tmux 会话: running ({session_name})" in status_result.stdout
        assert "窗口列表:" in status_result.stdout
        assert "  - postgres" in status_result.stdout
        assert "  - api" in status_result.stdout
        assert "  - frontend" in status_result.stdout
        assert "地址汇总:" in status_result.stdout
        assert "tmux_session=running" in status_result.stdout
        assert "postgres=running" in status_result.stdout
        assert "api=running" in status_result.stdout
        assert "frontend=running" in status_result.stdout
        assert "worker=disabled" in status_result.stdout
    finally:
        kill_tmux_session(session_name)


def test_dev_common_defaults_bind_public_host_and_frontend_port_5180() -> None:
    result = subprocess.run(
        [
            "bash",
            "-lc",
            (
                "source scripts/dev_common.sh && "
                "printf '%s\\n%s\\n%s\\n%s\\n' "
                "\"$(api_url)\" "
                "\"$(frontend_url)\" "
                "\"$(api_cmd)\" "
                "\"$(frontend_cmd)\""
            ),
        ],
        cwd=ROOT_DIR,
        capture_output=True,
        text=True,
        env=os.environ.copy(),
        check=True,
    )

    output_lines = result.stdout.splitlines()
    assert output_lines[0] == "http://0.0.0.0:18080"
    assert output_lines[1] == "http://0.0.0.0:5180"
    assert "--host 0.0.0.0 --port 18080" in output_lines[2]
    assert "--host 0.0.0.0 --port 5180" in output_lines[3]


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
        assert "worker=running" in start_result.stdout

        stop_result = run_script("dev_stop.sh", env=env)
        assert stop_result.returncode == 0, stop_result.stderr
        assert not tmux_session_exists(session_name)
    finally:
        kill_tmux_session(session_name)


def test_dev_attach_rejects_unknown_window_with_available_window_list() -> None:
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

        attach_result = run_script("dev_attach.sh", "missing-window", env=env)
        assert attach_result.returncode == 1
        assert "tmux 窗口不存在：missing-window" in attach_result.stderr
        assert "可用窗口：" in attach_result.stderr
        assert "  - postgres" in attach_result.stderr
        assert "  - api" in attach_result.stderr
        assert "  - frontend" in attach_result.stderr
    finally:
        kill_tmux_session(session_name)


def test_frontend_cmd_prefers_dev_proxy_target_over_absolute_api_base_url() -> None:
    result = subprocess.run(
        [
            "bash",
            "-lc",
            "source scripts/dev_common.sh && frontend_cmd",
        ],
        cwd=ROOT_DIR,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "AETHERFLOW_DEV_API_BASE_URL": "http://127.0.0.1:18080",
            "AETHERFLOW_DEV_FRONTEND_HOST": "127.0.0.1",
            "AETHERFLOW_DEV_FRONTEND_PORT": "5173",
        },
        check=True,
    )

    assert "VITE_DEV_PROXY_TARGET" in result.stdout
    assert "VITE_API_BASE_URL" not in result.stdout
