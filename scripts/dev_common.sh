#!/usr/bin/env bash
set -euo pipefail

readonly AETHERFLOW_DEV_ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly AETHERFLOW_DEV_DEFAULT_DATABASE_URL="postgresql+psycopg://postgres:postgres@127.0.0.1:55432/aetherflow_dev"

AETHERFLOW_DEV_TMUX_SESSION="${AETHERFLOW_DEV_TMUX_SESSION:-aetherflow-dev}"
AETHERFLOW_DEV_API_HOST="${AETHERFLOW_DEV_API_HOST:-127.0.0.1}"
AETHERFLOW_DEV_API_PORT="${AETHERFLOW_DEV_API_PORT:-18080}"
AETHERFLOW_DEV_FRONTEND_HOST="${AETHERFLOW_DEV_FRONTEND_HOST:-127.0.0.1}"
AETHERFLOW_DEV_FRONTEND_PORT="${AETHERFLOW_DEV_FRONTEND_PORT:-5173}"
AETHERFLOW_DEV_DATABASE_URL="${AETHERFLOW_DEV_DATABASE_URL:-$AETHERFLOW_DEV_DEFAULT_DATABASE_URL}"
AETHERFLOW_DEV_API_BASE_URL="${AETHERFLOW_DEV_API_BASE_URL:-http://${AETHERFLOW_DEV_API_HOST}:${AETHERFLOW_DEV_API_PORT}}"

require_tmux() {
    if ! command -v tmux >/dev/null 2>&1; then
        echo "缺少 tmux，无法管理本地开发会话。" >&2
        exit 1
    fi
}

session_exists() {
    tmux has-session -t "$AETHERFLOW_DEV_TMUX_SESSION" >/dev/null 2>&1
}

tmux_window_exists() {
    local window_name="$1"
    tmux list-windows -t "$AETHERFLOW_DEV_TMUX_SESSION" -F "#W" 2>/dev/null \
        | grep -Fxq "$window_name"
}

tmux_window_running() {
    local window_name="$1"
    local pane_dead=""

    if ! tmux_window_exists "$window_name"; then
        return 1
    fi

    pane_dead="$(tmux list-panes -t "${AETHERFLOW_DEV_TMUX_SESSION}:${window_name}" -F "#{pane_dead}" 2>/dev/null | head -n 1)"
    [ "$pane_dead" = "0" ]
}

start_postgres_cmd() {
    if [ -n "${AETHERFLOW_DEV_POSTGRES_START_CMD:-}" ]; then
        printf "%s" "${AETHERFLOW_DEV_POSTGRES_START_CMD}"
        return
    fi

    cat <<'EOF'
docker compose -f infra/docker-compose.dev.yml up -d postgres && \
until docker compose -f infra/docker-compose.dev.yml exec -T postgres pg_isready -U postgres >/dev/null 2>&1; do \
    sleep 1; \
done
EOF
}

postgres_log_cmd() {
    if [ -n "${AETHERFLOW_DEV_POSTGRES_LOG_CMD:-}" ]; then
        printf "%s" "${AETHERFLOW_DEV_POSTGRES_LOG_CMD}"
        return
    fi

    printf "%s" "exec docker compose -f infra/docker-compose.dev.yml logs -f postgres"
}

api_cmd() {
    if [ -n "${AETHERFLOW_DEV_API_CMD:-}" ]; then
        printf "%s" "${AETHERFLOW_DEV_API_CMD}"
        return
    fi

    printf \
        "export DATABASE_URL=%q AETHERFLOW_DATABASE_URL=%q && exec ./.venv/bin/python -m uvicorn app.main:app --app-dir backend --host %q --port %q" \
        "$AETHERFLOW_DEV_DATABASE_URL" \
        "$AETHERFLOW_DEV_DATABASE_URL" \
        "$AETHERFLOW_DEV_API_HOST" \
        "$AETHERFLOW_DEV_API_PORT"
}

frontend_cmd() {
    if [ -n "${AETHERFLOW_DEV_FRONTEND_CMD:-}" ]; then
        printf "%s" "${AETHERFLOW_DEV_FRONTEND_CMD}"
        return
    fi

    printf \
        "export VITE_DEV_PROXY_TARGET=%q && exec npm --prefix frontend run dev -- --host %q --port %q" \
        "$AETHERFLOW_DEV_API_BASE_URL" \
        "$AETHERFLOW_DEV_FRONTEND_HOST" \
        "$AETHERFLOW_DEV_FRONTEND_PORT"
}

worker_cmd() {
    if [ -n "${AETHERFLOW_DEV_WORKER_CMD:-}" ]; then
        printf "%s" "${AETHERFLOW_DEV_WORKER_CMD}"
        return
    fi

    printf \
        "cd backend && export DATABASE_URL=%q AETHERFLOW_DATABASE_URL=%q && exec ../.venv/bin/python -m app.worker.main" \
        "$AETHERFLOW_DEV_DATABASE_URL" \
        "$AETHERFLOW_DEV_DATABASE_URL"
}

stop_postgres_cmd() {
    if [ -n "${AETHERFLOW_DEV_POSTGRES_STOP_CMD:-}" ]; then
        printf "%s" "${AETHERFLOW_DEV_POSTGRES_STOP_CMD}"
        return
    fi

    printf "%s" "docker compose -f infra/docker-compose.dev.yml stop postgres"
}

run_project_command() {
    local command="$1"
    (
        cd "$AETHERFLOW_DEV_ROOT_DIR"
        bash -lc "$command"
    )
}

ensure_default_runtime_dependencies() {
    if [ -z "${AETHERFLOW_DEV_POSTGRES_START_CMD:-}" ] || [ -z "${AETHERFLOW_DEV_POSTGRES_LOG_CMD:-}" ]; then
        if ! command -v docker >/dev/null 2>&1; then
            echo "缺少 docker，无法启动默认 postgres 服务。" >&2
            exit 1
        fi
    fi

    if [ -z "${AETHERFLOW_DEV_API_CMD:-}" ] && [ ! -x "${AETHERFLOW_DEV_ROOT_DIR}/.venv/bin/python" ]; then
        echo "缺少 .venv/bin/python，请先执行 make backend-install。" >&2
        exit 1
    fi

    if [ -z "${AETHERFLOW_DEV_FRONTEND_CMD:-}" ] && [ ! -d "${AETHERFLOW_DEV_ROOT_DIR}/frontend/node_modules" ]; then
        echo "缺少 frontend/node_modules，请先执行 make frontend-install。" >&2
        exit 1
    fi
}

send_command_to_window() {
    local window_name="$1"
    local raw_command="$2"
    local full_command=""

    # 统一先切回仓库根目录，再 exec 具体进程，确保 pane 退出状态可见。
    printf -v full_command "cd %q && exec bash -lc %q" "$AETHERFLOW_DEV_ROOT_DIR" "$raw_command"

    if tmux_window_exists "$window_name"; then
        tmux send-keys -t "${AETHERFLOW_DEV_TMUX_SESSION}:${window_name}" C-c
    else
        tmux new-window -d -t "$AETHERFLOW_DEV_TMUX_SESSION" -n "$window_name"
    fi

    tmux send-keys -t "${AETHERFLOW_DEV_TMUX_SESSION}:${window_name}" -l "$full_command"
    tmux send-keys -t "${AETHERFLOW_DEV_TMUX_SESSION}:${window_name}" Enter
}

service_state() {
    local window_name="$1"

    if ! session_exists; then
        printf "%s" "stopped"
        return
    fi

    if ! tmux_window_exists "$window_name"; then
        printf "%s" "disabled"
        return
    fi

    if tmux_window_running "$window_name"; then
        printf "%s" "running"
        return
    fi

    printf "%s" "stopped"
}

api_url() {
    printf "http://%s:%s" "$AETHERFLOW_DEV_API_HOST" "$AETHERFLOW_DEV_API_PORT"
}

frontend_url() {
    printf "http://%s:%s" "$AETHERFLOW_DEV_FRONTEND_HOST" "$AETHERFLOW_DEV_FRONTEND_PORT"
}

print_service_state_lines() {
    local worker_mode="${1:-auto}"

    echo "当前 tmux 窗口状态："
    echo "  - postgres: $(service_state postgres)"
    echo "  - api: $(service_state api)"
    echo "  - frontend: $(service_state frontend)"

    if [ "$worker_mode" = "enabled" ]; then
        echo "  - worker: $(service_state worker)"
        return
    fi

    if [ "$worker_mode" = "disabled" ]; then
        echo "  - worker: disabled"
        return
    fi

    echo "  - worker: $(service_state worker)"
}

list_tmux_windows() {
    if ! session_exists; then
        return
    fi

    tmux list-windows -t "$AETHERFLOW_DEV_TMUX_SESSION" -F "#W" 2>/dev/null
}

print_window_list() {
    if ! session_exists; then
        echo "窗口列表:"
        echo "  - 无"
        return
    fi

    echo "窗口列表:"
    while IFS= read -r window_name; do
        [ -n "$window_name" ] || continue
        echo "  - $window_name"
    done < <(list_tmux_windows)
}

print_address_summary() {
    echo "地址汇总:"
    echo "  - API: $(api_url)"
    echo "  - Frontend: $(frontend_url)"
}

print_status_key_values() {
    local worker_mode="${1:-auto}"

    if session_exists; then
        echo "tmux_session=running"
    else
        echo "tmux_session=stopped"
    fi

    echo "postgres=$(service_state postgres)"
    echo "api=$(service_state api)"
    echo "frontend=$(service_state frontend)"

    if [ "$worker_mode" = "disabled" ]; then
        echo "worker=disabled"
        return
    fi

    echo "worker=$(service_state worker)"
}
