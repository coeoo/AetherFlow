#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dev_common.sh"

usage() {
    cat <<'EOF'
用法: bash scripts/dev_start.sh [--without-worker]

启动本地开发会话，默认拉起：
- postgres（Docker Compose）
- api（uvicorn）
- frontend（Vite）
- worker

可选参数：
  --without-worker  跳过 worker，仅启动 postgres/api/frontend
  --help           显示帮助
EOF
}

with_worker=1

while [ "$#" -gt 0 ]; do
    case "$1" in
        --without-worker)
            with_worker=0
            ;;
        --help)
            usage
            exit 0
            ;;
        *)
            echo "未知参数：$1" >&2
            usage >&2
            exit 1
            ;;
    esac
    shift
done

require_tmux
ensure_default_runtime_dependencies

if session_exists; then
    echo "tmux 会话已存在：${AETHERFLOW_DEV_TMUX_SESSION}"
    echo "附着会话：bash scripts/dev_attach.sh"
    echo "查看状态：bash scripts/dev_status.sh"
    exit 0
fi

created_session=0

cleanup_on_error() {
    if [ "$created_session" -eq 1 ]; then
        tmux kill-session -t "$AETHERFLOW_DEV_TMUX_SESSION" >/dev/null 2>&1 || true
    fi
}

trap cleanup_on_error ERR

run_project_command "$(start_postgres_cmd)"

tmux new-session -d -s "$AETHERFLOW_DEV_TMUX_SESSION" -n "postgres"
created_session=1
tmux set-option -t "$AETHERFLOW_DEV_TMUX_SESSION" remain-on-exit on >/dev/null

send_command_to_window "postgres" "$(postgres_log_cmd)"
send_command_to_window "api" "$(api_cmd)"
send_command_to_window "frontend" "$(frontend_cmd)"

if [ "$with_worker" -eq 1 ]; then
    send_command_to_window "worker" "$(worker_cmd)"
fi

tmux select-window -t "${AETHERFLOW_DEV_TMUX_SESSION}:postgres"
trap - ERR

echo "本地开发会话已创建。"
echo "tmux 会话: ${AETHERFLOW_DEV_TMUX_SESSION}"
echo "API 地址: $(api_url)"
echo "前端地址: $(frontend_url)"
echo "附着会话: bash scripts/dev_attach.sh"
echo "查看状态: bash scripts/dev_status.sh"
echo
print_window_list
echo
if [ "$with_worker" -eq 0 ]; then
    print_service_state_lines "disabled"
    echo
    print_status_key_values "disabled"
else
    print_service_state_lines "enabled"
    echo
    print_status_key_values "enabled"
fi
