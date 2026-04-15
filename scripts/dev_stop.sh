#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dev_common.sh"

usage() {
    cat <<'EOF'
用法: bash scripts/dev_stop.sh [--with-postgres]

停止本地开发 tmux 会话。

可选参数：
  --with-postgres  额外停止 postgres 容器
  --help           显示帮助
EOF
}

with_postgres=0

while [ "$#" -gt 0 ]; do
    case "$1" in
        --with-postgres)
            with_postgres=1
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

if session_exists; then
    tmux kill-session -t "$AETHERFLOW_DEV_TMUX_SESSION"
fi

if [ "$with_postgres" -eq 1 ]; then
    run_project_command "$(stop_postgres_cmd)"
fi

echo "tmux_session=stopped"
if [ "$with_postgres" -eq 1 ]; then
    echo "postgres=stopped"
fi
