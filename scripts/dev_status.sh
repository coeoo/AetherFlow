#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dev_common.sh"

usage() {
    cat <<'EOF'
用法: bash scripts/dev_status.sh

输出本地开发会话状态。
EOF
}

if [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

if [ "$#" -gt 0 ]; then
    echo "未知参数：$1" >&2
    usage >&2
    exit 1
fi

require_tmux

if session_exists; then
    echo "tmux_session=running"
else
    echo "tmux_session=stopped"
fi

echo "postgres=$(service_state postgres)"
echo "api=$(service_state api)"
echo "frontend=$(service_state frontend)"
echo "worker=$(service_state worker)"
