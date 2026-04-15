#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dev_common.sh"

usage() {
    cat <<'EOF'
用法: bash scripts/dev_attach.sh

附着到本地开发 tmux 会话。
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

if ! session_exists; then
    echo "tmux 会话不存在：${AETHERFLOW_DEV_TMUX_SESSION}" >&2
    exit 1
fi

exec tmux attach -t "$AETHERFLOW_DEV_TMUX_SESSION"
