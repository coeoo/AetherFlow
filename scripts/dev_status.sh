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

echo "本地开发会话状态"
if session_exists; then
    echo "tmux 会话: running (${AETHERFLOW_DEV_TMUX_SESSION})"
else
    echo "tmux 会话: stopped (${AETHERFLOW_DEV_TMUX_SESSION})"
fi

echo
print_service_state_lines
echo
print_window_list
echo
print_address_summary
echo "  - 附着会话: bash scripts/dev_attach.sh"
echo
print_status_key_values
