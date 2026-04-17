#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/dev_common.sh"

usage() {
    cat <<'EOF'
用法: bash scripts/dev_attach.sh [window_name]

附着到本地开发 tmux 会话。

可选参数：
  window_name     直接切换到指定窗口
EOF
}

if [ "${1:-}" = "--help" ]; then
    usage
    exit 0
fi

if [ "$#" -gt 1 ]; then
    echo "未知参数：$1" >&2
    usage >&2
    exit 1
fi

require_tmux

if ! session_exists; then
    echo "tmux 会话不存在：${AETHERFLOW_DEV_TMUX_SESSION}" >&2
    exit 1
fi

target_window="${1:-}"

if [ -n "$target_window" ]; then
    if ! tmux_window_exists "$target_window"; then
        echo "tmux 窗口不存在：${target_window}" >&2
        echo "可用窗口：" >&2
        while IFS= read -r window_name; do
            [ -n "$window_name" ] || continue
            echo "  - ${window_name}" >&2
        done < <(list_tmux_windows)
        exit 1
    fi

    exec tmux attach-session -t "$AETHERFLOW_DEV_TMUX_SESSION" \; select-window -t "${AETHERFLOW_DEV_TMUX_SESSION}:${target_window}"
fi

exec tmux attach -t "$AETHERFLOW_DEV_TMUX_SESSION"
