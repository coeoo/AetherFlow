#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$ROOT_DIR"

if command -v uv >/dev/null 2>&1; then
    uv venv --clear --seed --python 3.11 .venv
    uv pip install \
        --python "$ROOT_DIR/.venv/bin/python" \
        --no-build-isolation \
        -e "./backend[dev]"
    exit 0
fi

python3 -m venv .venv
"$ROOT_DIR/.venv/bin/python" -m pip --disable-pip-version-check install wheel
"$ROOT_DIR/.venv/bin/python" -m pip --disable-pip-version-check install \
    --no-build-isolation \
    -e "./backend[dev]"
