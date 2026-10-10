#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_PATH="${GD1_CONFIG:-$SCRIPT_DIR/config.env}"
exec python3 "$SCRIPT_DIR/configure_target.py" --config "$CONFIG_PATH" "$@"
