#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"
GD1_CONFIG="${GD1_CONFIG:-$SCRIPT_DIR/config.env}"
gd1_load_config
gd1_ssh_args
exec "${GD1_SSH[@]}" "$@"
