#!/usr/bin/env bash
# Session-owned capture, closed-file publication and graceful final-file drain.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec python3 "$SCRIPT_DIR/capture_pull.py" "$@"
