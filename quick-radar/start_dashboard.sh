#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"
if [[ -x "$HOME/ctf_env/bin/python3" ]]; then PYTHON_BIN="$HOME/ctf_env/bin/python3"; fi
"$PYTHON_BIN" -c 'import aiohttp' 2>/dev/null || { echo 'Thiếu thư viện aiohttp! Cài đặt bằng: pip install aiohttp' >&2; exit 2; }
exec "$PYTHON_BIN" "$SCRIPT_DIR/live_dashboard.py" "$@"
