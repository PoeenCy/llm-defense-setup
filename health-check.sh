#!/usr/bin/env bash
# health-check.sh — thin wrapper, kept for muscle memory. The real checks live
# in health_check.py (shared with the Dashboard's "System Status" panel, so
# the CLI and the web UI always agree on what "healthy" means).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
exec python3 health_check.py "$@"
