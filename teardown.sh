#!/usr/bin/env bash
# teardown.sh — Graceful shutdown of the entire CTF monitor hub
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TULIP_DIR="$SCRIPT_DIR/offline-bundle/repos/tulip"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log() { echo -e "${CYAN}[TEARDOWN]${NC} $*"; }
ok()  { echo -e "${GREEN}[OK]${NC}       $*"; }

log "Stopping CTF Monitor Hub..."

# Stop hub services
cd "$SCRIPT_DIR"
docker compose down 2>&1 | tail -3 || true
ok "Hub services stopped"

# Stop Tulip
if [[ -d "$TULIP_DIR" ]]; then
    cd "$TULIP_DIR"
    docker compose down 2>&1 | tail -3 || true
    cd "$SCRIPT_DIR"
    ok "Tulip stopped"
fi

# Stop Ollama (optional — comment out if you want to keep it)
# pkill -f "ollama serve" 2>/dev/null || true
# ok "Ollama stopped"

echo ""
echo -e "${GREEN}CTF Monitor Hub stopped. All traffic/alert data preserved.${NC}"
echo "To start again: bash bringup.sh"
