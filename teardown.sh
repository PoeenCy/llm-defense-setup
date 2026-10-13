#!/usr/bin/env bash
# teardown.sh — Graceful shutdown of the entire CTF monitor hub
#
# Always tears down BOTH docker-compose.contest.yml and docker-compose.prep.yml
# regardless of which MODE brought the stack up — `docker compose down` on a
# file whose services were never started is a safe no-op, and this guarantees
# teardown never leaves a stray prep-only (AI) container running.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TULIP_DIR="$SCRIPT_DIR/offline-bundle/repos/tulip"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log() { echo -e "${CYAN}[TEARDOWN]${NC} $*"; }
ok()  { echo -e "${GREEN}[OK]${NC}       $*"; }

log "Stopping CTF Monitor Hub..."

# Stop hub services (both zones — see header comment)
cd "$SCRIPT_DIR"
docker compose -f docker-compose.contest.yml -f docker-compose.prep.yml down 2>&1 | tail -3 || true
ok "Hub services stopped (contest + prep)"

# Stop Tulip — must pass the same -f overlay bringup.sh used to start it, or
# docker-compose-suricata.yml's suricata service (and anything else only
# defined in the overlay) is left orphaned and running (verified: an earlier
# version of this script left tulip-suricata-1 running after teardown).
if [[ -d "$TULIP_DIR" ]]; then
    cd "$TULIP_DIR"
    TULIP_COMPOSE="-f docker-compose.yml"
    [[ -f docker-compose-suricata.yml ]] && TULIP_COMPOSE="-f docker-compose.yml -f docker-compose-suricata.yml"
    docker compose $TULIP_COMPOSE down 2>&1 | tail -3 || true
    cd "$SCRIPT_DIR"
    ok "Tulip stopped"
fi

echo ""
echo -e "${GREEN}CTF Monitor Hub stopped. All traffic/alert data preserved.${NC}"
echo "To start again: bash bringup.sh"
