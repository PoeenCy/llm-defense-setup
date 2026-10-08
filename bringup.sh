#!/usr/bin/env bash
# bringup.sh — CTF Monitor Hub: One-Command Bring-Up
# Usage: bash bringup.sh [--offline]
#
# Steps:
#   1. Validate services.json
#   2. If --offline: restore from offline-bundle/ (no network)
#   3. Generate Tulip .env from services.json
#   4. Export all env vars for docker-compose
#   5. Build/pull images if needed
#   6. Start all services in correct dependency order
#   7. Health-check and report status
#
# Safety: read-only MongoDB. No auto-blocking. No auto-deploy.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="$SCRIPT_DIR/services.json"
TULIP_DIR="$SCRIPT_DIR/offline-bundle/repos/tulip"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

log()    { echo -e "${CYAN}[BRINGUP]${NC} $*"; }
ok()     { echo -e "${GREEN}[OK]${NC}      $*"; }
warn()   { echo -e "${YELLOW}[WARN]${NC}    $*"; }
die()    { echo -e "${RED}[FATAL]${NC}   $*"; exit 1; }
header() { echo -e "\n${BOLD}${CYAN}══ $* ══${NC}"; }

OFFLINE=false
for arg in "$@"; do [[ "$arg" == "--offline" ]] && OFFLINE=true; done

echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║     CTF Monitor Hub — Bring-Up                      ║${NC}"
echo -e "${BOLD}${CYAN}║     Attack-Defense CTF Situational Awareness Stack   ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
[[ "$OFFLINE" == true ]] && warn "OFFLINE MODE — no network calls will be made"

# ═══════════════════════════════════════════════════════════════
# 0. Validate config
# ═══════════════════════════════════════════════════════════════
header "Step 0: Validate services.json"

[[ -f "$CONFIG" ]] || die "services.json not found at $SCRIPT_DIR"
bash "$SCRIPT_DIR/validate-config.sh" "$CONFIG" || die "services.json validation failed — fix errors above"
ok "services.json valid"

# Parse all config values
TEAM_ID=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['team_id'])")
VULNBOX_IP=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['vulnbox']['ip'])")
VULNBOX_BROKER_PORT=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['vulnbox']['pcap_broker_port'])")
MONITOR_IP=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['monitor_host']['ip'])")
DASHBOARD_PORT=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['monitor_host']['dashboard_port'])")
ALERT_QUEUE_PORT=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['monitor_host']['alert_queue_port'])")
IOC_API_PORT=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['monitor_host']['ioc_api_port'])")
FLAG_REGEX=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['flag']['regex'])")
HONEYTOKEN_FLAG=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['honeytoken']['flag'])")
HONEYTOKEN_PORT=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['honeytoken']['endpoint_port'])")
TEAMS_CIDR=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['teams_cidr'])")
TULIP_WEB_PORT=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['tulip']['web_port'])")
OLLAMA_PORT=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['ollama']['port'])")
LLM_MODEL=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['ollama']['llm_model'])")
EMBED_MODEL=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['ollama']['embed_model'])")
GPU_LAYERS=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['ollama']['gpu_layers'])")
ANYTHINGLLM_PORT=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['anythingllm']['port'])")
MCP_PG_ROLE=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['mcp']['postgres_role'])")
MCP_PG_DB=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['mcp']['postgres_db'])")
MCP_PG_PORT=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['mcp']['postgres_host_port'])")

# ═══════════════════════════════════════════════════════════════
# 1. Offline restore (if requested)
# ═══════════════════════════════════════════════════════════════
if [[ "$OFFLINE" == true ]]; then
    header "Step 1: Offline Restore"
    [[ -d "$SCRIPT_DIR/offline-bundle" ]] || die "offline-bundle/ not found — run pull-and-save.sh first"
    bash "$SCRIPT_DIR/offline-restore.sh"
    ok "Offline restore complete"
fi

# ═══════════════════════════════════════════════════════════════
# 2. Create required directories
# ═══════════════════════════════════════════════════════════════
header "Step 2: Prepare directories"

mkdir -p \
    "$SCRIPT_DIR/traffic" \
    "$SCRIPT_DIR/vault" \
    "$SCRIPT_DIR/suricata/log" \
    "$SCRIPT_DIR/suricata/etc" \
    "$SCRIPT_DIR/suricata/lib"

ok "Directories ready"

# ═══════════════════════════════════════════════════════════════
# 3. Generate Tulip .env
# ═══════════════════════════════════════════════════════════════
header "Step 3: Generate Tulip config"

if [[ -d "$TULIP_DIR" ]]; then
    CONFIG="$CONFIG" TULIP_DIR="$TULIP_DIR" python3 "$SCRIPT_DIR/generators/gen-tulip-env.py"
    ok "Tulip .env generated"
else
    warn "Tulip repo not found at $TULIP_DIR — skipping Tulip config"
    warn "Run: bash pull-and-save.sh to clone Tulip"
fi

CTF_PROXY_DIR="$SCRIPT_DIR/offline-bundle/repos/ctf_proxy"
if [[ -d "$CTF_PROXY_DIR" ]]; then
    CONFIG="$CONFIG" CTF_PROXY_DIR="$CTF_PROXY_DIR" python3 "$SCRIPT_DIR/generators/gen-ctfproxy.py"
    ok "ctf_proxy config generated"
else
    warn "ctf_proxy not found at $CTF_PROXY_DIR — skipping"
fi

# ═══════════════════════════════════════════════════════════════
# 4. Export environment for docker-compose
# ═══════════════════════════════════════════════════════════════
header "Step 4: Export environment"

export TEAM_ID VULNBOX_IP MONITOR_IP TEAMS_CIDR
export FLAG_REGEX HONEYTOKEN_FLAG HONEYTOKEN_PORT HONEYTOKEN_PORT
export DASHBOARD_PORT ALERT_QUEUE_PORT IOC_API_PORT
export TULIP_WEB_PORT
export OLLAMA_PORT LLM_MODEL EMBED_MODEL GPU_LAYERS
export ANYTHINGLLM_PORT

# On some hosts "docker" is actually backed by podman (check: docker info's
# Server Version matches podman's numbering, not a docker-ce release). In that
# case custom bridge networks don't NAT "host.docker.internal" back to the
# host correctly, so services relying on it (ioc-brain, dashboard, anythingllm)
# can't reach Ollama/Tulip/Mongo on the host. Detect this and fall back to the
# classic docker0 bridge gateway, which does route correctly even under podman.
# The actual gateway probe needs ctf-net to exist, so it happens in Step 6
# below (right after `docker compose up -d` creates that network) — this
# placeholder lets steps between here and there reference the var safely.
PODMAN_BACKED=false
if docker info 2>/dev/null | grep -qi "^ *Server Version: *5\."; then
    PODMAN_BACKED=true
fi

log "Environment exported (${#TEAM_ID} values set)"

# ═══════════════════════════════════════════════════════════════
# 5. Start Tulip stack
# ═══════════════════════════════════════════════════════════════
header "Step 5: Start Tulip stack"

if [[ -d "$TULIP_DIR" ]]; then
    log "Building Tulip images (first run may take 5-10 min)..."
    cd "$TULIP_DIR"
    docker compose build --quiet 2>&1 | tail -3 || warn "Tulip build had warnings"
    log "Starting Tulip..."
    docker compose up -d 2>&1 | tail -5
    cd "$SCRIPT_DIR"
    ok "Tulip started"
else
    warn "Tulip repo missing — skipping Tulip"
fi

# ═══════════════════════════════════════════════════════════════
# 6. Start monitor hub services
# ═══════════════════════════════════════════════════════════════
header "Step 6: Start monitor hub services"

cd "$SCRIPT_DIR"
log "Building hub images..."
docker compose build --quiet 2>&1 | tail -3 || warn "Build had warnings"

log "Starting core services (redis, detection, watchdog, dashboard)..."
docker compose up -d mock-vulnbox redis
sleep 3  # wait for redis; this also creates the ctf-net network

if [[ "$PODMAN_BACKED" == true && -z "${DOCKER_HOST_GATEWAY:-}" ]]; then
    log "Probing bridge gateways for one that actually routes to the host..."
    CANDIDATES="$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null) 172.17.0.1 10.88.0.1"
    for GW in $CANDIDATES; do
        [[ -z "$GW" ]] && continue
        if docker run --rm --network ctf-net busybox sh -c "nc -z -w2 $GW $OLLAMA_PORT" &>/dev/null; then
            warn "Using bridge gateway: $GW (set DOCKER_HOST_GATEWAY to override next time)"
            export DOCKER_HOST_GATEWAY="$GW"
            break
        fi
    done
    [[ -z "${DOCKER_HOST_GATEWAY:-}" ]] && warn "No working bridge gateway found — ollama/mcp-tulip may be unreachable"
fi
export MCP_POSTGRES_RO_URI="postgresql://${MCP_PG_ROLE}@${DOCKER_HOST_GATEWAY:-host.docker.internal}:${MCP_PG_PORT}/${MCP_PG_DB}"

docker compose up -d detection watchdog ml-fingerprint mcp-tulip
sleep 2

docker compose up -d ioc-brain dashboard anythingllm
ok "Hub services started"

# ctf_proxy lives in its own compose project (separate repo, like Tulip) and
# needs the ctf-net network this file just created, so it must come after.
CTF_PROXY_DIR="$SCRIPT_DIR/offline-bundle/repos/ctf_proxy"
if [[ -d "$CTF_PROXY_DIR" ]]; then
    log "Starting ctf_proxy (fronting mock-vulnbox at $VULNBOX_IP)..."
    (cd "$CTF_PROXY_DIR" && docker compose build --quiet 2>&1 | tail -3 && docker compose up -d) \
        || warn "ctf_proxy failed to start"
else
    warn "ctf_proxy not found at $CTF_PROXY_DIR — skipping"
fi

# ═══════════════════════════════════════════════════════════════
# 7. Start Ollama (load on demand only — do NOT keep LLM loaded)
# ═══════════════════════════════════════════════════════════════
header "Step 7: Ollama setup"

if command -v ollama &>/dev/null; then
    if ! pgrep -x ollama > /dev/null; then
        log "Starting Ollama service..."
        ollama serve &>/tmp/ollama.log &
        sleep 3
        ok "Ollama started (models load on demand)"
    else
        ok "Ollama already running"
    fi
    # Verify models available
    if ollama list 2>/dev/null | grep -q "${LLM_MODEL%%:*}"; then
        ok "LLM model available: $LLM_MODEL"
    else
        warn "LLM model not pulled yet: $LLM_MODEL"
        warn "Run: ollama pull '$LLM_MODEL'"
    fi
else
    warn "ollama command not found — IOC Brain will be unavailable"
fi

# ═══════════════════════════════════════════════════════════════
# 8. Health check
# ═══════════════════════════════════════════════════════════════
header "Step 8: Health checks"

sleep 5  # let services initialize

check_service() {
    local name="$1"
    local url="$2"
    if curl -sf --connect-timeout 3 "$url" &>/dev/null; then
        ok "$name: UP ($url)"
        return 0
    else
        warn "$name: NOT responding ($url)"
        return 1
    fi
}

check_service "Redis"        "http://127.0.0.1:$ALERT_QUEUE_PORT"     2>/dev/null || true
check_service "Detection"    "http://127.0.0.1:$HONEYTOKEN_PORT/health"
check_service "Dashboard"    "http://127.0.0.1:$DASHBOARD_PORT/health"
check_service "IOC Brain"    "http://127.0.0.1:$IOC_API_PORT/health"

if [[ -d "$TULIP_DIR" ]]; then
    check_service "Tulip UI" "http://127.0.0.1:$TULIP_WEB_PORT"
fi

check_service "AnythingLLM" "http://127.0.0.1:$ANYTHINGLLM_PORT"

# ═══════════════════════════════════════════════════════════════
# 9. Summary
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║  🛡  CTF Monitor Hub is UP                          ║${NC}"
echo -e "${BOLD}${GREEN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${GREEN}║${NC}  Dashboard:     http://localhost:${DASHBOARD_PORT}              ${BOLD}${GREEN}║${NC}"
echo -e "${BOLD}${GREEN}║${NC}  Tulip UI:      http://localhost:${TULIP_WEB_PORT}              ${BOLD}${GREEN}║${NC}"
echo -e "${BOLD}${GREEN}║${NC}  IOC Brain:     http://localhost:${IOC_API_PORT}              ${BOLD}${GREEN}║${NC}"
echo -e "${BOLD}${GREEN}║${NC}  AnythingLLM:   http://localhost:${ANYTHINGLLM_PORT}              ${BOLD}${GREEN}║${NC}"
echo -e "${BOLD}${GREEN}║${NC}  Honeytoken:    http://localhost:${HONEYTOKEN_PORT}/honeytoken   ${BOLD}${GREEN}║${NC}"
echo -e "${BOLD}${GREEN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${GREEN}║${NC}  Vulnbox:  $VULNBOX_IP                              ${BOLD}${GREEN}║${NC}"
echo -e "${BOLD}${GREEN}║${NC}  Monitor:  $MONITOR_IP                              ${BOLD}${GREEN}║${NC}"
echo -e "${BOLD}${GREEN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${GREEN}║${NC}  ⚠️  NO AUTO-BLOCKING. HUMAN DECISION ONLY.          ${BOLD}${GREEN}║${NC}"
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
log "Next steps:"
log "  1. Open dashboard: xdg-open http://localhost:$DASHBOARD_PORT"
log "  2. Deploy vulnbox capture: bash vulnbox-deploy/deploy-capture.sh"
log "  3. Deploy OS watchdog:     bash vulnbox-deploy/deploy-os-watchdog.sh"
log "  4. Deploy honeytoken:      bash vulnbox-deploy/deploy-honeytoken.sh"
log "  5. Test detection:         curl -X POST http://localhost:$HONEYTOKEN_PORT/test/inject-flag"
log "  6. Teardown when done:     bash teardown.sh"
