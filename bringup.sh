#!/usr/bin/env bash
# bringup.sh — CTF Monitor Hub: One-Command Bring-Up
# Usage: MODE=contest|prep bash bringup.sh [--offline]
#
# There is no LLM / generative-AI path anywhere in this repo (removed per an
# explicit decision — see docs/STATUS.md). The MODE split still matters
# because `ml-fingerprint` (a non-generative sklearn classifier) and
# `mock-vulnbox` (a rehearsal-only toy target) are still prep-only/practice
# fixtures, not real contest-day defense.
#
# MODE=contest — ONLY docker-compose.contest.yml runs. Any already-running
#                prep-only container is stopped before contest services
#                start, and the whole run is refused if one is still found
#                running afterward (assert_contest_clean, Step 6b).
# MODE=prep    — docker-compose.contest.yml AND docker-compose.prep.yml both
#                run (home/practice use: mock-vulnbox, and — only if
#                services.json's ml_classifier.enabled is also true —
#                ml-fingerprint).
#
# Steps:
#   1. Validate services.json
#   2. If --offline: restore from offline-bundle/ (no network)
#   3. Generate Tulip .env from services.json
#   4. Export all env vars for docker-compose
#   5. Build/pull images if needed
#   6. Start all services in correct dependency order (mode-gated)
#   6b. Assert no prep-only container is running when MODE=contest
#   7. Health-check and report status
#
# Safety: read-only Postgres (Tulip). No auto-blocking. No auto-deploy.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="$SCRIPT_DIR/contest-runtime/config/services.json"
TULIP_DIR="$SCRIPT_DIR/offline-bundle/repos/tulip"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; BOLD='\033[1m'; NC='\033[0m'

log()    { echo -e "${CYAN}[BRINGUP]${NC} $*"; }
ok()     { echo -e "${GREEN}[OK]${NC}      $*"; }
warn()   { echo -e "${YELLOW}[WARN]${NC}    $*"; }
die()    { echo -e "${RED}[FATAL]${NC}   $*"; exit 1; }
header() { echo -e "\n${BOLD}${CYAN}══ $* ══${NC}"; }

OFFLINE=false
for arg in "$@"; do [[ "$arg" == "--offline" ]] && OFFLINE=true; done

MODE="${MODE:-}"
case "$MODE" in
    contest|prep) ;;
    "") die "MODE is not set. Run as: MODE=contest bash bringup.sh   (or MODE=prep for home/practice use)" ;;
    *)  die "MODE must be 'contest' or 'prep', got: '$MODE'" ;;
esac
export MODE  # so docker-compose interpolates ${MODE} into every container's
             # environment — the prep-only services re-check this themselves
             # at startup (defense-in-depth beyond "which compose file ran")

# Container names that must NEVER be running when MODE=contest. Kept here
# (not sourced from docker-compose.prep.yml) so the check doesn't depend on
# that file parsing correctly — a hard-coded denylist is the right failure
# mode for a compliance gate.
PREP_ONLY_CONTAINERS=(ctf-ml-fingerprint ctf-mock-vulnbox)

assert_contest_clean() {
    local offenders=()
    for name in "${PREP_ONLY_CONTAINERS[@]}"; do
        if docker ps --format '{{.Names}}' | grep -qx "$name"; then
            offenders+=("$name")
        fi
    done
    if [[ ${#offenders[@]} -gt 0 ]]; then
        echo -e "${RED}[COMPLIANCE FAILURE]${NC} prep-only container(s) running while MODE=contest:"
        printf '  - %s\n' "${offenders[@]}"
        die "Refusing to proceed — stop these (docker stop ...) and re-run."
    fi
}

COMPOSE_FILES=(-f docker-compose.contest.yml)
if [[ "$MODE" == "prep" ]]; then
    COMPOSE_FILES+=(-f docker-compose.prep.yml)
fi

echo ""
echo -e "${BOLD}${CYAN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${CYAN}║     CTF Monitor Hub — Bring-Up                      ║${NC}"
echo -e "${BOLD}${CYAN}║     Attack-Defense CTF Situational Awareness Stack   ║${NC}"
echo -e "${BOLD}${CYAN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
log "MODE=$MODE"
if [[ "$MODE" == "contest" ]]; then
    ok "Contest mode — only docker-compose.contest.yml will run."
else
    warn "Prep mode — mock-vulnbox and (if enabled) ml-fingerprint MAY start. Never use this mode on contest day."
fi
[[ "$OFFLINE" == true ]] && warn "OFFLINE MODE — no network calls will be made"

# ═══════════════════════════════════════════════════════════════
# 0. Validate config
# ═══════════════════════════════════════════════════════════════
header "Step 0: Validate services.json"

[[ -f "$CONFIG" ]] || die "services.json not found at $CONFIG"
bash "$SCRIPT_DIR/contest-runtime/config/validate-config.sh" "$CONFIG" || die "services.json validation failed — fix errors above"
ok "services.json valid"

# Parse all config values
TEAM_ID=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['team_id'])")
VULNBOX_IP=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['vulnbox']['ip'])")
VULNBOX_BROKER_PORT=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['vulnbox']['pcap_broker_port'])")
MONITOR_IP=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['monitor_host']['ip'])")
DASHBOARD_PORT=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['monitor_host']['dashboard_port'])")
ALERT_QUEUE_PORT=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['monitor_host']['alert_queue_port'])")
FLAG_REGEX=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['flag']['regex'])")
HONEYTOKEN_FLAG=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['honeytoken']['flag'])")
HONEYTOKEN_PORT=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['honeytoken']['endpoint_port'])")
TEAMS_CIDR=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['teams_cidr'])")
TULIP_WEB_PORT=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['tulip']['web_port'])")
BIND_IP=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['monitor_host'].get('bind_ip','127.0.0.1'))")
MOCK_VULNBOX_ENABLED=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(str(d.get('mock_vulnbox',{}).get('enabled',False)).lower())")
ML_CLASSIFIER_ENABLED=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(str(d.get('ml_classifier',{}).get('enabled',False)).lower())")
FLAGTRACE_ENABLED=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(str(d.get('flagtrace',{}).get('enabled',False)).lower())")
FLAGTRACE_TRACE_ENABLED=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(str((d.get('flagtrace',{}).get('trace') or {}).get('enabled',False)).lower())")

if [[ "$MODE" == "contest" ]]; then
    header "Step 0b: Pre-clean — stop any leftover prep-only containers"
    for name in "${PREP_ONLY_CONTAINERS[@]}"; do
        if docker ps -a --format '{{.Names}}' | grep -qx "$name"; then
            warn "Stopping leftover prep-only container: $name"
            docker rm -f "$name" >/dev/null 2>&1 || true
        fi
    done
    ok "No prep-only containers will carry over into this contest run"
fi

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
    "$SCRIPT_DIR/contest-runtime/detection/suricata/log" \
    "$SCRIPT_DIR/contest-runtime/detection/suricata/etc" \
    "$SCRIPT_DIR/contest-runtime/detection/suricata/lib"

ok "Directories ready"

# ═══════════════════════════════════════════════════════════════
# 3. Generate Tulip .env
# ═══════════════════════════════════════════════════════════════
header "Step 3: Generate Tulip config"

if [[ -d "$TULIP_DIR" ]]; then
    CONFIG="$CONFIG" TULIP_DIR="$TULIP_DIR" python3 "$SCRIPT_DIR/contest-runtime/config/generators/gen-tulip-env.py"
    ok "Tulip .env generated"
else
    warn "Tulip repo not found at $TULIP_DIR — skipping Tulip config"
    warn "Run: bash pull-and-save.sh to clone Tulip"
fi

CTF_PROXY_DIR="$SCRIPT_DIR/offline-bundle/repos/ctf_proxy"
if [[ -d "$CTF_PROXY_DIR" ]]; then
    CONFIG="$CONFIG" CTF_PROXY_DIR="$CTF_PROXY_DIR" python3 "$SCRIPT_DIR/contest-runtime/config/generators/gen-ctfproxy.py"
    ok "ctf_proxy config generated"
else
    warn "ctf_proxy not found at $CTF_PROXY_DIR — skipping"
fi

# ═══════════════════════════════════════════════════════════════
# 4. Export environment for docker-compose
# ═══════════════════════════════════════════════════════════════
header "Step 4: Export environment"

export TEAM_ID VULNBOX_IP MONITOR_IP TEAMS_CIDR
export FLAG_REGEX HONEYTOKEN_FLAG HONEYTOKEN_PORT
export DASHBOARD_PORT ALERT_QUEUE_PORT
export TULIP_WEB_PORT BIND_IP

log "Environment exported (${#TEAM_ID} values set)"

# ═══════════════════════════════════════════════════════════════
# 5. Start Tulip stack
# ═══════════════════════════════════════════════════════════════
header "Step 5: Start Tulip stack"

if [[ -d "$TULIP_DIR" ]]; then
    log "Building Tulip images (first run may take 5-10 min)..."
    cd "$TULIP_DIR"
    # docker-compose-suricata.yml is a full superset of docker-compose.yml
    # (same services + suricata, enricher wired to eve.json). Plain
    # docker-compose.yml alone leaves Suricata OFF and the enricher idle.
    TULIP_COMPOSE="-f docker-compose.yml"
    if [[ -f docker-compose-suricata.yml && -d "$SCRIPT_DIR/contest-runtime/detection/suricata/lib/rules" ]]; then
        TULIP_COMPOSE="-f docker-compose.yml -f docker-compose-suricata.yml"
        log "Suricata overlay enabled (rules: contest-runtime/detection/suricata/lib/rules/)"
    else
        warn "Suricata overlay or contest-runtime/detection/suricata/lib/rules missing — starting Tulip WITHOUT Suricata"
    fi
    docker compose $TULIP_COMPOSE build --quiet 2>&1 | tail -3 || warn "Tulip build had warnings"
    log "Starting Tulip..."
    docker compose $TULIP_COMPOSE up -d 2>&1 | tail -5
    cd "$SCRIPT_DIR"
    ok "Tulip started"
else
    warn "Tulip repo missing — skipping Tulip"
fi
# dashboard joins Tulip's internal network (reads Tulip's API for the Rules
# tab). If Tulip didn't come up (repo missing / failed), create an empty
# network of that name so the dashboard still starts — it degrades (no flow
# lookups) instead of refusing to run.
if ! docker network inspect tulip_internal >/dev/null 2>&1; then
    warn "Tulip network tulip_internal not found — creating an empty one so the dashboard can still start"
    docker network create tulip_internal >/dev/null
fi

# ═══════════════════════════════════════════════════════════════
# 6. Start monitor hub services (mode-gated)
# ═══════════════════════════════════════════════════════════════
header "Step 6: Start monitor hub services (MODE=$MODE)"

cd "$SCRIPT_DIR"
log "Building hub images..."
if [[ "$OFFLINE" != true ]]; then
    docker compose "${COMPOSE_FILES[@]}" build --quiet 2>&1 | tail -3 || warn "Build had warnings"
fi

log "Starting core services (redis, detection, watchdog)..."
docker compose "${COMPOSE_FILES[@]}" up -d redis
sleep 3  # wait for redis; this also creates the ctf-net network

# Persist every value compose interpolates into ./.env (compose reads it
# automatically). Without this, any later `docker compose up -d <svc>` — by
# hand, or a Restart from the dashboard — would start containers with EMPTY
# config (e.g. detection crashes on an empty TEAMS_CIDR).
{
    echo "# AUTO-GENERATED by bringup.sh from services.json — re-run bringup.sh instead of editing"
    for v in MODE TEAM_ID VULNBOX_IP MONITOR_IP TEAMS_CIDR FLAG_REGEX HONEYTOKEN_FLAG HONEYTOKEN_PORT \
             DASHBOARD_PORT ALERT_QUEUE_PORT TULIP_WEB_PORT BIND_IP; do
        val="${!v:-}"
        [[ "$val" == *"'"* ]] && die "$v contains a single quote, which .env can't hold literally: $val"
        printf "%s='%s'\n" "$v" "$val"
    done
} > "$SCRIPT_DIR/.env"
ok "Compose environment saved to .env (manual 'docker compose up -d <svc>' now gets the same config)"

docker compose "${COMPOSE_FILES[@]}" up -d detection watchdog
ok "Legal defense/monitor services started"

if [[ "$FLAGTRACE_ENABLED" == true ]]; then
    mkdir -p "$SCRIPT_DIR/data/flagtrace"
    if [[ "$OFFLINE" == true ]]; then
        FT_UP=(up -d --no-build --pull never)
    else
        FT_UP=(up -d)
        docker compose "${COMPOSE_FILES[@]}" build flagtrace
    fi
    # The new image decides whether its schema is newer than the file on disk.
    # Upgrades run with ingest and worker both stopped, after a consistent
    # backup: the previous image cannot read an upgraded database.
    FT_SCHEMA=0
    docker compose "${COMPOSE_FILES[@]}" run --rm --no-deps flagtrace \
        python -m flagtrace.app.main migrate --check >/dev/null 2>&1 || FT_SCHEMA=$?
    if [[ "$FT_SCHEMA" -eq 3 ]]; then
        log "Flag-trace schema upgrade pending: stopping ingest + worker, backing up, migrating"
        docker compose "${COMPOSE_FILES[@]}" stop flagtrace flagtrace-worker >/dev/null 2>&1 || true
        docker compose "${COMPOSE_FILES[@]}" run --rm --no-deps flagtrace python -m flagtrace.app.main migrate \
            || die "Flag-trace migration failed; the pre-upgrade backup is in data/flagtrace/backups/"
        ok "Flag-trace database migrated (backup in data/flagtrace/backups/)"
    elif [[ "$FT_SCHEMA" -ne 0 ]]; then
        die "Flag-trace schema check failed (database newer than this image, or unreadable); not starting it"
    fi
    docker compose "${COMPOSE_FILES[@]}" "${FT_UP[@]}" flagtrace
    if [[ "$FLAGTRACE_TRACE_ENABLED" == true ]]; then
        docker compose "${COMPOSE_FILES[@]}" "${FT_UP[@]}" flagtrace-worker
        ok "Flag-trace ingest + trace worker started"
    else
        # Ingest keeps running; stored profiles, jobs and results are kept.
        docker compose "${COMPOSE_FILES[@]}" stop flagtrace-worker >/dev/null 2>&1 || true
        ok "Flag-trace ingest started (flagtrace.trace.enabled=false: trace worker stopped)"
    fi
else
    docker compose "${COMPOSE_FILES[@]}" stop flagtrace flagtrace-worker >/dev/null 2>&1 || true
fi

if [[ "$MODE" == "prep" ]]; then
    log "MODE=prep: starting practice fixtures..."
    if [[ "$ML_CLASSIFIER_ENABLED" == "true" ]]; then
        log "ml_classifier.enabled=true — starting ml-fingerprint"
        docker compose "${COMPOSE_FILES[@]}" up -d ml-fingerprint
    else
        log "ml_classifier.enabled=false — ml-fingerprint not started"
    fi
    if [[ "$MOCK_VULNBOX_ENABLED" == "true" ]]; then
        docker compose "${COMPOSE_FILES[@]}" up -d mock-vulnbox
    fi
fi

docker compose "${COMPOSE_FILES[@]}" up -d dashboard
ok "Dashboard started"

# ctf_proxy lives in its own compose project (separate repo, like Tulip).
# Fronting the REAL vulnbox is deployed separately via
# contest-runtime/defense/deploy-ctfproxy.sh (legal-runtime, runs regardless of
# MODE, via deploy-all.sh)
# — this block only starts the LOCAL rehearsal instance in front of
# mock-vulnbox, which is prep-only.
if [[ "$MODE" == "prep" && "$MOCK_VULNBOX_ENABLED" == "true" ]]; then
    CTF_PROXY_DIR="$SCRIPT_DIR/offline-bundle/repos/ctf_proxy"
    if [[ -d "$CTF_PROXY_DIR" ]]; then
        log "Starting ctf_proxy (fronting mock-vulnbox at $VULNBOX_IP, rehearsal only)..."
        (cd "$CTF_PROXY_DIR" && docker compose build --quiet 2>&1 | tail -3 && docker compose up -d) \
            || warn "ctf_proxy failed to start"
    else
        warn "ctf_proxy not found at $CTF_PROXY_DIR — skipping"
    fi
elif [[ "$MODE" == "contest" ]]; then
    log "MODE=contest: local mock ctf_proxy never starts — real ctf_proxy is deployed onto the actual vulnbox by contest-runtime/defense/deploy-ctfproxy.sh (see deploy-all.sh)"
fi

# ═══════════════════════════════════════════════════════════════
# 6b. Compliance assertion — refuse to continue if contest mode somehow has
#     a prep-only container running anyway.
# ═══════════════════════════════════════════════════════════════
if [[ "$MODE" == "contest" ]]; then
    header "Step 6b: Compliance check"
    assert_contest_clean
    ok "Compliance check passed — no prep-only container is running"
fi

# ═══════════════════════════════════════════════════════════════
# 7. Health check
# ═══════════════════════════════════════════════════════════════
header "Step 7: Health checks"

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

# Redis speaks RESP, not HTTP — ping it properly instead of curling it.
if docker exec ctf-redis redis-cli ping 2>/dev/null | grep -q PONG; then
    ok "Redis: UP (127.0.0.1:$ALERT_QUEUE_PORT)"
else
    warn "Redis: NOT responding — docker logs ctf-redis"
fi
# Health checks are informational only — a slow/down service here must never
# abort the script under `set -e`, or the rest of bringup (and deploy-all.sh
# after it) never runs.
check_service "Detection"    "http://127.0.0.1:$HONEYTOKEN_PORT/health" || true
check_service "Dashboard"    "http://127.0.0.1:$DASHBOARD_PORT/health" || true

if [[ -d "$TULIP_DIR" ]]; then
    check_service "Tulip UI" "http://127.0.0.1:$TULIP_WEB_PORT" || true
fi

# Final compliance re-check right before declaring success — belt-and-
# suspenders against a race where a prep container started mid-bringup.
if [[ "$MODE" == "contest" ]]; then
    assert_contest_clean
fi

# ═══════════════════════════════════════════════════════════════
# 8. Summary
# ═══════════════════════════════════════════════════════════════
echo ""
echo -e "${BOLD}${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BOLD}${GREEN}║  🛡  CTF Monitor Hub is UP (MODE=$MODE)${NC}"
echo -e "${BOLD}${GREEN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${GREEN}║${NC}  Dashboard:     http://localhost:${DASHBOARD_PORT}              ${BOLD}${GREEN}║${NC}"
echo -e "${BOLD}${GREEN}║${NC}  Tulip UI:      http://localhost:${TULIP_WEB_PORT}              ${BOLD}${GREEN}║${NC}"
echo -e "${BOLD}${GREEN}║${NC}  Honeytoken:    http://localhost:${HONEYTOKEN_PORT}/honeytoken   ${BOLD}${GREEN}║${NC}"
echo -e "${BOLD}${GREEN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${BOLD}${GREEN}║${NC}  Vulnbox:  $VULNBOX_IP                              ${BOLD}${GREEN}║${NC}"
echo -e "${BOLD}${GREEN}║${NC}  Monitor:  $MONITOR_IP                              ${BOLD}${GREEN}║${NC}"
echo -e "${BOLD}${GREEN}╠══════════════════════════════════════════════════════╣${NC}"
if [[ "$MODE" == "contest" ]]; then
echo -e "${BOLD}${GREEN}║${NC}  ⚠️  NO AUTO-BLOCKING. HUMAN DECISION ONLY.          ${BOLD}${GREEN}║${NC}"
else
echo -e "${BOLD}${GREEN}║${NC}  ⚠️  PREP MODE — practice fixtures may be running. Do NOT use on contest day. ${BOLD}${GREEN}║${NC}"
fi
echo -e "${BOLD}${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
log "Next steps:"
log "  1. Open dashboard: xdg-open http://localhost:$DASHBOARD_PORT"
log "  2. Deploy vulnbox capture: bash contest-runtime/monitor/deploy-capture.sh"
log "  3. Deploy OS watchdog:     bash contest-runtime/watchdog/deploy-os-watchdog.sh"
log "  4. Deploy honeytoken:      bash contest-runtime/detection/deploy-honeytoken.sh"
log "  5. Test detection:         curl -X POST http://localhost:9998/test/inject-flag  (admin port, loopback only)"
log "  6. Teardown when done:     MODE=$MODE bash teardown.sh"
