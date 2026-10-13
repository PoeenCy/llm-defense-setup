#!/usr/bin/env bash
# deploy-all.sh — the "1-click": bring up the entire monitor hub + vulnbox
# pipeline from zero. Safe to re-run any time (every step is idempotent).
#
# Usage: MODE=contest|prep bash deploy-all.sh [--offline]
#
# Order matters: local stack first (always works, no external dependency),
# then remote capture (hard-fails if the vulnbox is unreachable -- nothing
# past that point can work without it), then ctf_proxy (soft-fails to
# monitor-only if its config-driven preconditions in services.json don't
# check out), then a final health report.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
step() { echo -e "\n${CYAN}━━━ $* ━━━${NC}"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; }

case "${MODE:-}" in
    contest|prep) ;;
    *) fail "MODE must be 'contest' or 'prep'. Run as: MODE=contest bash deploy-all.sh"; exit 1 ;;
esac

step "1/7 — Preflight checks (on a fresh machine, catch missing deps HERE, not as a silent crash later)"
PREFLIGHT_FAIL=false
for cmd in docker python3; do
    if ! command -v "$cmd" &>/dev/null; then
        fail "'$cmd' not found on PATH — install it before continuing."
        PREFLIGHT_FAIL=true
    fi
done
if command -v docker &>/dev/null && ! docker compose version &>/dev/null; then
    fail "'docker compose' (the v2 plugin) not found — install docker-compose-plugin."
    PREFLIGHT_FAIL=true
fi
# host_agent.py / health_check.py run directly on the host (not in a
# container) and need the 'redis' package to be importable by this machine's
# python3. Missing this fails SILENTLY later (host_agent.py dies with a
# traceback in .host-agent.log, System Status just never appears, and rule
# changes from the Dashboard stop working) -- so check and fix it HERE,
# loudly, before that can happen.
if ! python3 -c "import redis" &>/dev/null; then
    warn "python3 module 'redis' missing (needed by host_agent.py) — attempting: pip3 install --user -r contest-runtime/requirements-host.txt"
    if pip3 install --user -r contest-runtime/requirements-host.txt &>/tmp/pip-redis-install.log; then
        if python3 -c "import redis" &>/dev/null; then
            ok "'redis' installed successfully"
        else
            fail "pip install reported success but 'import redis' still fails — check /tmp/pip-redis-install.log and your python3/pip3 versions match"
            PREFLIGHT_FAIL=true
        fi
    else
        fail "pip3 install failed (see /tmp/pip-redis-install.log) — install it yourself: pip3 install --user redis"
        PREFLIGHT_FAIL=true
    fi
fi
if [[ "$PREFLIGHT_FAIL" == true ]]; then
    fail "Preflight failed — fix the above before continuing. Nothing below has been touched."
    exit 1
fi
ok "Preflight checks passed (docker, docker compose, python3, redis module)"

step "2/7 — Validate config"
bash contest-runtime/config/validate-config.sh || { fail "services.json has problems — fix those first, nothing below will work right."; exit 1; }

step "3/7 — Local monitor-hub stack (MODE=$MODE: Tulip, detection, dashboard, watchdog$([ "$MODE" = prep ] && echo ', ml-fingerprint/mock-vulnbox if enabled'))"
bash bringup.sh "$@" || { fail "bringup.sh failed — check its output above."; exit 1; }
ok "local stack up"

pkill -f '[h]ealth_check.py --push' 2>/dev/null || true
pkill -f '[h]ost_agent.py' 2>/dev/null || true
nohup python3 contest-runtime/host_agent.py >.host-agent.log 2>&1 &
disown
ok "host_agent.py backgrounded (pid $!, log .host-agent.log) — feeds System Status + applies rule changes from the Dashboard"

step "4/7 — Remote capture (tcpdump + pull loop, backgrounded)"
if bash contest-runtime/monitor/deploy-capture-pull.sh --background; then
    ok "capture running"
    CAPTURE_OK=true
else
    warn "capture setup failed (vulnbox likely unreachable) — Tulip/Suricata/Dashboard will sit idle until this is fixed. See docs/RUNBOOK.md Troubleshooting."
    CAPTURE_OK=false
fi

step "5/7 — Vulnbox traps: honeytoken + OS watchdog (best-effort)"
if [[ "$CAPTURE_OK" == true ]]; then
    bash contest-runtime/detection/deploy-honeytoken.sh  || warn "honeytoken install failed — see output above"
    bash contest-runtime/watchdog/deploy-os-watchdog.sh || warn "OS watchdog install failed — see output above"
else
    warn "skipping honeytoken + OS watchdog — vulnbox wasn't reachable in step 3"
fi

step "6/7 — ctf_proxy (best-effort; falls back to monitor-only if preconditions don't check out)"
if [[ "$CAPTURE_OK" == true ]]; then
    bash contest-runtime/defense/deploy-ctfproxy.sh
else
    warn "skipping ctf_proxy — vulnbox wasn't reachable in step 3"
fi

step "7/7 — Final health check"
bash health-check.sh

echo -e "\n${CYAN}Done.${NC} Dashboard: http://localhost:8080  |  Tulip: http://localhost:3000"
echo "Re-run this script any time things look wrong — every step is safe to repeat."
