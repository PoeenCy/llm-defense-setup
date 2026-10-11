#!/usr/bin/env bash
# deploy-all.sh — the "1-click": bring up the entire monitor hub + vulnbox
# pipeline from zero. Safe to re-run any time (every step is idempotent).
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

step "1/6 — Validate config"
bash validate-config.sh || { fail "services.json has problems — fix those first, nothing below will work right."; exit 1; }

step "2/6 — Local monitor-hub stack (Tulip, detection, dashboard, watchdog, Ollama RAG)"
bash bringup.sh || { fail "bringup.sh failed — check its output above."; exit 1; }
ok "local stack up"

pkill -f '[h]ealth_check.py --push' 2>/dev/null || true
pkill -f '[h]ost_agent.py' 2>/dev/null || true
nohup python3 host_agent.py >.host-agent.log 2>&1 &
disown
ok "host_agent.py backgrounded (pid $!, log .host-agent.log) — feeds System Status + applies rule changes from the Dashboard"

step "3/6 — Remote capture (tcpdump + pull loop, backgrounded)"
if bash vulnbox-deploy/deploy-capture-pull.sh --background; then
    ok "capture running"
    CAPTURE_OK=true
else
    warn "capture setup failed (vulnbox likely unreachable) — Tulip/Suricata/Dashboard will sit idle until this is fixed. See docs/RUNBOOK.md Troubleshooting."
    CAPTURE_OK=false
fi

step "4/6 — Vulnbox traps: honeytoken + OS watchdog (best-effort)"
if [[ "$CAPTURE_OK" == true ]]; then
    bash vulnbox-deploy/deploy-honeytoken.sh  || warn "honeytoken install failed — see output above"
    bash vulnbox-deploy/deploy-os-watchdog.sh || warn "OS watchdog install failed — see output above"
else
    warn "skipping honeytoken + OS watchdog — vulnbox wasn't reachable in step 3"
fi

step "5/6 — ctf_proxy (best-effort; falls back to monitor-only if preconditions don't check out)"
if [[ "$CAPTURE_OK" == true ]]; then
    bash vulnbox-deploy/deploy-ctfproxy.sh
else
    warn "skipping ctf_proxy — vulnbox wasn't reachable in step 3"
fi

step "6/6 — Final health check"
bash health-check.sh

echo -e "\n${CYAN}Done.${NC} Dashboard: http://localhost:8080  |  Tulip: http://localhost:3000"
echo "Re-run this script any time things look wrong — every step is safe to repeat."
