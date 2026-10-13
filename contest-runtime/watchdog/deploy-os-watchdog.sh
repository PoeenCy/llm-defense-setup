#!/usr/bin/env bash
# vulnbox-deploy/deploy-os-watchdog.sh — install / control the OS integrity
# watchdog (os-watchdog-agent.sh) on the vulnbox HOST.
#
#   bash deploy-os-watchdog.sh            install (or reinstall) and start
#   bash deploy-os-watchdog.sh --stop     stop it
#   bash deploy-os-watchdog.sh --status   print running|stopped|absent
#
# Called by deploy-all.sh. Best-effort: when a precondition is missing (VM
# unreachable, no sudo) it prints why and exits 0 — the rest of the system
# works without it, you only lose the "os-watchdog" events.
#
# Uses the admin alias vulnbox.capture_ssh_alias (same as capture, needs
# passwordless sudo). The agent reports to http://<monitor_host.ip>:<honeytoken.endpoint_port>/watchdog/os-report.
# Runs as a systemd service when systemd is available, otherwise under nohup.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${SCRIPT_DIR}/../config/services.json"
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${CYAN}[OS-WATCHDOG]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC}          $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}        $*"; }
skip() { echo -e "${YELLOW}[SKIP]${NC}        $* — OS watchdog not installed; everything else keeps working."; exit 0; }

MODE="${1:-install}"
cfgval() { python3 -c "import json,sys; d=json.load(open('$CONFIG')); print(eval(sys.argv[1]))" "$1" 2>/dev/null || true; }
ALIAS=$(cfgval "d['vulnbox'].get('capture_ssh_alias') or ''")
MONITOR_IP=$(cfgval "d['monitor_host']['ip']")
REPORT_PORT=$(cfgval "d.get('honeytoken',{}).get('endpoint_port',9999)")
BIN=/usr/local/bin/os-watchdog-agent.sh
UNIT=/etc/systemd/system/os-watchdog.service

[[ -n "$ALIAS" ]] || skip "vulnbox.capture_ssh_alias not set in services.json"
R() { timeout 30 ssh -o ConnectTimeout=8 -o BatchMode=yes "$ALIAS" "$@"; }

STATUS_CMD="if systemctl is-active --quiet os-watchdog 2>/dev/null || pgrep -f '[o]s-watchdog-agent.sh run' >/dev/null; then echo running; elif [ -f $BIN ]; then echo stopped; else echo absent; fi"

if [[ "$MODE" == "--status" ]]; then
    R "$STATUS_CMD" 2>/dev/null || echo unknown
    exit 0
fi

log "Checking SSH: $ALIAS"
R "echo OK" >/dev/null 2>&1 || skip "ssh $ALIAS unreachable (VM stopped?)"
R "sudo -n true" >/dev/null 2>&1 || skip "no passwordless sudo on $ALIAS (the agent reads /proc, crontabs and /etc as root)"

if [[ "$MODE" == "--stop" ]]; then
    R "sudo systemctl stop os-watchdog 2>/dev/null; sudo pkill -f '[o]s-watchdog-agent.sh run' 2>/dev/null; true"
    ok "OS watchdog stopped ($(R "$STATUS_CMD"))"
    exit 0
fi

log "Uploading agent to $ALIAS:$BIN"
R "sudo tee $BIN >/dev/null && sudo chmod 755 $BIN" < "$SCRIPT_DIR/os-watchdog-agent.sh"

# The agent is useless if its reports can't reach us: check the path first.
if R "curl -s -m 4 -o /dev/null http://$MONITOR_IP:$REPORT_PORT/health" 2>/dev/null; then
    ok "vulnbox can reach the monitor at $MONITOR_IP:$REPORT_PORT"
else
    warn "vulnbox can NOT reach http://$MONITOR_IP:$REPORT_PORT — reports will be lost. Check monitor_host.ip in services.json and the firewall/VPN on this machine."
fi

ENVV="MONITOR_IP=$MONITOR_IP MONITOR_PORT=$REPORT_PORT CHECK_INTERVAL=10"
if R "command -v systemctl >/dev/null && [ -d /run/systemd/system ]"; then
    log "Installing systemd unit os-watchdog"
    R "sudo tee $UNIT >/dev/null" <<EOF
[Unit]
Description=CTF OS Integrity Watchdog
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=5
Environment=MONITOR_IP=$MONITOR_IP
Environment=MONITOR_PORT=$REPORT_PORT
Environment=CHECK_INTERVAL=10
ExecStartPre=$BIN snapshot
ExecStart=$BIN run

[Install]
WantedBy=multi-user.target
EOF
    R "sudo systemctl daemon-reload && sudo systemctl enable os-watchdog >/dev/null 2>&1; sudo systemctl restart os-watchdog"
else
    log "No systemd — starting under nohup (won't survive a reboot; re-run deploy-all.sh after one)"
    R "sudo pkill -f '[o]s-watchdog-agent.sh run' 2>/dev/null; sudo env $ENVV $BIN snapshot >/dev/null 2>&1; sudo env $ENVV nohup $BIN run >/tmp/os-watchdog.log 2>&1 </dev/null & disown"
fi
sleep 2
STATE=$(R "$STATUS_CMD")
[[ "$STATE" == "running" ]] && ok "OS watchdog running on $ALIAS (events: Dashboard → EVENTS → source os-watchdog)" \
                            || warn "OS watchdog state: $STATE — see: ssh $ALIAS sudo journalctl -u os-watchdog -n 30"
