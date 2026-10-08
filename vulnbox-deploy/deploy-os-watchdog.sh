#!/usr/bin/env bash
# vulnbox-deploy/deploy-os-watchdog.sh
# Deploy OS watchdog agent to vulnbox from monitor machine.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${SCRIPT_DIR}/../services.json"
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log()  { echo -e "${CYAN}[DEPLOY-OSWATCHDOG]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC}                  $*"; }
die()  { echo -e "${RED}[FATAL]${NC}               $*"; exit 1; }

[[ -f "$CONFIG" ]] || die "services.json not found"

VULNBOX_IP=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['vulnbox']['ip'])")
SSH_USER=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['vulnbox']['ssh_user'])")
SSH_PORT=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['vulnbox'].get('ssh_port',22))")
MONITOR_IP=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['monitor_host']['ip'])")
HONEYTOKEN_PORT=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['honeytoken']['endpoint_port'])")

SSH="ssh -p $SSH_PORT -o StrictHostKeyChecking=no"
SCP="scp -P $SSH_PORT -o StrictHostKeyChecking=no"

log "Deploying OS watchdog to $SSH_USER@$VULNBOX_IP"

# Test SSH
$SSH "$SSH_USER@$VULNBOX_IP" "echo SSH-OK" || die "SSH failed"
ok "SSH OK"

# Copy agent
log "Copying os-watchdog-agent.sh..."
$SCP "$SCRIPT_DIR/os-watchdog-agent.sh" "$SSH_USER@$VULNBOX_IP:/usr/local/bin/os-watchdog-agent.sh"
$SSH "$SSH_USER@$VULNBOX_IP" "chmod +x /usr/local/bin/os-watchdog-agent.sh"
ok "Agent copied"

# Create systemd service
log "Installing systemd service..."
$SSH "$SSH_USER@$VULNBOX_IP" "cat > /etc/systemd/system/os-watchdog.service << SVCEOF
[Unit]
Description=CTF OS Integrity Watchdog
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=5
Environment=MONITOR_IP=${MONITOR_IP}
Environment=MONITOR_PORT=${HONEYTOKEN_PORT}
Environment=CHECK_INTERVAL=10
ExecStartPre=/usr/local/bin/os-watchdog-agent.sh snapshot
ExecStart=/usr/local/bin/os-watchdog-agent.sh run
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF
systemctl daemon-reload
systemctl enable os-watchdog
systemctl restart os-watchdog
sleep 2
systemctl is-active os-watchdog && echo 'os-watchdog RUNNING' || echo 'WARNING: os-watchdog failed'
"

ok "OS watchdog deployed and running on vulnbox"
log "View logs: ssh $SSH_USER@$VULNBOX_IP journalctl -f -u os-watchdog"
log "Take snapshot manually: ssh $SSH_USER@$VULNBOX_IP /usr/local/bin/os-watchdog-agent.sh snapshot"
log "Diff vs snapshot:       ssh $SSH_USER@$VULNBOX_IP /usr/local/bin/os-watchdog-agent.sh diff"
