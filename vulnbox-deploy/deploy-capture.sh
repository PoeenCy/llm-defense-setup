#!/usr/bin/env bash
# vulnbox-deploy/deploy-capture.sh
# Deploy tcpdump + pcap-broker server on vulnbox.
# Run from MONITOR: bash vulnbox-deploy/deploy-capture.sh
# Reads all params from services.json — never hardcoded.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${SCRIPT_DIR}/../services.json"
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

log()  { echo -e "${CYAN}[DEPLOY-CAPTURE]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC}             $*"; }
die()  { echo -e "${RED}[FATAL]${NC}          $*"; exit 1; }

[[ -f "$CONFIG" ]] || die "services.json not found"

VULNBOX_IP=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['vulnbox']['ip'])")
SSH_USER=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['vulnbox']['ssh_user'])")
SSH_PORT=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['vulnbox'].get('ssh_port',22))")
BROKER_PORT=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['vulnbox']['pcap_broker_port'])")
CAPTURE_IFACE=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['vulnbox']['capture_iface'])")
MONITOR_IP=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['monitor_host']['ip'])")

SSH="ssh -p $SSH_PORT -o StrictHostKeyChecking=no -o ConnectTimeout=5"
SCP="scp -P $SSH_PORT -o StrictHostKeyChecking=no"

log "Deploying capture stack to $SSH_USER@$VULNBOX_IP:$SSH_PORT"
log "  Capture iface: $CAPTURE_IFACE"
log "  Broker port:   $BROKER_PORT"
log "  Monitor IP:    $MONITOR_IP"

# Test connectivity
$SSH "$SSH_USER@$VULNBOX_IP" "echo 'SSH OK'" || die "Cannot reach vulnbox"
ok "SSH connectivity verified"

# Install dependencies
log "Installing tcpdump..."
$SSH "$SSH_USER@$VULNBOX_IP" "
    apt-get update -qq 2>/dev/null || yum update -q 2>/dev/null || true
    command -v tcpdump || apt-get install -y tcpdump 2>/dev/null || yum install -y tcpdump 2>/dev/null
    tcpdump --version 2>&1 | head -1
"

# Install Go pcap-broker if available, else use socat+tcpdump
log "Installing pcap-broker (pcap-over-IP server)..."
$SSH "$SSH_USER@$VULNBOX_IP" "
    # Try Go installation
    if command -v go &>/dev/null; then
        GO_BIN=\"\$(go env GOPATH)/bin\"
        go install github.com/fstark/pcap-broker@latest 2>/dev/null && echo 'pcap-broker installed via go'
    fi

    # Fallback: install via curl if binary available
    if ! command -v pcap-broker &>/dev/null; then
        echo 'pcap-broker binary not found; using socat+tcpdump fallback'
    fi
"

# Create and deploy the pcap-broker service
log "Creating pcap-broker systemd service..."
$SSH "$SSH_USER@$VULNBOX_IP" "cat > /etc/systemd/system/pcap-broker.service << 'SVCEOF'
[Unit]
Description=PCAP over IP Broker for CTF Monitor
After=network.target

[Service]
Type=simple
Restart=always
RestartSec=2
# Try pcap-broker binary first, fall back to socat
ExecStart=/bin/bash -c '
if command -v pcap-broker &>/dev/null; then
    exec pcap-broker -iface ${CAPTURE_IFACE} -port ${BROKER_PORT}
else
    # Socat fallback: pipe tcpdump output as raw pcap stream
    exec socat TCP-LISTEN:${BROKER_PORT},fork,reuseaddr EXEC:\"tcpdump -i ${CAPTURE_IFACE} -U -w - not port 22\",nofork
fi
'
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF
systemctl daemon-reload
systemctl enable pcap-broker
systemctl restart pcap-broker
sleep 1
systemctl is-active pcap-broker && echo 'pcap-broker service RUNNING' || echo 'WARNING: pcap-broker not running'
"

ok "Capture stack deployed to vulnbox"
log "Verify from monitor: nc -v $VULNBOX_IP $BROKER_PORT | head -c 24 | xxd"
