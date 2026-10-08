#!/usr/bin/env bash
# vulnbox-deploy/deploy-honeytoken.sh
# Deploy the honeytoken trap on the vulnbox.
# Places a decoy flag in a trap location and hooks reads to notify the monitor.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${SCRIPT_DIR}/../services.json"
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log() { echo -e "${CYAN}[DEPLOY-HONEYTOKEN]${NC} $*"; }
ok()  { echo -e "${GREEN}[OK]${NC}               $*"; }
die() { echo -e "${RED}[FATAL]${NC}            $*"; exit 1; }

[[ -f "$CONFIG" ]] || die "services.json not found"

VULNBOX_IP=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['vulnbox']['ip'])")
SSH_USER=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['vulnbox']['ssh_user'])")
SSH_PORT=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['vulnbox'].get('ssh_port',22))")
MONITOR_IP=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['monitor_host']['ip'])")
HONEYTOKEN_PORT=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['honeytoken']['endpoint_port'])")
HONEYTOKEN_FLAG=$(python3 -c "import json; d=json.load(open('$CONFIG')); print(d['honeytoken']['flag'])")

SSH="ssh -p $SSH_PORT -o StrictHostKeyChecking=no"

log "Deploying honeytoken to $SSH_USER@$VULNBOX_IP"
log "  Honeytoken: $HONEYTOKEN_FLAG"
log "  Reports to: http://$MONITOR_IP:$HONEYTOKEN_PORT/honeytoken"

$SSH "$SSH_USER@$VULNBOX_IP" "echo SSH-OK" || die "SSH failed"

$SSH "$SSH_USER@$VULNBOX_IP" "
set -e
MONITOR_URL='http://${MONITOR_IP}:${HONEYTOKEN_PORT}/honeytoken'
HONEYTOKEN='${HONEYTOKEN_FLAG}'

# Place decoy flag in several tempting locations
mkdir -p /opt/flags /tmp/.secret /.secret 2>/dev/null || true
for path in /opt/flags/flag.txt /tmp/.secret/flag /root/.bash_history_backup /etc/.hidden_flag; do
    echo \"\$HONEYTOKEN\" > \"\$path\" 2>/dev/null || true
    # inotifywait hook if available
    if command -v inotifywait &>/dev/null; then
        (
            while true; do
                inotifywait -e access,open \"\$path\" 2>/dev/null && \
                curl -s -X POST \"\$MONITOR_URL\" \\
                     -H 'Content-Type: application/json' \\
                     -d \"{\\\"path\\\":\\\"\$path\\\",\\\"flag\\\":\\\"\$HONEYTOKEN\\\"}\" &
            done
        ) &
        disown
        echo \"Trap set on \$path (inotify)\"
    else
        echo \"inotify not available for \$path (install inotify-tools for active trapping)\"
    fi
done

# Place a fake service response honeytoken (curl trap)
cat > /usr/local/bin/flag-server.sh << 'FLAGEOF'
#!/usr/bin/env python3
import http.server, subprocess, urllib.request

MONITOR='${MONITOR_IP}'
PORT=${HONEYTOKEN_PORT}
FLAG='${HONEYTOKEN_FLAG}'

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        # Alert monitor
        try:
            req = urllib.request.Request(
                f'http://{MONITOR}:{PORT}/honeytoken/{FLAG}',
                method='GET'
            )
            urllib.request.urlopen(req, timeout=2)
        except: pass
        self.send_response(200)
        self.end_headers()
        self.wfile.write(FLAG.encode())
    def log_message(self, *a): pass

http.server.HTTPServer(('0.0.0.0', 7777), H).serve_forever()
FLAGEOF
chmod +x /usr/local/bin/flag-server.sh

# Run as background service
nohup python3 /usr/local/bin/flag-server.sh &>/tmp/flag-server.log &
echo \"Honeytoken HTTP trap on port 7777\"
echo 'Deployment complete.'
"

ok "Honeytoken deployed"
log "Test: curl http://$VULNBOX_IP:7777/ — should trigger alert on monitor"
