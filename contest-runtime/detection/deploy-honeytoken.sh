#!/usr/bin/env bash
# vulnbox-deploy/deploy-honeytoken.sh
# Deploy the honeytoken trap on the vulnbox.
# Places a decoy flag in a trap location and hooks reads to notify the monitor.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${SCRIPT_DIR}/../config/services.json"
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
log() { echo -e "${CYAN}[DEPLOY-HONEYTOKEN]${NC} $*"; }
ok()  { echo -e "${GREEN}[OK]${NC}               $*"; }
die() { echo -e "${RED}[FATAL]${NC}            $*"; exit 1; }

[[ -f "$CONFIG" ]] || die "services.json not found"

cfgval() { python3 -c "import json,sys; d=json.load(open('$CONFIG')); print(eval(sys.argv[1]))" "$1" 2>/dev/null || true; }
# Honeytoken writes decoy files to the vulnbox HOST filesystem and installs a
# trap process, so it needs the ADMIN alias (capture_ssh_alias), not the team
# patch key (ssh_user, which only reaches the public-proxy container).
ALIAS=$(cfgval "d['vulnbox'].get('capture_ssh_alias') or ''")
MONITOR_IP=$(cfgval "d['monitor_host']['ip']")
HONEYTOKEN_PORT=$(cfgval "d['honeytoken']['endpoint_port']")
HONEYTOKEN_FLAG=$(cfgval "d['honeytoken']['flag']")
skip() { echo -e "${CYAN}[DEPLOY-HONEYTOKEN]${NC} [SKIP] $* — honeytoken not installed; everything else keeps working."; exit 0; }

[[ -n "$ALIAS" ]] || skip "vulnbox.capture_ssh_alias not set in services.json"
SSH="ssh -o ConnectTimeout=8 -o BatchMode=yes -o StrictHostKeyChecking=no"

log "Deploying honeytoken to $ALIAS"
log "  Honeytoken: $HONEYTOKEN_FLAG"
log "  Reports to: http://$MONITOR_IP:$HONEYTOKEN_PORT/honeytoken"

timeout 15 $SSH "$ALIAS" "echo SSH-OK" >/dev/null 2>&1 || skip "ssh $ALIAS unreachable (VM stopped?)"

$SSH "$ALIAS" "
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

http.server.HTTPServer(('127.0.0.1', 7777), H).serve_forever()
FLAGEOF
chmod +x /usr/local/bin/flag-server.sh

# Run as background service
nohup python3 /usr/local/bin/flag-server.sh &>/tmp/flag-server.log &
echo \"Honeytoken HTTP trap on port 7777\"
echo 'Deployment complete.'
"

ok "Honeytoken deployed"
log "Decoy files: /opt/flags/flag.txt /tmp/.secret/flag /root/.bash_history_backup /etc/.hidden_flag (reading any = alert)"
log "Needs inotify-tools on the vulnbox for the file traps; without it only the decoy files are placed (still caught leaving in pcap as honeytoken-out)."
