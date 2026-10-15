#!/usr/bin/env bash
# vulnbox-deploy/deploy-honeytoken.sh
# Deploy the honeytoken trap on the vulnbox.
# Places a decoy flag in a trap location and hooks reads to notify the monitor.
#
# KNOWN LIMITATION, confirmed live against a real DFCD practice vulnbox (not
# speculation): the decoy paths below (/opt/flags, /root, /etc, /tmp/.secret)
# live on the docker HOST filesystem. On a real team-03-style compose stack
# the actual flag is bind-mounted read-only into the *vulnerable app
# container* only (e.g. "/flags/service-<n>:/flag:ro" on the "node"
# service) -- an attacker who exploits the app lands inside that container,
# not on the host, and never touches any of these host-side decoy paths.
# These decoys still have value for catching a full container ESCAPE/host
# compromise, but do not assume they catch an ordinary app-level flag theft.
# A container-aware honeytoken (planted via `docker exec` into the actual
# vulnerable service, next to or instead of the mounted flag) would be a
# materially different and more invasive change -- not done here without
# confirming the exact placement with whoever owns the vulnbox stack.
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

# deploy-all.sh is meant to be safe to re-run any number of times, but this
# script used to start a brand new flag-server.sh + inotify watcher loop on
# every run with no check for an existing one -- confirmed live: a
# flag-server.sh from an earlier deploy was still running 3+ days later,
# never cleaned up (same leak class as the capture tcpdump issue).
#
# This must NOT be `pkill -f '<pattern>'` run as part of the one big
# deployment command below: the whole heredoc is sent as a single string,
# so a pattern that also appears later in that same string (it always will
# -- the pattern IS the thing we're about to start) matches the currently
# running shell itself and kills the deploy mid-script with no output at
# all. Confirmed live (exit 255, dies before even the next line runs) --
# the same self-match footgun as `pkill -f` matching your own invoking
# command line, just via "later in the same script" instead of "earlier in
# it". Fixed with PID files + bare-numeric `kill`, each in its own separate
# ssh call with nothing else in that call's command text to self-match.
OLD_FS_PID=$($SSH "$ALIAS" "cat /tmp/.honeytoken-flagserver.pid 2>/dev/null" || true)
[[ "$OLD_FS_PID" =~ ^[0-9]+$ ]] && $SSH "$ALIAS" "kill -TERM $OLD_FS_PID" 2>/dev/null || true
OLD_WATCHER_PIDS=$($SSH "$ALIAS" "cat /tmp/.honeytoken-watchers.pid 2>/dev/null" || true)
for p in $OLD_WATCHER_PIDS; do
    [[ "$p" =~ ^[0-9]+$ ]] && $SSH "$ALIAS" "kill -TERM $p" 2>/dev/null || true
done

$SSH "$ALIAS" "
set -e
MONITOR_URL='http://${MONITOR_IP}:${HONEYTOKEN_PORT}/honeytoken'
HONEYTOKEN='${HONEYTOKEN_FLAG}'
> /tmp/.honeytoken-watchers.pid

# Place decoy flag in several tempting locations. These paths are root-owned
# on a stock vulnbox (/opt, /root, /etc) -- the admin SSH user here is NOT
# root (confirmed live: plain writes failed with Permission denied / No such
# file or directory once mkdir silently failed too), so every write and the
# trap-process install below need sudo -n.
sudo -n mkdir -p /opt/flags /tmp/.secret /.secret 2>/dev/null || true
for path in /opt/flags/flag.txt /tmp/.secret/flag /root/.bash_history_backup /etc/.hidden_flag; do
    echo \"\$HONEYTOKEN\" | sudo -n tee \"\$path\" >/dev/null 2>/dev/null || true
    # inotifywait hook if available
    if command -v inotifywait &>/dev/null; then
        (
            while true; do
                sudo -n inotifywait -e access,open \"\$path\" 2>/dev/null && \
                curl -s -X POST \"\$MONITOR_URL\" \\
                     -H 'Content-Type: application/json' \\
                     -d \"{\\\"path\\\":\\\"\$path\\\",\\\"flag\\\":\\\"\$HONEYTOKEN\\\"}\" &
            done
        ) &
        echo \$! >> /tmp/.honeytoken-watchers.pid
        disown
        echo \"Trap set on \$path (inotify)\"
    else
        echo \"inotify not available for \$path (install inotify-tools for active trapping)\"
    fi
done

# Place a fake service response honeytoken (curl trap)
sudo -n tee /usr/local/bin/flag-server.sh >/dev/null << 'FLAGEOF'
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
sudo -n chmod +x /usr/local/bin/flag-server.sh

# Run as background service
nohup python3 /usr/local/bin/flag-server.sh &>/tmp/flag-server.log &
echo \$! > /tmp/.honeytoken-flagserver.pid
echo \"Honeytoken HTTP trap on port 7777\"
echo 'Deployment complete.'
"

ok "Honeytoken deployed"
log "Decoy files: /opt/flags/flag.txt /tmp/.secret/flag /root/.bash_history_backup /etc/.hidden_flag (reading any = alert)"
log "Needs inotify-tools on the vulnbox for the file traps; without it only the decoy files are placed (still caught leaving in pcap as honeytoken-out)."
