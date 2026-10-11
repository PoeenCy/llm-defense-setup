#!/usr/bin/env bash
# deploy-ctfproxy.sh — insert ctf_proxy in front of a real, already-running
# service on the vulnbox-host so we can actually block malicious traffic, not
# just observe it.
#
# This is explicitly OPT-IN and config-driven (services.json -> ctf_proxy.insertion),
# because the only safe way to insert a proxy in front of a LIVE service is to
# know exactly which compose file/service/network it lives in -- guessing at an
# unfamiliar layout risks real downtime for a real guess that might be wrong.
#
# Every precondition is RE-VERIFIED over SSH before anything is touched. If any
# check fails -- mode is "disabled", the compose file/service/network doesn't
# exist, docker compose isn't even installed -- this exits 0 (success) having
# done nothing, so the pipeline stays in monitor-only mode instead of crashing
# or half-configuring something. Monitor-only (Tulip + Suricata + Dashboard,
# no blocking) is a legitimate, fully-working fallback, not a failure state.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${SCRIPT_DIR}/../services.json"
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${CYAN}[CTF-PROXY]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC}        $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}      $*"; }
skip() { echo -e "${YELLOW}[SKIP]${NC}      $*  -- staying monitor-only."; exit 0; }
die()  { echo -e "${RED}[FATAL]${NC}     $*"; exit 1; }

[[ -f "$CONFIG" ]] || die "services.json not found"

eval "$(python3 -c "
import json, shlex
d = json.load(open('$CONFIG'))
ins = d.get('ctf_proxy', {}).get('insertion', {})
for k in ('mode','remote_compose_file','remote_compose_service','remote_network_name','remote_ssh_alias'):
    print(f'{k.upper()}={shlex.quote(ins.get(k) or \"\")}')
svc = d['services'][0]
print(f'TARGET_PORT={shlex.quote(str(svc[\"port\"]))}')
print(f'KEYWORD={shlex.quote(d[\"ctf_proxy\"][\"keyword\"])}')
print(f'TEAM_ID={shlex.quote(d[\"team_id\"])}')
")"

[[ "$MODE" == "docker-compose" ]] || skip "ctf_proxy.insertion.mode is '$MODE', not 'docker-compose'"
[[ -n "$REMOTE_SSH_ALIAS" ]] || skip "ctf_proxy.insertion.remote_ssh_alias not set"
[[ -n "$REMOTE_COMPOSE_FILE" && -n "$REMOTE_COMPOSE_SERVICE" && -n "$REMOTE_NETWORK_NAME" ]] \
    || skip "ctf_proxy.insertion is missing remote_compose_file/remote_compose_service/remote_network_name"

log "Verifying preconditions on $REMOTE_SSH_ALIAS before touching anything..."

timeout 10 ssh -o ConnectTimeout=8 -o BatchMode=yes "$REMOTE_SSH_ALIAS" "echo OK" >/dev/null 2>&1 \
    || skip "ssh $REMOTE_SSH_ALIAS unreachable"
ok "ssh reachable"

ssh "$REMOTE_SSH_ALIAS" "test -f $REMOTE_COMPOSE_FILE" 2>/dev/null \
    || skip "remote_compose_file '$REMOTE_COMPOSE_FILE' not found on $REMOTE_SSH_ALIAS"
ok "compose file exists: $REMOTE_COMPOSE_FILE"

ssh "$REMOTE_SSH_ALIAS" "grep -qE '^\s*${REMOTE_COMPOSE_SERVICE}:' $REMOTE_COMPOSE_FILE" 2>/dev/null \
    || skip "service '$REMOTE_COMPOSE_SERVICE' not found in $REMOTE_COMPOSE_FILE"
ok "service '$REMOTE_COMPOSE_SERVICE' found in compose file"

ssh "$REMOTE_SSH_ALIAS" "grep -qE '\"${TARGET_PORT}:[0-9]+\"' $REMOTE_COMPOSE_FILE" 2>/dev/null \
    || skip "no port binding for '$TARGET_PORT' found under '$REMOTE_COMPOSE_SERVICE' in $REMOTE_COMPOSE_FILE -- refusing to guess which line to remove"
INTERNAL_PORT=$(ssh "$REMOTE_SSH_ALIAS" "grep -oE '\"${TARGET_PORT}:[0-9]+\"' $REMOTE_COMPOSE_FILE | head -1 | grep -oE ':[0-9]+' | tr -d ':'")
ok "found port binding ${TARGET_PORT}:${INTERNAL_PORT}"

ssh "$REMOTE_SSH_ALIAS" "docker network inspect $REMOTE_NETWORK_NAME >/dev/null 2>&1" \
    || skip "docker network '$REMOTE_NETWORK_NAME' not found on $REMOTE_SSH_ALIAS"
ok "docker network '$REMOTE_NETWORK_NAME' exists"

ssh "$REMOTE_SSH_ALIAS" "command -v docker >/dev/null && docker compose version >/dev/null 2>&1" \
    || skip "'docker compose' not available on $REMOTE_SSH_ALIAS"
ok "docker compose available"

log "All preconditions verified. Proceeding with insertion (brief downtime expected when the port is handed over)."

REMOTE_CTFPROXY_DIR="~/ctf-proxy-${TEAM_ID}"
LOCAL_CTFPROXY_SRC="${SCRIPT_DIR}/../offline-bundle/repos/ctf_proxy"
[[ -d "$LOCAL_CTFPROXY_SRC" ]] || die "ctf_proxy source not found at $LOCAL_CTFPROXY_SRC -- run pull-and-save.sh or offline-restore.sh first"

log "Copying ctf_proxy source to $REMOTE_SSH_ALIAS:$REMOTE_CTFPROXY_DIR"
rsync -az --exclude='.git' "$LOCAL_CTFPROXY_SRC/" "${REMOTE_SSH_ALIAS}:${REMOTE_CTFPROXY_DIR}/" || die "rsync of ctf_proxy source failed"

log "Writing proxy/config/config.json (target: ${REMOTE_COMPOSE_SERVICE}:${INTERNAL_PORT}, listen: ${TARGET_PORT})"
ssh "$REMOTE_SSH_ALIAS" "cat > ${REMOTE_CTFPROXY_DIR}/proxy/config/config.json" << EOF
{
  "services": [
    {
      "name": "web",
      "target_ip": "${REMOTE_COMPOSE_SERVICE}",
      "target_port": ${INTERNAL_PORT},
      "listen_port": ${TARGET_PORT},
      "http": true
    }
  ],
  "global_config": {
    "keyword": "${KEYWORD}",
    "verbose": false,
    "nginx": { "connect_timeout": 5, "max_fails": 1, "fail_timeout": 20 },
    "dos": { "enabled": false, "duration": 60, "interval": 2 },
    "max_stored_messages": 10,
    "max_message_size": 65535
  }
}
EOF

log "Writing ctf_proxy's own docker-compose.yml (joins existing network: ${REMOTE_NETWORK_NAME})"
ssh "$REMOTE_SSH_ALIAS" "cat > ${REMOTE_CTFPROXY_DIR}/docker-compose.yml" << EOF
services:
  nginx:
    build: "./nginx"
    hostname: nginx
    container_name: ctfproxy-${TEAM_ID}-nginx
    restart: unless-stopped
    ports:
      - "${TARGET_PORT}:${TARGET_PORT}"
    networks:
      - proxy-public
    volumes:
     - ./nginx/nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
     - proxy

  proxy:
    build: ./
    hostname: proxy
    container_name: ctfproxy-${TEAM_ID}-proxy
    restart: unless-stopped
    environment:
      PYTHONUNBUFFERED: 1
    networks:
      - proxy-public
    volumes:
     - "./proxy:/proxy"
     - "./nginx/nginx.conf:/nginx.conf"

networks:
  proxy-public:
    external: true
    name: ${REMOTE_NETWORK_NAME}
EOF

log "Removing port binding ${TARGET_PORT}:${INTERNAL_PORT} from ${REMOTE_COMPOSE_SERVICE} in the ORIGINAL compose file"
ssh "$REMOTE_SSH_ALIAS" "cp ${REMOTE_COMPOSE_FILE} ${REMOTE_COMPOSE_FILE}.pre-ctfproxy.bak && sed -i.bak '/\"${TARGET_PORT}:${INTERNAL_PORT}\"/d' ${REMOTE_COMPOSE_FILE}" \
    || die "failed to edit remote compose file (backup at ${REMOTE_COMPOSE_FILE}.pre-ctfproxy.bak if anything needs reverting)"
ok "port line removed (original backed up as ${REMOTE_COMPOSE_FILE}.pre-ctfproxy.bak)"

log "Recreating ${REMOTE_COMPOSE_SERVICE} to release the port (brief downtime now)"
REMOTE_COMPOSE_DIR=$(dirname "$REMOTE_COMPOSE_FILE")
ssh "$REMOTE_SSH_ALIAS" "cd ${REMOTE_COMPOSE_DIR} && docker compose up -d ${REMOTE_COMPOSE_SERVICE}" \
    || die "failed to recreate ${REMOTE_COMPOSE_SERVICE} -- port may now be unbound with nothing serving it; restore from ${REMOTE_COMPOSE_FILE}.pre-ctfproxy.bak if needed"

log "Building and starting ctf_proxy"
ssh "$REMOTE_SSH_ALIAS" "cd ${REMOTE_CTFPROXY_DIR} && docker compose build" || die "ctf_proxy build failed"
ssh "$REMOTE_SSH_ALIAS" "cd ${REMOTE_CTFPROXY_DIR} && docker compose up -d" 2>&1 | tee /tmp/ctfproxy-up.log
# Known gotcha: the nginx container can come up with no network attached if
# created before the "proxy" container's DNS entry fully propagated. A plain
# restart does not fix this -- only a full recreate does.
sleep 3
NET=$(ssh "$REMOTE_SSH_ALIAS" "docker inspect ctfproxy-${TEAM_ID}-nginx --format '{{json .NetworkSettings.Networks}}' 2>/dev/null")
if [[ "$NET" == "{}" || -z "$NET" ]]; then
    warn "nginx came up with no network attached (known startup race) -- forcing a clean recreate"
    ssh "$REMOTE_SSH_ALIAS" "docker rm -f ctfproxy-${TEAM_ID}-nginx && cd ${REMOTE_CTFPROXY_DIR} && docker compose up -d nginx"
    sleep 3
fi

log "Verifying real traffic still gets through..."
sleep 2
HTTP_CODE=$(ssh "$REMOTE_SSH_ALIAS" "curl -s -o /dev/null -w '%{http_code}' --max-time 8 http://localhost:${TARGET_PORT}/" 2>/dev/null)
if [[ "$HTTP_CODE" =~ ^[0-9]+$ ]] && [[ "$HTTP_CODE" != "000" ]]; then
    ok "ctf_proxy is up and passing traffic through (HTTP $HTTP_CODE from the real service)"
else
    warn "ctf_proxy is up but traffic check got no clean response (HTTP_CODE='$HTTP_CODE') -- verify manually before trusting it: curl http://<vulnbox-ip>:${TARGET_PORT}/"
fi

log "filter_modules/web/web_in.py on the remote starts EMPTY (pass-through only) -- write real rules there once you've confirmed an attack pattern via Tulip/Dashboard."
