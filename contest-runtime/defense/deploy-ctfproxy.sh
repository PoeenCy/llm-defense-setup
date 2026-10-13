#!/usr/bin/env bash
# deploy-ctfproxy.sh — insert ctf_proxy in front of EVERY TCP service on the
# vulnbox-host so we can actually block malicious traffic, not just observe
# it. One ctf_proxy deployment handles all of them (it natively supports a
# services[] list -- one nginx failover + filter module pair per service).
#
# UDP services are skipped: ctf_proxy only proxies TCP and HTTP (see its own
# README) -- there is no way to insert it in front of a UDP service. For
# those, use the dashboard's content-based firewall block instead (SERVICES
# tab -- iptables string-match, protocol-agnostic).
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
CONFIG="${SCRIPT_DIR}/../config/services.json"
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${CYAN}[CTF-PROXY]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC}        $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}      $*"; }
skip() { echo -e "${YELLOW}[SKIP]${NC}      $*  -- staying monitor-only."; exit 0; }
die()  { echo -e "${RED}[FATAL]${NC}     $*"; exit 1; }

[[ -f "$CONFIG" ]] || die "services.json not found"

eval "$(python3 -c "
import json, re, shlex
d = json.load(open('$CONFIG'))
ins = d.get('ctf_proxy', {}).get('insertion', {})
for k in ('mode','remote_compose_file','remote_network_name','remote_ssh_alias'):
    print(f'{k.upper()}={shlex.quote(ins.get(k) or \"\")}')
print(f'KEYWORD={shlex.quote(d[\"ctf_proxy\"][\"keyword\"])}')
print(f'TEAM_ID={shlex.quote(d[\"team_id\"])}')

def sanitize(name):
    n = re.sub(r'[^a-zA-Z0-9_]', '_', (name or '').strip()) or 'svc'
    return 's_' + n if n[0].isdigit() else n

eligible = [s for s in d['services'] if s.get('proto', 'tcp') == 'tcp']
skipped_udp = [s['name'] for s in d['services'] if s.get('proto') == 'udp']
print(f'SVC_COUNT={len(eligible)}')
print(f'SKIPPED_UDP={shlex.quote(\",\".join(skipped_udp))}')
for i, s in enumerate(eligible):
    san = sanitize(s['name'])
    compose_svc = s.get('compose_service') or ins.get('remote_compose_service') or ''
    http = 'true' if s.get('layer') in ('l7-http', 'l7-https') else 'false'
    print(f'SVC_{i}_NAME={shlex.quote(s[\"name\"])}')
    print(f'SVC_{i}_SAN={shlex.quote(san)}')
    print(f'SVC_{i}_PORT={shlex.quote(str(s[\"port\"]))}')
    print(f'SVC_{i}_COMPOSE_SVC={shlex.quote(compose_svc)}')
    print(f'SVC_{i}_HTTP={http}')
")"

[[ "$MODE" == "docker-compose" ]] || skip "ctf_proxy.insertion.mode is '$MODE', not 'docker-compose'"
[[ -n "$REMOTE_SSH_ALIAS" ]] || skip "ctf_proxy.insertion.remote_ssh_alias not set"
[[ -n "$REMOTE_COMPOSE_FILE" && -n "$REMOTE_NETWORK_NAME" ]] \
    || skip "ctf_proxy.insertion is missing remote_compose_file/remote_network_name"
[[ "$SVC_COUNT" -gt 0 ]] || skip "no TCP services in services.json to insert ctf_proxy in front of"
if [[ -n "$SKIPPED_UDP" ]]; then
    warn "skipping UDP service(s) [$SKIPPED_UDP] -- ctf_proxy cannot proxy UDP. Use the dashboard's content-based firewall block for these instead."
fi

log "Verifying preconditions on $REMOTE_SSH_ALIAS before touching anything..."

timeout 10 ssh -o ConnectTimeout=8 -o BatchMode=yes "$REMOTE_SSH_ALIAS" "echo OK" >/dev/null 2>&1 \
    || skip "ssh $REMOTE_SSH_ALIAS unreachable"
ok "ssh reachable"

ssh "$REMOTE_SSH_ALIAS" "test -f $REMOTE_COMPOSE_FILE" 2>/dev/null \
    || skip "remote_compose_file '$REMOTE_COMPOSE_FILE' not found on $REMOTE_SSH_ALIAS"
ok "compose file exists: $REMOTE_COMPOSE_FILE"

ssh "$REMOTE_SSH_ALIAS" "docker network inspect $REMOTE_NETWORK_NAME >/dev/null 2>&1" \
    || skip "docker network '$REMOTE_NETWORK_NAME' not found on $REMOTE_SSH_ALIAS"
ok "docker network '$REMOTE_NETWORK_NAME' exists"

ssh "$REMOTE_SSH_ALIAS" "command -v docker >/dev/null && docker compose version >/dev/null 2>&1" \
    || skip "'docker compose' not available on $REMOTE_SSH_ALIAS"
ok "docker compose available"

# Per-service precondition checks: compose_service set, present in the compose
# file, and actually binding the port we're about to take over. Any failure
# here skips (not dies) -- a bad service entry must not block the OTHERS from
# getting ctf_proxy.
ELIGIBLE_IDX=()
for ((i = 0; i < SVC_COUNT; i++)); do
    name_var="SVC_${i}_NAME";    svc_name="${!name_var}"
    cs_var="SVC_${i}_COMPOSE_SVC"; compose_svc="${!cs_var}"
    port_var="SVC_${i}_PORT";    port="${!port_var}"

    if [[ -z "$compose_svc" ]]; then
        warn "service '$svc_name': no compose_service set (and no legacy ctf_proxy.insertion.remote_compose_service fallback) -- skipping this one"
        continue
    fi
    ssh "$REMOTE_SSH_ALIAS" "grep -qE '^\s*${compose_svc}:' $REMOTE_COMPOSE_FILE" 2>/dev/null \
        || { warn "service '$svc_name': compose service '$compose_svc' not found in $REMOTE_COMPOSE_FILE -- skipping"; continue; }
    ssh "$REMOTE_SSH_ALIAS" "grep -qE '\"${port}:[0-9]+\"' $REMOTE_COMPOSE_FILE" 2>/dev/null \
        || { warn "service '$svc_name': no port binding for '$port' found under '$compose_svc' -- refusing to guess which line to remove, skipping"; continue; }
    internal_port=$(ssh "$REMOTE_SSH_ALIAS" "grep -oE '\"${port}:[0-9]+\"' $REMOTE_COMPOSE_FILE | head -1 | grep -oE ':[0-9]+' | tr -d ':'")
    declare "SVC_${i}_INTERNAL=$internal_port"
    ok "service '$svc_name': found port binding ${port}:${internal_port} on compose service '$compose_svc'"
    ELIGIBLE_IDX+=("$i")
done

[[ ${#ELIGIBLE_IDX[@]} -gt 0 ]] || skip "no service passed its precondition checks -- nothing to insert ctf_proxy in front of"

log "All preconditions verified for ${#ELIGIBLE_IDX[@]} service(s). Proceeding with insertion (brief downtime expected when each port is handed over)."

REMOTE_CTFPROXY_DIR="~/ctf-proxy-${TEAM_ID}"
LOCAL_CTFPROXY_SRC="${SCRIPT_DIR}/../../offline-bundle/repos/ctf_proxy"
[[ -d "$LOCAL_CTFPROXY_SRC" ]] || die "ctf_proxy source not found at $LOCAL_CTFPROXY_SRC -- run pull-and-save.sh or offline-restore.sh first"

log "Copying ctf_proxy source to $REMOTE_SSH_ALIAS:$REMOTE_CTFPROXY_DIR"
rsync -az --exclude='.git' "$LOCAL_CTFPROXY_SRC/" "${REMOTE_SSH_ALIAS}:${REMOTE_CTFPROXY_DIR}/" || die "rsync of ctf_proxy source failed"

# Build proxy/config/config.json (one entry per eligible service) and the
# nginx container's port list in one python pass over the indices bash just
# verified -- avoids re-deriving the same JSON by hand in bash string-gluing.
# export: the python subprocess below only sees os.environ, not plain shell vars.
export KEYWORD TEAM_ID
for i in "${ELIGIBLE_IDX[@]}"; do
    export "SVC_${i}_SAN" "SVC_${i}_PORT" "SVC_${i}_INTERNAL" "SVC_${i}_COMPOSE_SVC" "SVC_${i}_HTTP"
done
CONFIG_JSON=$(python3 -c "
import json, sys
idx = [int(x) for x in sys.argv[1].split(',') if x]
services = []
ports = []
import os
for i in idx:
    name = os.environ[f'SVC_{i}_SAN']
    port = int(os.environ[f'SVC_{i}_PORT'])
    internal = int(os.environ[f'SVC_{i}_INTERNAL'])
    compose_svc = os.environ[f'SVC_{i}_COMPOSE_SVC']
    http = os.environ[f'SVC_{i}_HTTP'] == 'true'
    services.append({'name': name, 'target_ip': compose_svc, 'target_port': internal,
                      'listen_port': port, 'http': http})
    ports.append(port)
cfg = {
    'services': services,
    'global_config': {
        'keyword': os.environ['KEYWORD'], 'verbose': False,
        'nginx': {'connect_timeout': 5, 'max_fails': 1, 'fail_timeout': 20},
        'dos': {'enabled': False, 'duration': 60, 'interval': 2},
        'max_stored_messages': 10, 'max_message_size': 65535,
    },
}
print(json.dumps(cfg))
print('---PORTS---')
print(','.join(str(p) for p in sorted(set(ports))))
" "$(IFS=,; echo "${ELIGIBLE_IDX[*]}")")
PROXY_CFG="${CONFIG_JSON%%---PORTS---*}"
PORT_LIST="${CONFIG_JSON##*---PORTS---}"
PORT_LIST="$(echo "$PORT_LIST" | tr -d '[:space:]')"

log "Writing proxy/config/config.json (${#ELIGIBLE_IDX[@]} service(s))"
ssh "$REMOTE_SSH_ALIAS" "cat > ${REMOTE_CTFPROXY_DIR}/proxy/config/config.json" <<< "$PROXY_CFG"

NGINX_PORTS=""
IFS=',' read -ra PORT_ARR <<< "$PORT_LIST"
for p in "${PORT_ARR[@]}"; do
    NGINX_PORTS+=$'\n'"      - \"${p}:${p}\""
done

log "Writing ctf_proxy's own docker-compose.yml (joins existing network: ${REMOTE_NETWORK_NAME})"
ssh "$REMOTE_SSH_ALIAS" "cat > ${REMOTE_CTFPROXY_DIR}/docker-compose.yml" << EOF
services:
  nginx:
    build: "./nginx"
    hostname: nginx
    container_name: ctfproxy-${TEAM_ID}-nginx
    restart: unless-stopped
    ports:${NGINX_PORTS}
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

log "Removing port bindings from the ORIGINAL compose file for ${#ELIGIBLE_IDX[@]} service(s)"
ssh "$REMOTE_SSH_ALIAS" "cp ${REMOTE_COMPOSE_FILE} ${REMOTE_COMPOSE_FILE}.pre-ctfproxy.bak" \
    || die "failed to back up remote compose file"
RECREATE_SVCS=()
for i in "${ELIGIBLE_IDX[@]}"; do
    port_var="SVC_${i}_PORT"; port="${!port_var}"
    internal_var="SVC_${i}_INTERNAL"; internal="${!internal_var}"
    cs_var="SVC_${i}_COMPOSE_SVC"; compose_svc="${!cs_var}"
    ssh "$REMOTE_SSH_ALIAS" "sed -i.bak '/\"${port}:${internal}\"/d' ${REMOTE_COMPOSE_FILE}" \
        || die "failed removing port ${port}:${internal} from ${REMOTE_COMPOSE_FILE} (backup at ${REMOTE_COMPOSE_FILE}.pre-ctfproxy.bak if anything needs reverting)"
    ok "port line removed: ${port}:${internal} (compose service '$compose_svc')"
    [[ " ${RECREATE_SVCS[*]:-} " == *" ${compose_svc} "* ]] || RECREATE_SVCS+=("$compose_svc")
done

log "Recreating affected compose service(s) to release the ports (brief downtime now): ${RECREATE_SVCS[*]}"
REMOTE_COMPOSE_DIR=$(dirname "$REMOTE_COMPOSE_FILE")
ssh "$REMOTE_SSH_ALIAS" "cd ${REMOTE_COMPOSE_DIR} && docker compose up -d ${RECREATE_SVCS[*]}" \
    || die "failed to recreate ${RECREATE_SVCS[*]} -- ports may now be unbound with nothing serving them; restore from ${REMOTE_COMPOSE_FILE}.pre-ctfproxy.bak if needed"

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

log "Verifying real traffic still gets through on each service's port..."
sleep 2
for i in "${ELIGIBLE_IDX[@]}"; do
    port_var="SVC_${i}_PORT"; port="${!port_var}"
    name_var="SVC_${i}_NAME"; svc_name="${!name_var}"
    HTTP_CODE=$(ssh "$REMOTE_SSH_ALIAS" "curl -s -o /dev/null -w '%{http_code}' --max-time 8 http://localhost:${port}/" 2>/dev/null)
    if [[ "$HTTP_CODE" =~ ^[0-9]+$ ]] && [[ "$HTTP_CODE" != "000" ]]; then
        ok "'$svc_name' (port $port): ctf_proxy is up and passing traffic through (HTTP $HTTP_CODE)"
    else
        TCP_OK=$(ssh "$REMOTE_SSH_ALIAS" "timeout 5 bash -c 'echo > /dev/tcp/localhost/${port}' 2>/dev/null && echo yes || echo no")
        if [[ "$TCP_OK" == "yes" ]]; then
            ok "'$svc_name' (port $port): ctf_proxy is up and accepting TCP connections (non-HTTP service, no HTTP code to check)"
        else
            warn "'$svc_name' (port $port): no clean response (HTTP_CODE='$HTTP_CODE') -- verify manually: curl/nc <vulnbox-ip>:${port}"
        fi
    fi
done

log "filter_modules/<service>/<service>_in.py on the remote starts EMPTY (pass-through only) for each service -- write real rules there once you've confirmed an attack pattern via Tulip/Dashboard."
