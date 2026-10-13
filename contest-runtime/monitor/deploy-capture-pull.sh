#!/usr/bin/env bash
# deploy-capture-pull.sh — capture + pull loop for a vulnbox we only reach via
# an admin SSH alias (no pcap-broker, no agent install needed on the target).
#
# Design choice that makes this adapt to a target we haven't seen before:
# capture happens on the EXTERNAL interface (pre-NAT), filtered by the
# service's PUBLIC port. That means tcpdump and Tulip both see the same port
# number the checker/attacker actually connects to -- no need to know a
# docker bridge name, no NAT-induced BPF mismatch (public port vs internal
# container port), and it works identically whether the target is Docker,
# bare-metal, or anything else sitting behind that interface. Only fall back
# to vulnbox.docker_bridge if the external interface genuinely isn't where
# the public IP lives (rare -- e.g. capture must happen inside a network
# namespace docker created, with no visibility into the host's own NIC).
#
# Needs in services.json: vulnbox.capture_ssh_alias, services[].port
# Optional: vulnbox.capture_iface ("auto" default, or an explicit name),
#           vulnbox.docker_bridge (override, takes priority over capture_iface
#           if set), services[].capture_port (escape hatch for the NAT case
#           above, if you ever do have to capture downstream of a NAT)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="${SCRIPT_DIR}/../config/services.json"
TRAFFIC_DIR="${SCRIPT_DIR}/../../traffic"
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${CYAN}[CAPTURE-PULL]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC}            $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}          $*"; }
die()  { echo -e "${RED}[FATAL]${NC}         $*"; exit 1; }

BACKGROUND=false
[[ "${1:-}" == "--background" ]] && BACKGROUND=true

[[ -f "$CONFIG" ]] || die "services.json not found"
ALIAS=$(python3 -c "import json; print(json.load(open('$CONFIG'))['vulnbox']['capture_ssh_alias'])")
BRIDGE=$(python3 -c "import json; print(json.load(open('$CONFIG'))['vulnbox'].get('docker_bridge') or '')")
IFACE_CFG=$(python3 -c "import json; print(json.load(open('$CONFIG'))['vulnbox'].get('capture_iface','auto'))")
BPF=$(python3 -c "
import json
d = json.load(open('$CONFIG'))
ports = [str(s.get('capture_port', s['port'])) for s in d['services']]
print(' or '.join(f'port {p}' for p in ports))
")
REMOTE_DIR="/tmp/ctf-capture-$$"

[[ -n "$ALIAS" ]] || die "vulnbox.capture_ssh_alias not set in services.json"
[[ -n "$BPF" ]] || die "no services[] defined in services.json to build a capture filter from"

log "Checking SSH reachability: $ALIAS"
timeout 10 ssh -o ConnectTimeout=8 -o BatchMode=yes "$ALIAS" "echo OK" >/dev/null 2>&1 \
    || die "ssh $ALIAS unreachable (timed out or refused). If this hangs at banner exchange, the remote VM is probably stopped -- that must be fixed outside this script (Azure portal/CLI etc), not here."
ok "ssh $ALIAS reachable"

# Packet capture needs root on the remote (tcpdump opening a raw socket) --
# this is an OS-level requirement, there is no software workaround. Check it
# explicitly now so the failure is a clear one-line message instead of a
# cryptic error buried in /tmp/tcpdump.log on the remote.
log "Checking for root/sudo on $ALIAS (required for tcpdump)"
if ssh "$ALIAS" "sudo -n true" >/dev/null 2>&1; then
    ok "passwordless sudo available on $ALIAS"
elif ssh "$ALIAS" "test \$(id -u) -eq 0" >/dev/null 2>&1; then
    ok "already root on $ALIAS"
else
    die "no root/passwordless-sudo on $ALIAS -- tcpdump cannot open a raw socket without it, and there is no way around this in software. Ask whoever controls $ALIAS to either grant sudo, or run tcpdump for you and hand you the pcap files directly into $TRAFFIC_DIR/ (Tulip/Suricata/detection don't care who produced them, only that .pcap files land in that directory)."
fi

mkdir -p "$TRAFFIC_DIR"

# ── Pick the capture interface ──────────────────────────────────────────
if [[ -n "$BRIDGE" ]]; then
    IFACE="$BRIDGE"
    log "Using configured docker_bridge override: $IFACE"
elif [[ "$IFACE_CFG" == "auto" ]]; then
    IFACE=$(ssh "$ALIAS" "ip route show default 2>/dev/null | awk '/default/ {print \$5; exit}'")
    [[ -n "$IFACE" ]] || die "could not auto-detect the external interface on $ALIAS (no default route?). Set vulnbox.capture_iface explicitly in services.json."
    log "Auto-detected external interface on $ALIAS: $IFACE"
else
    IFACE="$IFACE_CFG"
    log "Using configured capture_iface: $IFACE"
fi

log "Starting tcpdump on $ALIAS (iface=$IFACE, filter='$BPF'), writing to $REMOTE_DIR (rotating every 30s)"
# `ssh -f`: forks ssh into the background right after auth, BEFORE running the
# command, so the local ssh client returns immediately -- it never waits for
# the remote command's file descriptors to close. Plain `nohup ... & disown`
# is not enough here: tcpdump (even fully redirected) can keep the SSH
# channel from reaching EOF, which hangs this call indefinitely (seen in
# practice -- the whole pipeline stalls at this one line). -f sidesteps that
# class of hang entirely regardless of what the remote command does.
ssh -f "$ALIAS" "mkdir -p $REMOTE_DIR && nohup sudo tcpdump -Z root -i $IFACE -w $REMOTE_DIR/cap_%Y%m%d_%H%M%S.pcap -G 30 '$BPF' </dev/null >/tmp/tcpdump.log 2>&1 & disown" \
    || die "Failed to launch tcpdump on $ALIAS (ssh -f itself failed -- auth/connection problem, check above)."
sleep 2
ssh "$ALIAS" "pgrep -f \"tcpdump -Z root -i $IFACE\" >/dev/null" \
    || die "tcpdump did not start on $ALIAS. Check /tmp/tcpdump.log there for details (common cause: iface name wrong)."
ok "tcpdump running remotely in $REMOTE_DIR, filtering at capture time (same filter Tulip will also see traffic for -- no post-hoc NAT mismatch possible)"

PULL_LOOP() {
    # --remove-source-files: a pcap is deleted on the vulnbox only after rsync
    # has copied it here completely, so the vulnbox disk never fills up (a full
    # disk there would take the services down = SLA loss). Local copies are
    # aged out by host_agent (services.json -> retention).
    log "Pull loop: rsync every 15s into $TRAFFIC_DIR (only files tcpdump has finished writing; moved, not copied)"
    while true; do
        STABLE_FILES=$(ssh "$ALIAS" "find $REMOTE_DIR -name '*.pcap' -mmin +0.6" 2>/dev/null)
        if [[ -n "$STABLE_FILES" ]]; then
            rsync -az --remove-source-files -e "ssh" --files-from=<(echo "$STABLE_FILES" | sed "s|^$REMOTE_DIR/||") \
                "$ALIAS:$REMOTE_DIR/" "$TRAFFIC_DIR/" 2>/dev/null || true
        fi
        sleep 15
    done
}

if [[ "$BACKGROUND" == true ]]; then
    PIDFILE="${SCRIPT_DIR}/.capture-pull.pid"
    LOGFILE="${SCRIPT_DIR}/.capture-pull.log"
    setsid nohup bash -c "$(declare -f log PULL_LOOP); ALIAS='$ALIAS'; REMOTE_DIR='$REMOTE_DIR'; TRAFFIC_DIR='$TRAFFIC_DIR'; PULL_LOOP" >"$LOGFILE" 2>&1 &
    echo $! > "$PIDFILE"
    ok "Pull loop backgrounded (pid $(cat "$PIDFILE"), log: $LOGFILE). Stop it with: kill \$(cat $PIDFILE)"
    log "Remote capture dir on $ALIAS: $REMOTE_DIR (clean up manually when done: ssh $ALIAS rm -rf $REMOTE_DIR)"
else
    log "Remote capture dir: $REMOTE_DIR (clean it up manually on $ALIAS when done: rm -rf $REMOTE_DIR)"
    log "Running in foreground -- Ctrl+C to stop (use --background to daemonize instead)"
    PULL_LOOP
fi
