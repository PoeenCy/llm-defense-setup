#!/usr/bin/env bash
# vulnbox-deploy/os-watchdog-agent.sh
# OS Integrity Watchdog — runs ON THE VULNBOX (not monitor).
# Monitors: new processes, unexpected outbound connections,
#           sensitive file changes, new cron entries, authorized_keys drift,
#           binary hash drift vs. snapshot.
#
# Deploy via: bash vulnbox-deploy/deploy-os-watchdog.sh
# Or manually: scp this file to vulnbox, then run it there.
#
# Reports to monitor via HTTP POST to honeytoken/watchdog endpoint.

set -euo pipefail

MONITOR_IP="${MONITOR_IP:-10.0.0.50}"
MONITOR_PORT="${MONITOR_PORT:-9999}"
REPORT_URL="http://${MONITOR_IP}:${MONITOR_PORT}/watchdog/os-report"
SNAPSHOT_DIR="${SNAPSHOT_DIR:-/var/ctf-watchdog}"
CHECK_INTERVAL="${CHECK_INTERVAL:-10}"
BASELINE="${SNAPSHOT_DIR}/baseline"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "[$(date +%H:%M:%S)] ${CYAN}[OS-WD]${NC} $*"; }
alert(){ echo -e "[$(date +%H:%M:%S)] ${RED}[ALERT]${NC} $*"; }

mkdir -p "$SNAPSHOT_DIR"

# ── Create snapshot ────────────────────────────────────────────
create_snapshot() {
    log "Creating baseline snapshot in $BASELINE..."
    mkdir -p "$BASELINE"

    # Listening ports
    ss -tlnup 2>/dev/null > "$BASELINE/listening_ports.txt" || \
    netstat -tlnup 2>/dev/null > "$BASELINE/listening_ports.txt" || true

    # Running processes
    ps aux --no-headers > "$BASELINE/processes.txt" 2>/dev/null || true

    # Crontabs
    for user in $(cut -f1 -d: /etc/passwd); do
        crontab -l -u "$user" 2>/dev/null > "$BASELINE/cron_${user}.txt" || true
    done
    ls /etc/cron* /var/spool/cron/ 2>/dev/null | sort > "$BASELINE/cron_paths.txt" || true

    # authorized_keys
    find /root /home -name "authorized_keys" -exec md5sum {} \; 2>/dev/null > "$BASELINE/authorized_keys.md5" || true

    # Binary hashes for service executables
    find /usr/local/bin /usr/bin /bin -maxdepth 1 -type f -executable 2>/dev/null \
        | xargs md5sum 2>/dev/null > "$BASELINE/binary_hashes.md5" || true

    # Setuid binaries
    find / -perm -4000 -type f 2>/dev/null | sort > "$BASELINE/setuid_files.txt" || true

    # /etc/passwd and /etc/shadow hashes
    md5sum /etc/passwd /etc/shadow 2>/dev/null > "$BASELINE/etc_hashes.md5" || true

    log "Snapshot created at $BASELINE"
}

# ── Send alert to monitor ─────────────────────────────────────
send_alert() {
    local type="$1"
    local message="$2"
    local detail="${3:-}"

    local payload="{\"type\":\"os-watchdog\",\"alert_type\":\"$type\",\"message\":\"$message\",\"detail\":\"$detail\",\"vulnbox\":\"$(hostname)\"}"

    curl -s -X POST "$REPORT_URL" \
         -H "Content-Type: application/json" \
         -d "$payload" \
         --connect-timeout 3 \
         --max-time 5 2>/dev/null || true

    alert "[$type] $message"
    [[ -n "$detail" ]] && echo "  Detail: $detail"
}

# ── Check: new processes ──────────────────────────────────────
check_new_processes() {
    local current
    current="$(ps aux --no-headers 2>/dev/null || true)"
    local baseline="$BASELINE/processes.txt"
    [[ -f "$baseline" ]] || return

    # Compare by command columns (cols 11+)
    local new_procs
    new_procs=$(diff <(awk '{$1=$2=$3=$4=$5=$6=$7=$8=$9=$10=""; print}' "$baseline" | sort) \
                     <(echo "$current" | awk '{$1=$2=$3=$4=$5=$6=$7=$8=$9=$10=""; print}' | sort) \
                | grep '^>' | grep -v grep | head -5 || true)

    if [[ -n "$new_procs" ]]; then
        send_alert "new-process" "New process(es) detected" "${new_procs//\"/\'}"
    fi
}

# ── Check: unexpected outbound connections ─────────────────────
check_outbound() {
    # Flag connections to non-LAN, non-gameserver destinations
    local outbound
    outbound=$(ss -tnp 2>/dev/null | grep ESTAB | grep -v ':22 ' | grep -v '127.0.0.1' || true)
    if [[ -n "$outbound" ]]; then
        local suspicious
        suspicious=$(echo "$outbound" | grep -v '10\.' | grep -v '192\.168\.' | grep -v '172\.1[6-9]\.' | head -3 || true)
        if [[ -n "$suspicious" ]]; then
            send_alert "suspicious-outbound" "Unexpected outbound connection" "${suspicious//\"/\'}"
        fi
    fi
}

# ── Check: new cron entries ────────────────────────────────────
check_cron() {
    for user in $(cut -f1 -d: /etc/passwd); do
        local current_cron
        current_cron=$(crontab -l -u "$user" 2>/dev/null || true)
        local baseline_file="$BASELINE/cron_${user}.txt"
        local baseline_cron
        baseline_cron=$(cat "$baseline_file" 2>/dev/null || true)

        if [[ "$current_cron" != "$baseline_cron" ]]; then
            send_alert "cron-change" "Crontab modified for user: $user" "$(diff <(echo "$baseline_cron") <(echo "$current_cron") | head -5 | tr '\n' '|')"
            echo "$current_cron" > "$baseline_file"
        fi
    done

    # Check for new files in cron dirs
    local current_paths
    current_paths=$(ls /etc/cron* /var/spool/cron/ 2>/dev/null | sort || true)
    local baseline_paths
    baseline_paths=$(cat "$BASELINE/cron_paths.txt" 2>/dev/null || true)
    if [[ "$current_paths" != "$baseline_paths" ]]; then
        send_alert "cron-new-file" "New file in cron directory" "$(diff <(echo "$baseline_paths") <(echo "$current_paths") | head -3)"
        echo "$current_paths" > "$BASELINE/cron_paths.txt"
    fi
}

# ── Check: authorized_keys drift ──────────────────────────────
check_authorized_keys() {
    local current
    current=$(find /root /home -name "authorized_keys" -exec md5sum {} \; 2>/dev/null || true)
    local baseline
    baseline=$(cat "$BASELINE/authorized_keys.md5" 2>/dev/null || true)
    if [[ "$current" != "$baseline" ]]; then
        send_alert "authorized-keys-change" "authorized_keys file modified!" "$(diff <(echo "$baseline") <(echo "$current") | head -5)"
        echo "$current" > "$BASELINE/authorized_keys.md5"
    fi
}

# ── Check: binary hash drift ───────────────────────────────────
check_binary_hashes() {
    local current
    current=$(find /usr/local/bin /usr/bin /bin -maxdepth 1 -type f -executable 2>/dev/null \
              | xargs md5sum 2>/dev/null || true)
    local baseline
    baseline=$(cat "$BASELINE/binary_hashes.md5" 2>/dev/null || true)
    if [[ "$current" != "$baseline" ]]; then
        local changed
        changed=$(diff <(echo "$baseline") <(echo "$current") | grep '^[<>]' | head -5 || true)
        if [[ -n "$changed" ]]; then
            send_alert "binary-hash-drift" "Binary file hash changed!" "${changed//\"/\'}"
            echo "$current" > "$BASELINE/binary_hashes.md5"
        fi
    fi
}

# ── Check: /etc/passwd and /etc/shadow ────────────────────────
check_etc() {
    local current
    current=$(md5sum /etc/passwd /etc/shadow 2>/dev/null || true)
    local baseline
    baseline=$(cat "$BASELINE/etc_hashes.md5" 2>/dev/null || true)
    if [[ "$current" != "$baseline" ]]; then
        send_alert "etc-passwd-changed" "/etc/passwd or /etc/shadow modified!" ""
        echo "$current" > "$BASELINE/etc_hashes.md5"
    fi
}

# ── Check: new SUID binaries ──────────────────────────────────
check_suid() {
    local current
    current=$(find / -perm -4000 -type f 2>/dev/null | sort || true)
    local baseline
    baseline=$(cat "$BASELINE/setuid_files.txt" 2>/dev/null || true)
    if [[ "$current" != "$baseline" ]]; then
        local new_suid
        new_suid=$(diff <(echo "$baseline") <(echo "$current") | grep '^>' | head -5 || true)
        if [[ -n "$new_suid" ]]; then
            send_alert "new-suid-binary" "New SUID binary found!" "${new_suid//\"/\'}"
        fi
        echo "$current" > "$BASELINE/setuid_files.txt"
    fi
}

# ── Snapshot diff command (called manually) ────────────────────
run_diff() {
    log "=== Snapshot diff vs baseline ==="
    echo ""
    for f in "$BASELINE"/*.txt "$BASELINE"/*.md5; do
        [[ -f "$f" ]] || continue
        echo "--- $f ---"
        case "$f" in
            *processes*)   diff "$f" <(ps aux --no-headers) 2>/dev/null | head -10 || true ;;
            *ports*)       diff "$f" <(ss -tlnup 2>/dev/null) 2>/dev/null | head -10 || true ;;
            *binary_hash*) diff "$f" <(find /usr/local/bin /usr/bin /bin -maxdepth 1 -type f -executable | xargs md5sum 2>/dev/null) 2>/dev/null | head -10 || true ;;
            *auth_key*)    diff "$f" <(find /root /home -name "authorized_keys" -exec md5sum {} \; 2>/dev/null) 2>/dev/null | head -5 || true ;;
        esac
        echo ""
    done
}

# ── Main ──────────────────────────────────────────────────────
case "${1:-run}" in
    snapshot) create_snapshot ;;
    diff)     run_diff ;;
    run)
        # Create snapshot if none exists
        [[ -f "$BASELINE/processes.txt" ]] || create_snapshot

        log "OS Watchdog running. Check interval: ${CHECK_INTERVAL}s"
        log "Reporting to: $REPORT_URL"

        # Send heartbeat
        send_alert "heartbeat" "OS watchdog started on $(hostname)" "$(uname -a | head -c 100)"

        while true; do
            check_new_processes
            check_outbound
            check_cron
            check_authorized_keys
            check_binary_hashes
            check_etc
            sleep "$CHECK_INTERVAL"
        done
        ;;
    *)
        echo "Usage: $0 {run|snapshot|diff}"
        exit 1
        ;;
esac
