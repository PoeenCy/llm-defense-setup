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
# One-time baseline diff can't tell the organizer's checker legitimately
# SSHing in to plant/verify a flag apart from a real intrusion -- both just
# look like "something not in baseline". Rather than guess at the checker's
# exact process/cron/IP signature in advance (usually not published before
# the contest), a human who sees an alert and recognizes it as the checker
# can mark that exact (type, substring-of-detail) pair here so it stops
# repeating every CHECK_INTERVAL -- any genuinely NEW/different alert still
# fires normally. One line per entry: "type|pattern".
ALLOWLIST="${SNAPSHOT_DIR}/allowlist.txt"

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
# JSON string escaping in pure bash (process command lines and diff output
# contain quotes, backslashes and newlines — unescaped they broke the JSON and
# the report was silently rejected).
json_str() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"; s="${s//$'\r'/\\r}"; s="${s//$'\t'/\\t}"
    s="$(printf '%s' "$s" | tr -d '\000-\010\013\014\016-\037')"
    printf '"%s"' "$s"
}

# ── Allowlist: suppress an alert type+detail a human already confirmed
#    is the organizer's checker (or otherwise known-good), not an intrusion ──
is_allowlisted() {
    local type="$1" text="$2"
    [[ -s "$ALLOWLIST" ]] || return 1
    local a_type a_pattern
    while IFS='|' read -r a_type a_pattern; do
        [[ -z "$a_type" ]] && continue
        if [[ "$a_type" == "$type" && -n "$a_pattern" && "$text" == *"$a_pattern"* ]]; then
            return 0
        fi
    done < "$ALLOWLIST"
    return 1
}

send_alert() {
    local type="$1"
    local message="$2"
    local detail="${3:-}"

    if is_allowlisted "$type" "${message} ${detail}"; then
        log "[$type] suppressed (allowlisted, not reported to monitor): $message"
        return 0
    fi

    local payload="{\"type\":\"os-watchdog\",\"alert_type\":$(json_str "$type"),\"message\":$(json_str "$message"),\"detail\":$(json_str "$detail"),\"vulnbox\":$(json_str "$(hostname)")}"

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

# ── Allowlist management (called remotely via SSH by host_agent) ──────
allow_add() {
    local a_type="${1:?usage: $0 allow <type> <pattern>}"
    local a_pattern="${2:?usage: $0 allow <type> <pattern>}"
    # '|' is the field separator and newlines would break the one-entry-per-
    # line format -- neither is meaningful to keep in a match pattern anyway.
    a_type="${a_type//$'\n'/ }"; a_type="${a_type//|/_}"
    a_pattern="${a_pattern//$'\n'/ }"; a_pattern="${a_pattern//|/_}"
    touch "$ALLOWLIST"
    echo "${a_type}|${a_pattern}" >> "$ALLOWLIST"
    log "Allowlisted: [$a_type] $a_pattern"
}

allow_remove() {
    local a_type="${1:?usage: $0 unallow <type> <pattern>}"
    local a_pattern="${2:?usage: $0 unallow <type> <pattern>}"
    [[ -f "$ALLOWLIST" ]] || return 0
    local tmp="${ALLOWLIST}.tmp"
    grep -vF "${a_type}|${a_pattern}" "$ALLOWLIST" > "$tmp" || true
    mv "$tmp" "$ALLOWLIST"
    log "Removed from allowlist: [$a_type] $a_pattern"
}

# ── Main ──────────────────────────────────────────────────────
case "${1:-run}" in
    snapshot)    create_snapshot ;;
    diff)        run_diff ;;
    allow)       allow_add "${2:-}" "${3:-}" ;;
    unallow)     allow_remove "${2:-}" "${3:-}" ;;
    allow-list)  cat "$ALLOWLIST" 2>/dev/null || true ;;
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
        echo "Usage: $0 {run|snapshot|diff|allow <type> <pattern>|unallow <type> <pattern>|allow-list}"
        exit 1
        ;;
esac
