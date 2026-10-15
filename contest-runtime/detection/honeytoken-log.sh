#!/usr/bin/env bash
# Local, unprivileged alert log for the honeytoken trap -- same append-only
# JSONL + monotonic-id + size-cap pattern as os-watchdog-agent.sh's
# alerts.jsonl, used here for the same reason: this vulnbox's VPN only
# routes monitor->vulnbox, not the reverse, so the trap's own curl/urlopen
# push (still attempted, kept as a fallback) silently goes nowhere. The
# monitor pulls instead (see hostagent/honeytoken_pull.py).
#
# Lives in the plain ssh user's home, not /usr/local/bin -- both callers
# (flag-server.sh, the inotify watcher loop in deploy-honeytoken.sh) already
# run unprivileged, so this never needs sudo on either the write or the
# read side, unlike os-watchdog's (which is root-owned because its agent
# runs under systemd as root).
set -uo pipefail
DIR="${HOME}/.ctf-honeytoken"
LOG="$DIR/alerts.jsonl"
SEQ="$DIR/seq"
MAX_LINES=2000
mkdir -p "$DIR"

json_str() {
    local s="$1"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"; s="${s//$'\r'/\\r}"
    printf '"%s"' "$s"
}

log_alert() {
    local kind="${1:?usage: $0 log <kind> <detail> [src_ip]}" detail="${2:-}" src="${3:-}"
    local seq
    seq=$(( $(cat "$SEQ" 2>/dev/null || echo 0) + 1 ))
    echo "$seq" > "$SEQ"
    echo "{\"id\":${seq},\"ts\":$(date +%s),\"kind\":$(json_str "$kind"),\"detail\":$(json_str "$detail"),\"src_ip\":$(json_str "$src"),\"vulnbox\":$(json_str "$(hostname)")}" >> "$LOG"
    if (( $(wc -l < "$LOG" 2>/dev/null || echo 0) > MAX_LINES )); then
        tail -n "$MAX_LINES" "$LOG" > "${LOG}.tmp" && mv "${LOG}.tmp" "$LOG"
    fi
}

alerts_since() {
    local since="${1:-0}" line id
    [[ -f "$LOG" ]] || return 0
    while IFS= read -r line; do
        # Lines come from two different writers (this script's own
        # log_alert, and flag-server.sh's Python json.dumps) -- Python
        # puts a space after every ":", this script doesn't. Strip all
        # whitespace from the extracted id so either format parses.
        id="${line#*\"id\":}"; id="${id%%,*}"; id="${id//[[:space:]]/}"
        [[ "$id" =~ ^[0-9]+$ ]] && (( id > since )) && echo "$line"
    done < "$LOG"
}

case "${1:-}" in
    log)   log_alert "${2:-}" "${3:-}" "${4:-}" ;;
    since) alerts_since "${2:-0}" ;;
    *)     echo "Usage: $0 {log <kind> <detail> [src_ip]|since <id>}"; exit 1 ;;
esac
