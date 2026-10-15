#!/usr/bin/env bash
# Owned capture session; called by capture_pull.py on the vulnbox via sudo.
#
# Does NOT use tcpdump's "-z postrotate-command": that makes tcpdump itself
# execlp() an external script on every rotation, and a stock Ubuntu/Debian
# install ships an enforcing AppArmor profile for /usr/sbin/tcpdump that
# denies exactly that (a known hardening measure against -z being a classic
# root-exec vector) -- confirmed live against a real practice vulnbox:
# tcpdump's own capture.log showed "execlp(...) failed: Permission denied"
# on every single rotation, even though the script itself had correct
# permissions and ran fine when invoked directly. Silently dropped every
# closed file (done/ stayed empty forever -- capture_pull.py never had
# anything to pull), with zero errors surfaced anywhere else. A real
# contest vulnbox is likely to ship the same stock AppArmor profile, so
# this isn't a one-off: assume -z will not work and don't depend on it.
#
# Equivalent completion detection instead: tcpdump only ever writes to the
# single NEWEST file in open/ (filenames are zero-padded timestamps, so
# lexicographic order == chronological order) -- every OTHER file already
# rotated away from and is safe to move, no exec involved, just this
# already-running script's own builtins.
set -uo pipefail
dir=$1; iface=$2; rotation=$3; max_kb=$4; filter=$5
mkdir -p "$dir/open" "$dir/done"
echo "$$" > "$dir/runner.pid"
close_rotated() {
    # Every file except the lexicographically-newest one in open/ has
    # already been rotated away from by tcpdump -- safe to move.
    local newest
    newest=$(ls -1 "$dir/open" 2>/dev/null | sort | tail -1)
    for file in "$dir/open/"*.pcap; do
        [ -e "$file" ] || continue
        [ "$(basename "$file")" = "$newest" ] && continue
        mv "$file" "$dir/done/" 2>/dev/null || true
    done
}
tcpdump -Z root -i "$iface" -s 0 -U -G "$rotation" \
    -w "$dir/open/cap_%Y%m%d_%H%M%S.pcap" "$filter" &
cap=$!
echo "$cap" > "$dir/tcpdump.pid"
finish() {
    trap - TERM INT EXIT
    kill -INT "$cap" 2>/dev/null || true
    wait "$cap" 2>/dev/null || true
    # After wait, tcpdump is gone -- every file still in open/, including
    # the one it was writing when killed, is now closed and safe to move.
    for file in "$dir/open/"*.pcap; do
        [ -f "$file" ] && mv "$file" "$dir/done/" 2>/dev/null || true
    done
    chmod -R a+rX "$dir/done"
    touch "$dir/stopped"
}
trap 'finish; exit 0' TERM INT
trap finish EXIT
while kill -0 "$cap" 2>/dev/null; do
    close_rotated
    used=$(du -sk "$dir" | cut -f1)
    available=$(df -Pk "$dir" | awk 'NR==2 {print $4}')
    if (( used >= max_kb || available < 262144 )); then
        echo 'spool_limit: capture stopped; captured files preserved' > "$dir/reason"
        break
    fi
    sleep 2
done
