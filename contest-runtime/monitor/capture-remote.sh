#!/usr/bin/env bash
# Owned capture session; called by capture_pull.py on the vulnbox via sudo.
set -uo pipefail
dir=$1; iface=$2; rotation=$3; max_kb=$4; filter=$5
mkdir -p "$dir/open" "$dir/done"
echo "$$" > "$dir/runner.pid"
cat > "$dir/closed.sh" <<'CLOSED'
#!/usr/bin/env bash
set -eu
file=$1
base=$(dirname "$file")
mv "$file" "$base/../done/"
CLOSED
chmod 755 "$dir/closed.sh"
tcpdump -Z root -i "$iface" -s 0 -U -G "$rotation" -z "$dir/closed.sh" \
    -w "$dir/open/cap_%Y%m%d_%H%M%S.pcap" "$filter" &
cap=$!
echo "$cap" > "$dir/tcpdump.pid"
finish() {
    trap - TERM INT EXIT
    kill -INT "$cap" 2>/dev/null || true
    wait "$cap" 2>/dev/null || true
    # Rotation callbacks only see closed files; after wait the final file is
    # closed too, including the case where tcpdump stopped before rotating.
    for file in "$dir/open/"*.pcap; do
        [ -f "$file" ] && mv "$file" "$dir/done/" 2>/dev/null || true
    done
    chmod -R a+rX "$dir/done"
    touch "$dir/stopped"
}
trap 'finish; exit 0' TERM INT
trap finish EXIT
while kill -0 "$cap" 2>/dev/null; do
    used=$(du -sk "$dir" | cut -f1)
    available=$(df -Pk "$dir" | awk 'NR==2 {print $4}')
    if (( used >= max_kb || available < 262144 )); then
        echo 'spool_limit: capture stopped; captured files preserved' > "$dir/reason"
        break
    fi
    sleep 2
done
