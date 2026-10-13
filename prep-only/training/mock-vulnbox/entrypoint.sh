#!/bin/sh
set -e
# Compliance hard guard (Item D): this is prep-only/training code (rehearsal
# fixture, not real defense) -- bringup.sh never starts it when MODE=contest,
# but refuse here too in case someone starts it by hand anyway.
if [ "$MODE" = "contest" ]; then
    echo "FATAL: mock-vulnbox is prep-only/training and must not run with MODE=contest. Refusing to start." >&2
    exit 1
fi
python3 svc2_tcp.py &
exec python3 svc1_http.py
