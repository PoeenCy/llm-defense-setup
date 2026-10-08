#!/bin/sh
set -e
python3 svc2_tcp.py &
exec python3 svc1_http.py
