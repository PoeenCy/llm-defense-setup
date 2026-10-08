#!/usr/bin/env python3
"""
watchdog_service.py — CTF Monitor Hub: SLA Watchdog (Item 7a)

Runs on the MONITOR machine. Probes vulnbox services every POLL_INTERVAL seconds.
Alerts on:
  - Connection refused / timeout  → service DOWN
  - Response time > SLOW_THRESHOLD → service SLOW
  - Recovery after DOWN → service RESTORED

Reads services from services.json. All alerts go to Redis "alerts" list.
"""
import json
import logging
import os
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import redis

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [WATCHDOG] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("watchdog")

# ── Config ──────────────────────────────────────────────────────────────────
REDIS_HOST     = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT     = int(os.environ.get("REDIS_PORT", 6379))
VULNBOX_IP     = os.environ.get("VULNBOX_IP", "10.0.0.2")
POLL_INTERVAL  = float(os.environ.get("POLL_INTERVAL_SEC", "3"))
TIMEOUT_SEC    = float(os.environ.get("TIMEOUT_SEC", "4"))
SLOW_THRESHOLD = float(os.environ.get("SLOW_THRESHOLD_SEC", "2"))

CONFIG_PATH = Path(os.environ.get("CONFIG", "/app/services.json"))
if CONFIG_PATH.exists():
    with open(CONFIG_PATH) as f:
        CFG = json.load(f)
else:
    CFG = {}

SERVICES = CFG.get("services", [])
if not SERVICES:
    log.warning("No services in config — watchdog has nothing to poll")

def get_redis():
    while True:
        try:
            r = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
            r.ping()
            return r
        except Exception:
            time.sleep(2)

def push_alert(rdb: redis.Redis, alert: dict):
    alert.setdefault("ts", datetime.now(timezone.utc).isoformat())
    alert["source"] = "watchdog"
    payload = json.dumps(alert)
    rdb.lpush("alerts", payload)
    rdb.ltrim("alerts", 0, 9999)
    rdb.publish("alerts_channel", payload)
    log.warning("🚨 WATCHDOG ALERT: %s", alert.get("message", ""))

def push_status(rdb: redis.Redis, key: str, status: dict):
    """Update service status in Redis hash."""
    status["ts"] = datetime.now(timezone.utc).isoformat()
    rdb.hset("watchdog_status", key, json.dumps(status))

def probe_tcp(host: str, port: int, timeout: float) -> tuple[str, float]:
    """
    Attempt TCP connection to host:port.
    Returns (status, latency_ms) where status is 'up', 'down', 'slow', or 'timeout'.
    """
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            latency = (time.monotonic() - start) * 1000
            return "up", latency
    except socket.timeout:
        return "timeout", timeout * 1000
    except ConnectionRefusedError:
        return "refused", (time.monotonic() - start) * 1000
    except OSError as e:
        return f"error:{e}", (time.monotonic() - start) * 1000

class ServiceWatcher(threading.Thread):
    """Polls a single service and emits alerts on state changes."""
    daemon = True

    def __init__(self, svc: dict, rdb: redis.Redis):
        super().__init__(name=f"Watcher-{svc['name']}")
        self.svc       = svc
        self._rdb      = rdb
        self._last_state = "unknown"
        self._down_since: float | None = None

    def run(self):
        name  = self.svc["name"]
        port  = self.svc["port"]
        proto = self.svc.get("proto", "tcp")

        log.info("Watching %s on %s:%d/%s every %.1fs",
                 name, VULNBOX_IP, port, proto, POLL_INTERVAL)

        while True:
            if proto == "tcp":
                status, latency_ms = probe_tcp(VULNBOX_IP, port, TIMEOUT_SEC)
            else:
                # UDP: just attempt a connect (best-effort)
                status, latency_ms = probe_tcp(VULNBOX_IP, port, TIMEOUT_SEC)

            state = "up"
            if status in ("timeout", "refused") or status.startswith("error"):
                state = "down"
            elif latency_ms > SLOW_THRESHOLD * 1000:
                state = "slow"

            push_status(self._rdb, f"{name}:{port}", {
                "name": name, "port": port, "proto": proto,
                "state": state, "latency_ms": round(latency_ms, 1),
                "status_detail": status,
            })

            if state == "down" and self._last_state != "down":
                self._down_since = time.time()
                push_alert(self._rdb, {
                    "type": "sla-down",
                    "confidence": "HIGH",
                    "message": f"SERVICE DOWN: {name} on {VULNBOX_IP}:{port}/{proto} — {status}",
                    "service": name,
                    "port": port,
                    "vulnbox_ip": VULNBOX_IP,
                    "latency_ms": round(latency_ms, 1),
                })
            elif state == "slow" and self._last_state == "up":
                push_alert(self._rdb, {
                    "type": "sla-slow",
                    "confidence": "MEDIUM",
                    "message": f"SERVICE SLOW: {name} on {VULNBOX_IP}:{port} — {latency_ms:.0f}ms",
                    "service": name,
                    "port": port,
                    "latency_ms": round(latency_ms, 1),
                })
            elif state == "up" and self._last_state == "down":
                downtime = (time.time() - self._down_since) if self._down_since else 0
                push_alert(self._rdb, {
                    "type": "sla-restored",
                    "confidence": "INFO",
                    "message": f"SERVICE RESTORED: {name} on {VULNBOX_IP}:{port} after {downtime:.0f}s down",
                    "service": name,
                    "port": port,
                    "downtime_sec": round(downtime, 1),
                    "latency_ms": round(latency_ms, 1),
                })
                self._down_since = None

            self._last_state = state
            time.sleep(POLL_INTERVAL)

def main():
    log.info("SLA Watchdog starting. Vulnbox: %s", VULNBOX_IP)
    log.info("Polling %d service(s) every %.1fs", len(SERVICES), POLL_INTERVAL)
    rdb = get_redis()

    threads = []
    for svc in SERVICES:
        w = ServiceWatcher(svc, rdb)
        w.start()
        threads.append(w)

    if not threads:
        log.warning("No services to watch. Add services to services.json.")
        # Keep alive for health check
        while True:
            time.sleep(60)

    # Health check endpoint
    import http.server, socketserver

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/health":
                self.send_response(200)
                self.end_headers()
                status = rdb.hgetall("watchdog_status")
                self.wfile.write(json.dumps({
                    "status": "ok",
                    "service": "watchdog",
                    "services": {k: json.loads(v) for k, v in status.items()},
                }).encode())
        def log_message(self, *args): pass

    with socketserver.TCPServer(("0.0.0.0", 5003), Handler) as httpd:
        log.info("Watchdog health check on :5003/health")
        httpd.serve_forever()

if __name__ == "__main__":
    main()
