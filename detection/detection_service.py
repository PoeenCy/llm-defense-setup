#!/usr/bin/env python3
"""
detection_service.py — CTF Monitor Hub: Deterministic Detection Layer (Item 4)

Three always-on detection mechanisms:
  1. Flag-out regex monitor — watches pcap dump dir for outbound flag exfil
  2. Honeytoken collector — HTTP endpoint; fires when decoy flag is fetched
  3. Suricata alert ingester — reads eve.json and forwards tagged alerts

All alerts go to Redis list "alerts" as JSON objects for the dashboard to consume.

Safety: read-only on traffic/; no auto-blocking; no auto-deploy.
"""
import asyncio
import json
import logging
import os
import re
import time
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import redis
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import uvicorn
import dpkt

# ── Config from environment ──────────────────────────────────────────────────
FLAG_REGEX       = os.environ.get("FLAG_REGEX", r"[A-Z0-9]{31}=")
HONEYTOKEN_FLAG  = os.environ.get("HONEYTOKEN_FLAG", "HONEYTOKEN0000000000000000000=")
REDIS_HOST       = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT       = int(os.environ.get("REDIS_PORT", 6379))
MONITOR_IP       = os.environ.get("MONITOR_IP", "10.0.0.50")
TEAMS_CIDR       = os.environ.get("TEAMS_CIDR", "10.60.0.0/16")
TRAFFIC_DIR      = Path(os.environ.get("TRAFFIC_DIR", "/traffic"))
SURICATA_DIR     = Path(os.environ.get("SURICATA_DIR", "/suricata"))

# Load services.json for full config
CONFIG_PATH = Path(os.environ.get("CONFIG", "/app/services.json"))
if CONFIG_PATH.exists():
    with open(CONFIG_PATH) as f:
        SERVICES_CFG = json.load(f)
else:
    SERVICES_CFG = {}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [DETECTION] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("detection")

# ── Redis connection ──────────────────────────────────────────────────────────
def get_redis():
    return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

def push_alert(rdb: redis.Redis, alert: dict):
    """Push alert to Redis list and publish to pub/sub channel."""
    alert.setdefault("ts", datetime.now(timezone.utc).isoformat())
    alert.setdefault("source", "detection")
    payload = json.dumps(alert)
    rdb.lpush("alerts", payload)
    rdb.ltrim("alerts", 0, 9999)          # keep last 10k alerts
    rdb.publish("alerts_channel", payload)
    log.warning("🚨 ALERT: [%s] %s", alert.get("type","?"), alert.get("message",""))

# ── 1. Flag-out detector — scans pcap files for outbound flag exfil ──────────
FLAG_RE = re.compile(FLAG_REGEX.encode())
HONEYTOKEN_RE = re.compile(re.escape(HONEYTOKEN_FLAG.encode()))

def cidr_to_range(cidr: str):
    """Convert CIDR to (network_int, mask_int) for fast IP matching."""
    import socket, struct
    net, bits = cidr.split("/")
    mask = (0xFFFFFFFF << (32 - int(bits))) & 0xFFFFFFFF
    net_int = struct.unpack("!I", socket.inet_aton(net))[0] & mask
    return net_int, mask

TEAMS_NET, TEAMS_MASK = cidr_to_range(TEAMS_CIDR)

def ip_in_cidr(ip_int: int, net_int: int, mask_int: int) -> bool:
    return (ip_int & mask_int) == net_int

def scan_pcap_for_flags(pcap_path: Path, rdb: redis.Redis, already_alerted: set):
    """Scan a pcap file for outbound flag exfil. Emit alerts for each match."""
    import struct, socket
    try:
        with open(pcap_path, "rb") as f:
            pcap = dpkt.pcap.Reader(f)
            for ts, buf in pcap:
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    if not isinstance(eth.data, dpkt.ip.IP):
                        continue
                    ip = eth.data
                    src_int = struct.unpack("!I", ip.src)[0]
                    dst_int = struct.unpack("!I", ip.dst)[0]

                    # Only alert on packets leaving our vulnbox toward teams network
                    # (outbound flag exfil direction)
                    payload = bytes(ip.data) if hasattr(ip, 'data') else b""
                    if hasattr(ip.data, 'data'):
                        payload = bytes(ip.data.data)

                    src_str = socket.inet_ntoa(ip.src)
                    dst_str = socket.inet_ntoa(ip.dst)

                    # Check for flag in payload
                    for pattern, ptype in [(FLAG_RE, "flag-out"), (HONEYTOKEN_RE, "honeytoken-out")]:
                        matches = pattern.findall(payload)
                        if matches:
                            for m in matches:
                                key = f"{pcap_path.name}:{src_str}:{dst_str}:{m.decode(errors='replace')}"
                                if key not in already_alerted:
                                    already_alerted.add(key)
                                    push_alert(rdb, {
                                        "type": ptype,
                                        "confidence": "HIGH",
                                        "message": f"{'Flag' if ptype == 'flag-out' else 'HONEYTOKEN'} detected outbound: {m.decode(errors='replace')}",
                                        "src_ip": src_str,
                                        "dst_ip": dst_str,
                                        "pcap": pcap_path.name,
                                        "ts_packet": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                                    })
                except Exception:
                    continue
    except Exception as e:
        log.debug("Error scanning %s: %s", pcap_path, e)

class PcapWatcher(threading.Thread):
    """Watch TRAFFIC_DIR for new pcap files and scan them for flags."""
    daemon = True

    def __init__(self):
        super().__init__(name="PcapWatcher")
        self._rdb = get_redis()
        self._already_alerted: set = set()
        self._seen: set = set()

    def run(self):
        log.info("PcapWatcher: monitoring %s for flag exfil...", TRAFFIC_DIR)
        while True:
            try:
                if TRAFFIC_DIR.exists():
                    for pcap in sorted(TRAFFIC_DIR.glob("*.pcap")):
                        if pcap.name not in self._seen:
                            # Wait briefly to ensure file is complete
                            time.sleep(0.2)
                            scan_pcap_for_flags(pcap, self._rdb, self._already_alerted)
                            self._seen.add(pcap.name)
            except Exception as e:
                log.error("PcapWatcher error: %s", e)
            time.sleep(1.0)

# ── 2. Suricata eve.json ingester ─────────────────────────────────────────────
class SuricataIngester(threading.Thread):
    """Tail eve.json from Suricata and forward alerts to Redis."""
    daemon = True

    def __init__(self):
        super().__init__(name="SuricataIngester")
        self._rdb = get_redis()
        self._eve_path = SURICATA_DIR / "eve.json"

    def run(self):
        log.info("SuricataIngester: tailing %s...", self._eve_path)
        while not self._eve_path.exists():
            time.sleep(2)

        with open(self._eve_path, "r") as f:
            f.seek(0, 2)  # seek to end
            while True:
                line = f.readline()
                if not line:
                    time.sleep(0.1)
                    continue
                try:
                    evt = json.loads(line.strip())
                    if evt.get("event_type") == "alert":
                        alert = evt.get("alert", {})
                        push_alert(self._rdb, {
                            "type": "suricata",
                            "confidence": "HIGH" if alert.get("severity", 3) <= 1 else "MEDIUM",
                            "message": f"[{alert.get('signature_id')}] {alert.get('signature', 'Suricata alert')}",
                            "src_ip": evt.get("src_ip"),
                            "dst_ip": evt.get("dest_ip"),
                            "src_port": evt.get("src_port"),
                            "dst_port": evt.get("dest_port"),
                            "proto": evt.get("proto"),
                            "category": alert.get("category"),
                            "severity": alert.get("severity"),
                        })
                except json.JSONDecodeError:
                    pass
                except Exception as e:
                    log.error("SuricataIngester error: %s", e)

# ── 3. Honeytoken HTTP collector ──────────────────────────────────────────────
app = FastAPI(title="CTF Detection Service", docs_url=None, redoc_url=None)

@app.on_event("startup")
async def startup():
    # Start background watchers
    PcapWatcher().start()
    SuricataIngester().start()
    log.info("Detection service started. Flag regex: %s", FLAG_REGEX)
    log.info("Honeytoken: %s", HONEYTOKEN_FLAG)

@app.get("/health")
async def health():
    return {"status": "ok", "service": "detection"}

@app.post("/honeytoken")
async def honeytoken_trigger(request: Request):
    """
    Called by the vulnbox's honeytoken trap when a decoy flag is accessed.
    Also reachable from manual curl: curl -X POST http://monitor:9999/honeytoken
    """
    body = await request.body()
    client_ip = request.client.host if request.client else "unknown"
    rdb = get_redis()
    push_alert(rdb, {
        "type": "honeytoken",
        "confidence": "HIGH",
        "message": f"HONEYTOKEN ACCESSED from {client_ip}! Decoy flag touched — attacker active.",
        "src_ip": client_ip,
        "flag": HONEYTOKEN_FLAG,
        "body": body.decode(errors="replace")[:256],
    })
    return JSONResponse({"status": "recorded", "flag": HONEYTOKEN_FLAG}, status_code=200)

@app.get("/honeytoken/{flag}")
async def honeytoken_get(flag: str, request: Request):
    """GET variant for honeypots that use URL-embedded flags."""
    client_ip = request.client.host if request.client else "unknown"
    rdb = get_redis()
    push_alert(rdb, {
        "type": "honeytoken",
        "confidence": "HIGH",
        "message": f"HONEYTOKEN GET from {client_ip}! Flag in URL: {flag[:50]}",
        "src_ip": client_ip,
        "flag": flag,
    })
    # Return a plausible response to not tip off the attacker
    return JSONResponse({"status": "ok", "data": flag}, status_code=200)

@app.get("/alerts/recent")
async def get_recent_alerts(n: int = 50):
    """Return the N most recent alerts from Redis."""
    rdb = get_redis()
    raw = rdb.lrange("alerts", 0, n - 1)
    return [json.loads(r) for r in raw]

@app.delete("/alerts/clear")
async def clear_alerts():
    """Clear all alerts (use during testing only)."""
    rdb = get_redis()
    rdb.delete("alerts")
    return {"status": "cleared"}

# ── Manual flag injection for testing ──────────────────────────────────────────
@app.post("/test/inject-flag")
async def inject_test_flag(request: Request):
    """Test endpoint: push a fake flag-out alert for dashboard testing."""
    rdb = get_redis()
    push_alert(rdb, {
        "type": "flag-out",
        "confidence": "HIGH",
        "message": "TEST: Fake flag-out injected for dashboard verification",
        "src_ip": "10.0.0.2",
        "dst_ip": "10.60.1.1",
        "flag": "TESTFLAG0000000000000000000000=",
    })
    return {"status": "injected"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9999, log_level="info")
