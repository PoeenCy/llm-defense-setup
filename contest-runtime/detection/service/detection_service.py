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

# Ports our services listen on (public and, when capture is on a docker bridge,
# the container-internal ones). A packet FROM one of these carries a response,
# i.e. data leaving the service; a packet TO one of them is a request.
SERVICE_PORTS = {int(p) for s in SERVICES_CFG.get("services", [])
                 for p in (s.get("port"), s.get("capture_port"), s.get("internal_port")) if p}


# ctf_proxy answers a blocked request with "<keyword> <service> <rule method>"
# (upstream service_process.py). Seeing that in a response = one block, with
# the rule that did it — the only place per-rule block counts come from.
PROXY_KEYWORD = (SERVICES_CFG.get("ctf_proxy") or {}).get("keyword") or ""
PROXY_BLOCK_RE = re.compile(re.escape(PROXY_KEYWORD.encode()) + rb" (\S+) (\w+)") if PROXY_KEYWORD else None


def is_response(sport: int, dport: int) -> bool:
    if sport in SERVICE_PORTS or dport in SERVICE_PORTS:
        return sport in SERVICE_PORTS
    return sport < dport          # servers listen low, clients use ephemeral ports


def scan_pcap_for_flags(pcap_path: Path, rdb: redis.Redis):
    """Scan one pcap for flags and LABEL every sighting — nothing is dropped:

      flag-planted  a flag sent INTO a service (normally the checker storing it)
      flag-echo     the response to that same store request repeats the flag
      flag-out      a flag leaving the service in any other response (the
                    checker reading it back OR an attacker stealing it) —
                    enriched with when/who planted it and the ML bot label of
                    the requester, so a human can tell which one it is.

    When the same flag crosses several hops (proxy -> app -> ...) only the
    last hop is reported, with the hop count."""
    import socket
    found = {}   # (ptype, flag) -> alert fields of the latest packet carrying it
    blocks = []  # ctf_proxy block answers seen
    planted = {}      # flag -> request fields, for flags seen in a REQUEST
    try:
        with open(pcap_path, "rb") as f:
            for ts, buf in dpkt.pcap.Reader(f):
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip = eth.data
                    if not isinstance(ip, dpkt.ip.IP) or not isinstance(ip.data, (dpkt.tcp.TCP, dpkt.udp.UDP)):
                        continue
                    seg = ip.data
                    payload = bytes(seg.data)
                    if not payload:
                        continue
                    if not is_response(seg.sport, seg.dport):
                        for m in FLAG_RE.findall(payload):
                            planted[m.decode(errors="replace")] = {
                                "src_ip": socket.inet_ntoa(ip.src), "src_port": seg.sport,
                                "dst_ip": socket.inet_ntoa(ip.dst), "dst_port": seg.dport,
                                "ts_packet": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                            }
                        continue
                    if PROXY_BLOCK_RE is not None:
                        for svc, rule in PROXY_BLOCK_RE.findall(payload):
                            blocks.append({
                                "service": svc.decode(errors="replace"), "rule": rule.decode(errors="replace"),
                                "src_ip": socket.inet_ntoa(ip.src), "src_port": seg.sport,
                                "dst_ip": socket.inet_ntoa(ip.dst), "dst_port": seg.dport,
                                "ts_packet": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                            })
                    for pattern, ptype in ((FLAG_RE, "flag-out"), (HONEYTOKEN_RE, "honeytoken-out")):
                        for m in pattern.findall(payload):
                            key = (ptype, m.decode(errors="replace"))
                            hops = found.get(key, {}).get("hops", 0) + 1
                            found[key] = {
                                "src_ip": socket.inet_ntoa(ip.src), "src_port": seg.sport,
                                "dst_ip": socket.inet_ntoa(ip.dst), "dst_port": seg.dport,
                                "ts_packet": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                                "hops": hops,
                            }
                except Exception:
                    continue
    except Exception as e:
        log.debug("Error scanning %s: %s", pcap_path, e)
    for b in blocks:
        push_alert(rdb, {
            "type": "proxy-blocked", "confidence": "MEDIUM", "pcap": pcap_path.name,
            "message": f"ctf_proxy blocked {b['dst_ip']} on {b['service']} with rule {b['rule']} "
                       "(if this is the checker, the rule is too broad — Pause filtering)",
            **b,
        })
    for flag, info in planted.items():
        rdb.set(PLANTED_KEY + flag, json.dumps(info), ex=6 * 3600)
        push_alert(rdb, {
            "type": "flag-planted", "confidence": "INFO",
            "message": f"Flag stored into service by {info['src_ip']}: {flag} (normally the checker putting a new flag)",
            "flag": flag, "pcap": pcap_path.name, **info,
        })
    for (ptype, flag), info in found.items():
        hops = f" (seen on {info['hops']} hops)" if info["hops"] > 1 else ""
        if ptype == "honeytoken-out":
            push_alert(rdb, {"type": ptype, "confidence": "HIGH", "flag": flag, "pcap": pcap_path.name,
                             "message": f"HONEYTOKEN leaving service: {flag}{hops}", **info})
            continue
        if flag in planted:
            push_alert(rdb, {
                "type": "flag-echo", "confidence": "LOW", "flag": flag, "pcap": pcap_path.name,
                "message": f"Response repeated a flag that was stored in the same capture: {flag}{hops} "
                           "(store endpoint echoing its input — check the flow if unsure)",
                **info,
            })
            continue
        ctx = []
        try:
            p = rdb.get(PLANTED_KEY + flag)
            if p:
                p = json.loads(p)
                ctx.append(f"planted {p['ts_packet'][11:19]} by {p['src_ip']}")
                info["planted_by"], info["planted_at"] = p["src_ip"], p["ts_packet"]
            else:
                ctx.append("plant not seen (older than capture, or flag format changed)")
            lbl = rdb.hget("bot_fingerprint_labels", f"{info['dst_ip']}:{info['src_port']}")
            info["requester_ml"] = json.loads(lbl)["label"] if lbl else "unknown"
            ctx.append(f"requester ML: {info['requester_ml']}")
        except Exception:
            pass
        push_alert(rdb, {
            "type": "flag-out", "confidence": "HIGH", "flag": flag, "pcap": pcap_path.name,
            "message": f"Flag leaving service to {info['dst_ip']}: {flag}{hops} — {'; '.join(ctx)}. "
                       "Checker reads also look like this: open the flow and judge the REQUEST.",
            **info,
        })


PLANTED_KEY = "flag:planted:"
SCANNED_KEY = "detection:scanned_pcaps"


class PcapWatcher(threading.Thread):
    """Watch TRAFFIC_DIR for new pcap files and scan them for flags."""
    daemon = True

    def __init__(self):
        super().__init__(name="PcapWatcher")
        self._rdb = get_redis()

    def run(self):
        # Scanned file names live in Redis, so a restart does not re-alert on
        # every pcap already on disk (that used to flood the feed with old flags).
        log.info("PcapWatcher: monitoring %s for flag exfil...", TRAFFIC_DIR)
        while True:
            try:
                if TRAFFIC_DIR.exists():
                    for pcap in sorted(TRAFFIC_DIR.glob("*.pcap")):
                        if self._rdb.sismember(SCANNED_KEY, pcap.name):
                            continue
                        if time.time() - pcap.stat().st_mtime < 2:
                            continue      # still being written
                        scan_pcap_for_flags(pcap, self._rdb)
                        self._rdb.sadd(SCANNED_KEY, pcap.name)
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
                            "sid": alert.get("signature_id"),
                            "ts_packet": evt.get("timestamp"),
                        })
                except json.JSONDecodeError:
                    pass
                except Exception as e:
                    log.error("SuricataIngester error: %s", e)

# ── 3. Honeytoken HTTP collector ──────────────────────────────────────────────
app = FastAPI(title="CTF Detection Service", docs_url=None, redoc_url=None)

# Two listeners. `app` (container :9999) has everything incl. admin/test
# endpoints and is only published on BIND_IP (loopback by default).
# `public_app` (container :9997) is the one published on ALL interfaces,
# because vulnbox-side traps/agents must reach it — so it carries nothing but
# the routes those need. (Filtering by client IP instead does not work here:
# under rootless podman every connection arrives from the netns gateway.)
public_app = FastAPI(title="CTF Detection — public intake", docs_url=None, redoc_url=None, openapi_url=None)

@app.on_event("startup")
async def startup():
    # Start background watchers
    PcapWatcher().start()
    SuricataIngester().start()
    log.info("Detection service started. Flag regex: %s", FLAG_REGEX)
    log.info("Honeytoken: %s", HONEYTOKEN_FLAG)

@app.get("/health")
@public_app.get("/health")
async def health():
    return {"status": "ok", "service": "detection"}

@app.post("/honeytoken")
@public_app.post("/honeytoken")
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
@public_app.get("/honeytoken/{flag}")
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

@app.post("/watchdog/os-report")
@public_app.post("/watchdog/os-report")
async def os_watchdog_report(request: Request):
    """Called by vulnbox-deploy/os-watchdog-agent.sh (new process, changed
    passwd/shadow, new listening port, ...). Publicly reachable by design, so
    every field is length-capped and the alert is labelled as agent-reported."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "expected JSON"}, status_code=400)
    def cap(v, n=500):
        return str(v or "")[:n]
    push_alert(get_redis(), {
        "type": "os-watchdog",
        "source": "os-watchdog",
        "confidence": "HIGH",
        "alert_type": cap(body.get("alert_type"), 64),
        "message": f"[OS watchdog on {cap(body.get('vulnbox'), 64)}] {cap(body.get('message'))}",
        "detail": cap(body.get("detail"), 2000),
    })
    return {"status": "recorded"}

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

async def _serve_both():
    admin = uvicorn.Server(uvicorn.Config(app, host="0.0.0.0", port=9999, log_level="info"))
    public = uvicorn.Server(uvicorn.Config(public_app, host="0.0.0.0", port=9997, log_level="info"))
    await asyncio.gather(admin.serve(), public.serve())

if __name__ == "__main__":
    asyncio.run(_serve_both())
