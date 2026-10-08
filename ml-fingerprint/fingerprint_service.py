#!/usr/bin/env python3
"""
fingerprint_service.py — CTF Monitor Hub: L3/L4 Bot Fingerprinting (Item 5)

Goal: After the organizer's checker turns on, learn what "checker bot traffic"
looks like at layers 3/4, then flag flows that DEVIATE from that pattern.

Method:
  - Extract per-source features: inter-arrival time (IAT), packet sizes, port
    predictability, TCP handshake ordering, per-tick flow count cadence.
  - Online clustering (DBSCAN + running stats) — no baseline needed at startup.
  - After N_WARMUP_TICKS cycles, label new connections as "bot-like" (steady
    checker pattern) vs "deviant" (anomalous cadence, unusual packet sizes, etc.)
  - Deviant connections → Redis hint (NOT a hard alarm).

⚠️  This is a HINT layer only. Labels indicate "looks different from checker bot"
     but do NOT trigger automated responses. Human decision required.

⚠️  Fingerprints by cadence + packet size distribution, NOT by IP alone,
     because the organizer may NAT all checker traffic through a shared IP.
"""
import collections
import json
import logging
import os
import socket
import struct
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import redis
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ML-FP] %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ml-fingerprint")

# ── Config ──────────────────────────────────────────────────────────────────
REDIS_HOST   = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT   = int(os.environ.get("REDIS_PORT", 6379))
TRAFFIC_DIR  = Path(os.environ.get("TRAFFIC_DIR", "/traffic"))
TEAMS_CIDR   = os.environ.get("TEAMS_CIDR", "10.60.0.0/16")
MONITOR_IP   = os.environ.get("MONITOR_IP", "10.0.0.50")

CONFIG_PATH = Path(os.environ.get("CONFIG", "/app/services.json"))
if CONFIG_PATH.exists():
    with open(CONFIG_PATH) as f:
        CFG = json.load(f)
    SERVICE_PORTS = {s["port"] for s in CFG.get("services", [])}
else:
    CFG = {}
    SERVICE_PORTS = set()

N_WARMUP_TICKS   = 3    # ticks before we start labeling
TICK_WINDOW_SEC  = 120  # seconds per observation window
MAX_OBSERVATIONS = 500  # max flow records to keep in memory
DBSCAN_EPS       = 1.5  # cluster radius (in scaled feature space)
DBSCAN_MIN_SAMP  = 3    # min points per cluster

def get_redis():
    return redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)

def push_hint(rdb: redis.Redis, hint: dict):
    """Push a bot-deviation hint to Redis. NOT a hard alarm."""
    hint.setdefault("ts", datetime.now(timezone.utc).isoformat())
    hint["source"] = "ml-fingerprint"
    hint["type"]   = "bot-deviation-hint"
    hint.setdefault("confidence", "LOW")
    payload = json.dumps(hint)
    rdb.lpush("hints", payload)
    rdb.ltrim("hints", 0, 4999)
    rdb.publish("hints_channel", payload)
    log.info("💡 HINT: %s", hint.get("message", ""))

# ── Feature extraction ────────────────────────────────────────────────────────
def cidr_to_range(cidr: str) -> Tuple[int, int]:
    net, bits = cidr.split("/")
    mask = (0xFFFFFFFF << (32 - int(bits))) & 0xFFFFFFFF
    net_int = struct.unpack("!I", socket.inet_aton(net))[0] & mask
    return net_int, mask

TEAMS_NET, TEAMS_MASK = cidr_to_range(TEAMS_CIDR)

def ip_in_cidr(ip_bytes: bytes) -> bool:
    ip_int = struct.unpack("!I", ip_bytes)[0]
    return (ip_int & TEAMS_MASK) == TEAMS_NET

try:
    import dpkt
    HAS_DPKT = True
except ImportError:
    HAS_DPKT = False
    log.warning("dpkt not available — pcap parsing disabled")

class FlowRecord:
    """Aggregate stats for a single source-IP/port → dst-port flow."""
    __slots__ = ["src_ip", "dst_port", "timestamps", "pkt_sizes", "syn_seen", "syn_ack_seen"]

    def __init__(self, src_ip: str, dst_port: int):
        self.src_ip      = src_ip
        self.dst_port    = dst_port
        self.timestamps: List[float]  = []
        self.pkt_sizes:  List[int]    = []
        self.syn_seen    = False
        self.syn_ack_seen = False

    def add_packet(self, ts: float, size: int, flags: int = 0):
        self.timestamps.append(ts)
        self.pkt_sizes.append(size)
        if flags & 0x02:  # SYN
            self.syn_seen = True
        if flags & 0x12:  # SYN+ACK
            self.syn_ack_seen = True

    def to_feature_vector(self) -> Optional[np.ndarray]:
        """Extract a 6-dim feature vector from this flow's observations."""
        if len(self.timestamps) < 2:
            return None
        ts   = np.array(self.timestamps)
        iats = np.diff(ts)
        sizes = np.array(self.pkt_sizes)
        return np.array([
            float(np.mean(iats)),           # mean inter-arrival time
            float(np.std(iats)),            # IAT std-dev (regularity)
            float(np.mean(sizes)),          # mean packet size
            float(np.std(sizes)),           # packet size std-dev
            float(len(self.timestamps)),    # flow packet count
            float(1 if self.syn_seen else 0),  # proper handshake?
        ])

class BotFingerprinter(threading.Thread):
    """Online L3/L4 bot fingerprinter. Runs in background, emits hints to Redis."""
    daemon = True

    def __init__(self):
        super().__init__(name="BotFingerprinter")
        self._rdb        = get_redis()
        self._tick       = 0
        self._flows: Dict[str, FlowRecord] = {}
        self._observations: List[np.ndarray] = []  # historical feature vectors
        self._scaler     = StandardScaler()
        self._fitted     = False
        self._seen_pcaps: set = set()

    def _ingest_pcap(self, pcap_path: Path):
        """Parse a pcap file and update flow records."""
        if not HAS_DPKT:
            return
        try:
            with open(pcap_path, "rb") as f:
                pcap = dpkt.pcap.Reader(f)
                for ts, buf in pcap:
                    try:
                        eth = dpkt.ethernet.Ethernet(buf)
                        if not isinstance(eth.data, dpkt.ip.IP):
                            continue
                        ip = eth.data
                        if not ip_in_cidr(ip.src):
                            continue  # only fingerprint inbound (attacker→us)
                        if not isinstance(ip.data, dpkt.tcp.TCP):
                            continue
                        tcp = ip.data
                        if tcp.dport not in SERVICE_PORTS:
                            continue  # only our monitored services
                        src_ip = socket.inet_ntoa(ip.src)
                        key    = f"{src_ip}:{tcp.dport}"
                        if key not in self._flows:
                            self._flows[key] = FlowRecord(src_ip, tcp.dport)
                        pkt_size = len(buf)
                        self._flows[key].add_packet(ts, pkt_size, tcp.flags)
                    except Exception:
                        continue
        except Exception as e:
            log.debug("Error parsing %s: %s", pcap_path, e)

    def _analyze_tick(self):
        """At end of each tick window, cluster flows and emit hints for deviants."""
        if not self._flows:
            return

        # Build feature matrix from completed flows
        new_vecs = []
        flow_keys = []
        for key, flow in list(self._flows.items()):
            vec = flow.to_feature_vector()
            if vec is not None:
                new_vecs.append(vec)
                flow_keys.append(key)

        if not new_vecs:
            return

        # Accumulate observations
        self._observations.extend(new_vecs)
        if len(self._observations) > MAX_OBSERVATIONS:
            self._observations = self._observations[-MAX_OBSERVATIONS:]

        self._tick += 1
        log.info("Tick %d: %d new flows, %d total observations",
                 self._tick, len(new_vecs), len(self._observations))

        # Only start labeling after warmup
        if self._tick < N_WARMUP_TICKS:
            log.info("Warmup phase (%d/%d ticks)", self._tick, N_WARMUP_TICKS)
            self._flows.clear()
            return

        # Fit/update scaler on all observations
        X_all = np.array(self._observations)
        try:
            X_scaled = self._scaler.fit_transform(X_all)
        except Exception as e:
            log.error("Scaler error: %s", e)
            self._flows.clear()
            return

        # Cluster all observations — dominant cluster = checker bot pattern
        db = DBSCAN(eps=DBSCAN_EPS, min_samples=DBSCAN_MIN_SAMP).fit(X_scaled)
        all_labels = db.labels_

        # Find the dominant cluster (most members = checker bot pattern)
        from collections import Counter
        label_counts = Counter(l for l in all_labels if l >= 0)
        dominant_label = label_counts.most_common(1)[0][0] if label_counts else -1

        # Now classify this tick's new flows
        new_arr = np.array(new_vecs)
        try:
            new_scaled = self._scaler.transform(new_arr)
        except Exception:
            self._flows.clear()
            return

        # For each new flow, find nearest cluster
        for i, (key, vec_scaled) in enumerate(zip(flow_keys, new_scaled)):
            flow = self._flows.get(key)
            if flow is None:
                continue

            # Distance to dominant cluster centroid
            dominant_mask = all_labels == dominant_label
            if dominant_mask.sum() == 0:
                # No dominant cluster yet
                continue
            centroid = X_scaled[dominant_mask].mean(axis=0)
            dist = float(np.linalg.norm(vec_scaled - centroid))

            label = "bot-like" if dist < DBSCAN_EPS * 1.5 else "deviant"

            if label == "deviant":
                fv = self._flows[key].to_feature_vector()
                push_hint(self._rdb, {
                    "message": (
                        f"Bot-deviation: {key} looks different from checker "
                        f"(dist={dist:.2f} from bot cluster). "
                        f"IAT_mean={fv[0]:.3f}s, pkt_size={fv[2]:.0f}B"
                    ),
                    "src_ip": flow.src_ip,
                    "dst_port": flow.dst_port,
                    "dist_from_bot_cluster": round(dist, 3),
                    "feature_iat_mean": round(float(fv[0]), 4),
                    "feature_iat_std":  round(float(fv[1]), 4),
                    "feature_pktsize_mean": round(float(fv[2]), 1),
                    "feature_pktsize_std":  round(float(fv[3]), 1),
                    "feature_pkt_count": int(fv[4]),
                    "label": "deviant",
                    "tick": self._tick,
                    "note": (
                        "HINT ONLY — fingerprints by cadence+size, not IP. "
                        "Organizer may NAT. Human review required."
                    ),
                })
            else:
                # Update Redis with bot-like classification (no alert)
                self._rdb.hset("bot_fingerprint_labels", key, json.dumps({
                    "label": "bot-like",
                    "tick": self._tick,
                    "dist": round(dist, 3),
                    "ts": datetime.now(timezone.utc).isoformat(),
                }))

        log.info("Tick %d analysis done. Dominant cluster: #%d (%d members)",
                 self._tick, dominant_label, label_counts.get(dominant_label, 0))

        # Reset flows for next window
        self._flows.clear()

    def run(self):
        log.info("BotFingerprinter started. Traffic dir: %s", TRAFFIC_DIR)
        log.info("Service ports monitored: %s", SERVICE_PORTS)
        log.info("Teams CIDR: %s (inbound traffic from this range will be fingerprinted)", TEAMS_CIDR)
        log.info("Warmup: %d ticks (~%ds each) before labeling begins", N_WARMUP_TICKS, TICK_WINDOW_SEC)

        tick_start = time.time()

        while True:
            # Ingest any new pcaps
            if TRAFFIC_DIR.exists():
                for pcap in sorted(TRAFFIC_DIR.glob("*.pcap")):
                    if pcap.name not in self._seen_pcaps:
                        self._ingest_pcap(pcap)
                        self._seen_pcaps.add(pcap.name)

            # At end of tick window, analyze
            now = time.time()
            if now - tick_start >= TICK_WINDOW_SEC:
                self._analyze_tick()
                tick_start = now

            time.sleep(2.0)

if __name__ == "__main__":
    fp = BotFingerprinter()
    fp.start()

    # Keep main thread alive, expose a minimal health check
    import http.server, socketserver

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/health":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'{"status":"ok","service":"ml-fingerprint"}')
        def log_message(self, *args): pass

    with socketserver.TCPServer(("0.0.0.0", 5002), Handler) as httpd:
        log.info("ML fingerprint health check on :5002/health")
        httpd.serve_forever()
