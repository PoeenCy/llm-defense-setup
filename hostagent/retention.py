"""Age out captured pcaps so the monitor disk never fills up.

Runs inside host_agent every 60s. Policy from services.json -> "retention":
  pcap_keep_minutes  delete pcaps older than this; 0 = off       (default 0)
  pcap_max_gb        keep traffic/ under this size, oldest first (default 5)
  min_free_gb        keep at least this much disk free           (default 10)

Safety: a pcap younger than MIN_AGE_S is never deleted (Tulip, Suricata, ML
and detection may still be reading it), and age-based deletion waits until
detection has scanned the file. Size/free-space limits override that last
condition — a full disk stops everything. Flows already imported stay in
Tulip; only the raw pcap file (Tulip's "download pcap") goes away.
"""
import json
import shutil
import time
from pathlib import Path

from .common import ROOT, audit, cfg, redis_client

TRAFFIC = ROOT / "traffic"
MIN_AGE_S = 600
SCANNED_KEY = "detection:scanned_pcaps"


def policy() -> dict:
    r = cfg().get("retention") or {}
    return {
        "keep_min": float(r.get("pcap_keep_minutes", 0)),
        "max_bytes": float(r.get("pcap_max_gb", 5)) * 1024 ** 3,
        "min_free": float(r.get("min_free_gb", 10)) * 1024 ** 3,
    }


def sweep(rdb) -> dict:
    p = policy()
    now = time.time()
    files = []
    for f in TRAFFIC.glob("*.pcap"):
        try:
            st = f.stat()
        except OSError:
            continue
        files.append((st.st_mtime, st.st_size, f))
    files.sort()                                    # oldest first
    total = sum(s for _, s, _ in files)
    try:
        scanned = rdb.smembers(SCANNED_KEY)
    except Exception:
        scanned = set()
    deleted, freed, reasons = [], 0, set()
    for mtime, size, f in files:
        age = now - mtime
        if age < MIN_AGE_S:
            break                                   # everything after is newer
        free = shutil.disk_usage(TRAFFIC).free
        why = None
        if free < p["min_free"]:
            why = "low disk"
        elif total > p["max_bytes"]:
            why = "traffic/ over size limit"
        elif p["keep_min"] > 0 and age > p["keep_min"] * 60 and f.name in scanned:
            why = "older than keep time"
        if not why:
            continue
        try:
            f.unlink()
        except OSError:
            continue
        deleted.append(f.name)
        freed += size
        total -= size
        reasons.add(why)
    if deleted:
        try:
            rdb.srem(SCANNED_KEY, *deleted)
        except Exception:
            pass
        audit(rdb, f"retention: deleted {len(deleted)} old pcap(s), freed {freed / 1024 ** 2:.0f} MB "
                   f"({', '.join(sorted(reasons))}); traffic/ now {total / 1024 ** 2:.0f} MB", True, "retention")
    status = {"files": len(files) - len(deleted), "size_mb": round(total / 1024 ** 2),
              "free_gb": round(shutil.disk_usage(TRAFFIC).free / 1024 ** 3, 1),
              "last_deleted": len(deleted), "policy": {k: round(v) for k, v in p.items()}, "ts": now}
    try:
        rdb.set("retention_status", json.dumps(status), ex=300)
    except Exception:
        pass
    return status


def retention_loop():
    while True:
        try:
            sweep(redis_client())
        except Exception as e:
            print(f"[host-agent] retention error: {e!r}", flush=True)
        time.sleep(60)
