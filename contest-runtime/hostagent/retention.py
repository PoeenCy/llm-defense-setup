"""Age out captured pcaps so the monitor disk never fills up, with escalating
fallbacks when that alone isn't enough.

Runs inside host_agent every 60s. Policy from services.json -> "retention":
  pcap_keep_minutes  delete pcaps older than this; 0 = off       (default 0)
  pcap_max_gb        keep traffic/ under this size, oldest first (default 5)
  min_free_gb        keep at least this much disk free           (default 10)

Safety: a pcap younger than MIN_AGE_S is never deleted (Tulip, Suricata, ML
and detection may still be reading it), and age-based deletion waits until
detection has scanned the file. Size/free-space limits override that last
condition — a full disk stops everything. Flows already imported stay in
Tulip; only the raw pcap file (Tulip's "download pcap") goes away.

IMPORTANT — pcap cleanup alone does NOT keep the disk healthy. The actual
disk hog in practice (see docs/RUNBOOK.md incident #1, and docs/STATUS.md's
2026-10-13 entry) is Docker's own image/build-cache layers piling up across
rebuilds, not captured traffic or Tulip's database -- one real session here
had 203 dangling images and 116GB reclaimable while `traffic/` held 24KB.
So when `min_free_gb` is still violated after deleting every eligible pcap,
this module escalates to pruning Docker's OWN reclaimable space, safely:
  1. `docker image prune -f`   -- dangling (untagged) images only; never
     touches an image a running OR stopped container still references.
  2. `docker builder prune -f` -- build cache only; never touches anything
     running.
Neither step can remove a volume, a running container, or data a container
still needs -- both are safe to run unattended, repeatedly, mid-competition.

Last resort, OPT-IN ONLY (services.json -> retention.tulip_flow_retention_hours,
default 0 = disabled): if disk is STILL low after both of the above, drop the
oldest TimescaleDB chunks from Tulip's `flow`/`flow_item` hypertables. Unlike
the two steps above, this deletes real contest data (old captured flows) --
it only runs at all if the operator has explicitly set a retention window,
and even then only as the last tier, logged as a CRITICAL audit event.
"""
import json
import shutil
import subprocess
import time
from contextlib import nullcontext
from pathlib import Path

from .common import ROOT, audit, cfg, redis_client
from flagtrace.app.ledger import ledger_lock, may_delete

TRAFFIC = ROOT.parent / "traffic"  # traffic/ lives at the repo root, not under contest-runtime/
MIN_AGE_S = 600
SCANNED_KEY = "detection:scanned_pcaps"
DOCKER_PRUNE_COOLDOWN_S = 300  # don't hammer the docker daemon every 60s if still low


def policy() -> dict:
    r = cfg().get("retention") or {}
    return {
        "keep_min": float(r.get("pcap_keep_minutes", 0)),
        "max_bytes": float(r.get("pcap_max_gb", 5)) * 1024 ** 3,
        "min_free": float(r.get("min_free_gb", 10)) * 1024 ** 3,
        "tulip_hours": float(r.get("tulip_flow_retention_hours", 0)),
    }


_last_docker_prune = 0.0


def _docker_prune(rdb, free_before: int, min_free: int) -> int:
    """Escalation when pcap deletion alone didn't free enough space. Only
    removes Docker's own dangling images / build cache -- see module
    docstring for why this is always safe to run unattended. Returns the
    current free-space reading (unchanged if skipped by cooldown)."""
    global _last_docker_prune
    now = time.time()
    if now - _last_docker_prune < DOCKER_PRUNE_COOLDOWN_S:
        return free_before
    _last_docker_prune = now
    ran = []
    for label, cmd in (
        ("images", ["docker", "image", "prune", "-f"]),
        ("build cache", ["docker", "builder", "prune", "-f"]),
    ):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=120).stdout
        except Exception as e:
            out = f"<failed: {e!r}>"
        ran.append(label)
        for line in out.splitlines():
            if "Total reclaimed space" in line:
                out = line.strip()
                break
        print(f"[host-agent] retention: docker {label} prune -> {out}", flush=True)
    free_after = shutil.disk_usage(TRAFFIC).free
    freed_mb = max(0, free_after - free_before) / 1024 ** 2
    audit(rdb, f"retention: low disk (<{min_free / 1024**3:.0f}GB free) persisted after pcap "
               f"cleanup -- pruned Docker {' + '.join(ran)}, freed ~{freed_mb:.0f} MB "
               f"(now {free_after / 1024**3:.1f}GB free)", True, "retention")
    return free_after


def _tulip_drop_chunks(rdb, hours: float) -> None:
    """LAST RESORT, opt-in only (retention.tulip_flow_retention_hours > 0):
    drop TimescaleDB chunks older than `hours` from Tulip's flow/flow_item
    hypertables. This deletes real captured contest data, not a cache -- only
    called when pcap cleanup + Docker pruning were both insufficient."""
    sql = (
        f"SELECT drop_chunks('flow', older_than => INTERVAL '{hours} hours'); "
        f"SELECT drop_chunks('flow_item', older_than => INTERVAL '{hours} hours');"
    )
    try:
        r = subprocess.run(
            ["docker", "exec", "tulip-timescale-1", "psql", "-U", "tulip", "-d", "tulip", "-c", sql],
            capture_output=True, text=True, timeout=60,
        )
        out = (r.stdout + r.stderr).strip()[-1000:]
    except Exception as e:
        out = f"<failed: {e!r}>"
    audit(rdb, f"retention: CRITICAL -- disk still low after pcap cleanup + Docker prune; "
               f"dropped Tulip flow/flow_item chunks older than {hours:.0f}h (opt-in, "
               f"retention.tulip_flow_retention_hours). Output: {out}", True, "retention")


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
        db_dir = ROOT.parent / "data" / "flagtrace"
        guarded = (cfg().get("flagtrace") or {}).get("enabled") or (db_dir / "flagtrace.sqlite3").exists()
        try:
            with ledger_lock(db_dir, blocking=False) if guarded else nullcontext():
                if guarded and not may_delete(db_dir / "flagtrace.sqlite3", f.name):
                    continue
                f.unlink()
                f.with_suffix(f.suffix + ".ready").unlink(missing_ok=True)
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

    # Escalation: pcap deletion alone didn't help (or there was nothing left
    # to delete) and we're still below the free-space floor -- prune Docker's
    # own reclaimable space instead of silently running the disk to 100%.
    free_now = shutil.disk_usage(TRAFFIC).free
    if free_now < p["min_free"]:
        free_now = _docker_prune(rdb, free_now, p["min_free"])
        # Last resort, opt-in only: still low even after Docker pruning.
        if free_now < p["min_free"] and p["tulip_hours"] > 0:
            _tulip_drop_chunks(rdb, p["tulip_hours"])

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
