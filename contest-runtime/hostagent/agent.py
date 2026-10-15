"""host agent main loops: status push + ops executor."""
import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

import redis

sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parent.parent))
import health_check  # noqa: E402

from .actions import ACTIONS  # noqa: E402
from .common import redis_client  # noqa: E402
from .oswatchdog_pull import POLL_SECONDS as OSWATCHDOG_POLL_SECONDS, oswatchdog_pull_loop  # noqa: E402
from .retention import retention_loop  # noqa: E402

# Requests run concurrently (a 5-minute traffic replay must not freeze the
# Services tab), but two writers on the same thing must not interleave.
_LOCKS = {name: threading.Lock() for name in ("suricata", "ctfproxy", "config", "service", "firewall")}


def _lock_for(action: str):
    if action in ("services_list", "config_redeploy_log", "ctfproxy_get", "config_validate", "suricata_test_traffic", "firewall_list"):
        return None
    return _LOCKS.get(action.split("_", 1)[0])


def _handle(raw: str):
    rdb = redis_client()
    try:
        req = json.loads(raw)
    except ValueError:
        return
    req_id = str(req.get("id", ""))[:64]
    action = str(req.get("action", ""))
    fn = ACTIONS.get(action)
    try:
        if fn is None:
            result = {"ok": False, "output": f"unknown action {action!r}"}
        else:
            lock = _lock_for(action)
            if lock is None:
                result = fn(req.get("payload") or {}, rdb)
            else:
                with lock:
                    result = fn(req.get("payload") or {}, rdb)
    except Exception as e:
        result = {"ok": False, "output": f"host agent error in {action}: {e!r}"}
        print(f"[host-agent] {action} failed: {e!r}", flush=True)
    if req_id:
        rdb.set(f"ops_result:{req_id}", json.dumps(result), ex=600)


def ops_loop():
    pool = ThreadPoolExecutor(max_workers=6)
    rdb = redis_client()
    while True:
        try:
            item = rdb.blpop("ops_requests", timeout=5)
            if item:
                pool.submit(_handle, item[1])
        except redis.TimeoutError:
            # A socket read timeout on the BLPOP itself (not a dropped
            # connection) — common on WSL/Docker-Desktop localhost port
            # forwarding. redis.TimeoutError is NOT a subclass of
            # ConnectionError, so it must be caught separately or it kills
            # the whole agent. The connection is usually still usable; just
            # loop and block again.
            continue
        except redis.ConnectionError:
            time.sleep(3)
            rdb = redis_client()


def status_loop():
    while True:
        try:
            result = health_check.run_all()
            health_check.push_redis(result, health_check._cfg())
        except Exception as e:
            print(f"[host-agent] status error: {e!r}", flush=True)
        time.sleep(15)


def main():
    print(f"[host-agent] started: status push every 15s + pcap retention every 60s + "
          f"os-watchdog alert pull every {OSWATCHDOG_POLL_SECONDS}s + "
          f"{len(ACTIONS)} whitelisted actions", flush=True)
    threading.Thread(target=status_loop, daemon=True).start()
    threading.Thread(target=retention_loop, daemon=True).start()
    threading.Thread(target=oswatchdog_pull_loop, daemon=True).start()
    ops_loop()
