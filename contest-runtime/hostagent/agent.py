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
    print(f"[host-agent] started: status push every 15s + pcap retention every 60s + {len(ACTIONS)} whitelisted actions", flush=True)
    threading.Thread(target=status_loop, daemon=True).start()
    threading.Thread(target=retention_loop, daemon=True).start()
    ops_loop()
