"""Pull-based delivery for OS-watchdog alerts.

os-watchdog-agent.sh (on the vulnbox) pushes each alert via curl POST to the
monitor's /watchdog/os-report endpoint. Confirmed live against a real
practice-arena VPN that this push direction (vulnbox opening a connection to
the monitor) does not work: even a brand-new, non-containerized listener on
a fresh port was unreachable from the vulnbox, while every monitor-initiated
connection (SSH, capture pull, ctf_proxy deploy) works fine. So the push is
one-way broken on this network, silently (the script's curl already has
`|| true`) -- alerts were being detected on the vulnbox but never reaching
the dashboard.

This polls the already-working direction instead: periodically SSH into the
vulnbox (same alias and sudo path already used by the allow/unallow/
allow-list actions in actions/oswatchdog.py) and ask for every alert the
agent's local log (ALERT_LOG in os-watchdog-agent.sh, size-capped there)
has written since the last one we've already pulled, tracked by a
monotonic id in a small local state file. Each new alert is written into
Redis exactly the way detection_service.py's /watchdog/os-report handler
already does, so the dashboard shows it identically whether it arrived by
push or by pull.
"""
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from .common import cfg, redis_client, ssh

BIN = "/usr/local/bin/os-watchdog-agent.sh"
STATE_FILE = Path(__file__).resolve().parent.parent / ".oswatchdog-pull-state.json"
POLL_SECONDS = 20


def _last_id() -> int:
    try:
        return int(json.loads(STATE_FILE.read_text()).get("last_id", 0))
    except Exception:
        return 0


def _save_last_id(n: int):
    STATE_FILE.write_text(json.dumps({"last_id": n}))


def _cap(v, n=500) -> str:
    return str(v or "")[:n]


def _push_alert(rdb, alert: dict):
    alert.setdefault("ts", datetime.now(timezone.utc).isoformat())
    alert.setdefault("source", "os-watchdog")
    payload = json.dumps(alert)
    rdb.lpush("alerts", payload)
    rdb.ltrim("alerts", 0, 9999)
    rdb.publish("alerts_channel", payload)


def _pull_once():
    alias = (cfg().get("vulnbox") or {}).get("capture_ssh_alias") or ""
    if not alias:
        return
    last_id = _last_id()
    code, out = ssh(alias, f"sudo {BIN} alerts-since {last_id}", timeout=20)
    if code != 0 or not out.strip():
        return
    rdb = redis_client()
    max_id = last_id
    for line in out.strip().splitlines():
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        try:
            rec_id = int(rec.get("id", 0))
        except (TypeError, ValueError):
            continue
        if rec_id <= last_id:
            continue  # defensive: ignore anything at/below what we've already recorded
        max_id = max(max_id, rec_id)
        _push_alert(rdb, {
            "type": "os-watchdog",
            "confidence": "HIGH",
            "alert_type": _cap(rec.get("alert_type"), 64),
            "message": f"[OS watchdog on {_cap(rec.get('vulnbox'), 64)}] {_cap(rec.get('message'))}",
            "detail": _cap(rec.get("detail"), 2000),
        })
    if max_id != last_id:
        _save_last_id(max_id)


def oswatchdog_pull_loop():
    while True:
        try:
            _pull_once()
        except Exception as e:
            print(f"[host-agent] os-watchdog pull error: {e!r}", flush=True)
        time.sleep(POLL_SECONDS)
