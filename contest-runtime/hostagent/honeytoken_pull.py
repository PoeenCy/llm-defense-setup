"""Pull-based delivery for honeytoken alerts -- same reasoning and pattern as
oswatchdog_pull.py: this vulnbox's VPN only routes monitor->vulnbox, so the
trap's own curl/urlopen push (still attempted there as a fallback) reaches
nowhere. Both honeytoken event sources on the vulnbox -- the inotify file
watcher and flag-server.sh's HTTP trap -- already run unprivileged (no
sudo), and now also append to a local JSONL log in that user's own home
(~/.ctf-honeytoken/alerts.jsonl, via honeytoken-log.sh / flag-server.sh's
own log_local()). This polls that log over SSH -- no sudo needed on this
side either, since the file is owned by the plain ssh user -- and writes
each new entry into Redis exactly the shape detection_service.py's existing
/honeytoken and /honeytoken/{flag} push handlers already produce, so the
dashboard shows a pulled alert identically to a pushed one.
"""
import json
import time
from datetime import datetime, timezone
from pathlib import Path

from .common import cfg, redis_client, ssh

LOG_SCRIPT = "~/honeytoken-log.sh"
STATE_FILE = Path(__file__).resolve().parent.parent / ".honeytoken-pull-state.json"
POLL_SECONDS = 20


def _last_id() -> int:
    try:
        return int(json.loads(STATE_FILE.read_text()).get("last_id", 0))
    except Exception:
        return 0


def _save_last_id(n: int):
    STATE_FILE.write_text(json.dumps({"last_id": n}))


def _push_alert(rdb, alert: dict):
    alert.setdefault("ts", datetime.now(timezone.utc).isoformat())
    alert.setdefault("source", "honeytoken")
    payload = json.dumps(alert)
    rdb.lpush("alerts", payload)
    rdb.ltrim("alerts", 0, 9999)
    rdb.publish("alerts_channel", payload)


def _pull_once():
    c = cfg()
    alias = (c.get("vulnbox") or {}).get("capture_ssh_alias") or ""
    if not alias:
        return
    default_flag = (c.get("honeytoken") or {}).get("flag", "")
    last_id = _last_id()
    code, out = ssh(alias, f"{LOG_SCRIPT} since {last_id}", timeout=20)
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
            continue
        max_id = max(max_id, rec_id)
        kind = rec.get("kind")
        src_ip = str(rec.get("src_ip") or rec.get("vulnbox") or "unknown")[:64]
        detail = str(rec.get("detail") or "")[:500]
        if kind == "trap-hit":
            flag = detail or default_flag
            _push_alert(rdb, {
                "type": "honeytoken",
                "confidence": "HIGH",
                "message": f"HONEYTOKEN GET from {src_ip}! Flag in URL: {flag[:50]}",
                "src_ip": src_ip,
                "flag": flag,
            })
        else:  # "file-access" or anything else from the inotify watcher
            _push_alert(rdb, {
                "type": "honeytoken",
                "confidence": "HIGH",
                "message": f"HONEYTOKEN ACCESSED from {src_ip}! Decoy flag touched at {detail} — attacker active.",
                "src_ip": src_ip,
                "flag": default_flag,
            })
    if max_id != last_id:
        _save_last_id(max_id)


def honeytoken_pull_loop():
    while True:
        try:
            _pull_once()
        except Exception as e:
            print(f"[host-agent] honeytoken pull error: {e!r}", flush=True)
        time.sleep(POLL_SECONDS)
