"""APPLIED tab: every rule that is live right now, where it lives, and how
often it fired. Hit counts come from the event log (Redis "alerts"):
  Suricata  -> "suricata" events, by sid
  ctf_proxy -> "proxy-blocked" events (detection sees the block answer
               "<keyword> <service> <rule>" in captured responses), by rule name
"""
import json
import re
from collections import Counter, defaultdict

from fastapi import APIRouter

from ..core.config import RULES_PATH
from ..core.ops import run_op
from ..core.redisclient import get_redis
from ..rulegen.ctfproxy import existing_methods

router = APIRouter(prefix="/api/applied")

_SID = re.compile(r"\bsid\s*:\s*(\d+)")
_MSG = re.compile(r'\bmsg\s*:\s*"((?:[^"\\]|\\.)*)"')
_MSG_SID = re.compile(r"^\[(\d+)\]")


def _hits(events, key):
    agg = defaultdict(lambda: {"hits": 0, "last": "", "sources": Counter()})
    for e in events:
        k = key(e)
        if not k:
            continue
        a = agg[k]
        a["hits"] += 1
        ts = e.get("ts_packet") or e.get("ts") or ""
        a["last"] = max(a["last"], ts)
        src = e.get("dst_ip") if e.get("type") == "proxy-blocked" else e.get("src_ip")
        if src:
            a["sources"][src] += 1
    return agg


def _fmt(a):
    return {"hits": a["hits"], "last_hit": a["last"], "top_sources": [f"{ip} ×{n}" for ip, n in a["sources"].most_common(3)]}


@router.get("")
async def applied(proxy: int = 0):
    rdb = get_redis()
    events = []
    for raw in await rdb.lrange("alerts", 0, 9999):
        try:
            events.append(json.loads(raw))
        except ValueError:
            continue

    # ── Suricata (monitor host) ──
    sur = _hits([e for e in events if e.get("type") == "suricata"],
                lambda e: str(e.get("sid") or (_MSG_SID.match(e.get("message") or "") or [None, None])[1] or ""))
    rules = []
    text = RULES_PATH.read_text(errors="replace") if RULES_PATH.exists() else ""
    for n, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if not re.match(r"^(alert|drop|reject|pass)\s", s):
            continue
        sid = (_SID.search(s) or [None, ""])[1]
        rules.append({"sid": sid, "msg": (_MSG.search(s) or [None, ""])[1], "action": s.split()[0], "line": n,
                      **_fmt(sur.get(sid, {"hits": 0, "last": "", "sources": Counter()}))})
    disabled = sum(1 for ln in text.splitlines() if re.match(r"^\s*#\s*(alert|drop)\s", ln))

    # ── ctf_proxy (vulnbox) ──
    blk = _hits([e for e in events if e.get("type") == "proxy-blocked"], lambda e: e.get("rule"))
    proxy_info = {"location": "vulnbox: ctf-proxy-<team>/proxy/filter_modules/web/web_in.py (ctf_proxy reloads it on change)",
                  "loaded": False, "paused": None, "error": None, "methods": []}
    names = set(blk)
    if proxy:
        d = await run_op("ctfproxy_get", wait_s=40)
        if d.get("ok"):
            proxy_info.update(loaded=True, paused=d.get("paused"), location=d.get("path") or proxy_info["location"])
            names |= existing_methods(d["source"]) - {"execute"}
        else:
            proxy_info["error"] = d.get("output")
    proxy_info["methods"] = sorted(
        ({"name": n, **_fmt(blk.get(n, {"hits": 0, "last": "", "sources": Counter()}))} for n in names),
        key=lambda m: -m["hits"])

    # ── built-in detectors (not editable rules, but they raise events too) ──
    builtin = Counter(e.get("type") for e in events if e.get("type") not in ("suricata", "proxy-blocked"))
    return {
        "suricata": {"location": "monitor host: contest-runtime/detection/suricata/lib/rules/suricata.rules (Suricata reads the captured pcaps)",
                     "active": len(rules), "disabled": disabled, "rules": rules},
        "ctfproxy": proxy_info,
        "builtin": [{"type": t, "count": c} for t, c in builtin.most_common()],
        "window": f"last {len(events)} stored alerts",
    }
