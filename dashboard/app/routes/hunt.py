"""HUNT tab: look back at what an attacker did. Combines
  - the event log (Redis: alerts, hints, LLM results, audit; last ~10k each)
  - Tulip's flow database (every captured connection, request + response text)
filtered by IP, port, time range and text/regex."""
import asyncio
import json
import re
import urllib.request
from collections import Counter

from fastapi import APIRouter

from ..core.config import TULIP_API_URL
from .events import collect
from .tulip import _parse_ts

router = APIRouter(prefix="/api/hunt")


def _tulip_query(q: dict) -> list:
    req = urllib.request.Request(f"{TULIP_API_URL}/query", data=json.dumps(q).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


@router.post("")
async def hunt(body: dict):
    ip = (body.get("ip") or "").strip()
    port = body.get("port") or None
    since, until = _parse_ts(body.get("since")), _parse_ts(body.get("until"))
    text = (body.get("text") or "").strip()
    is_regex = bool(body.get("regex"))
    if is_regex and text:
        try:
            re.compile(text)
        except re.error as e:
            return {"error": f"bad regex: {e}"}

    # 1) events
    evs = []
    for e in await collect("", "", "", 20000):
        if ip and ip not in (e.get("src_ip"), e.get("dst_ip")) and ip not in json.dumps(e["raw"]):
            continue
        if port and str(port) not in (str(e.get("dst_port")), str(e["raw"].get("src_port")), str(e["raw"].get("dst_port"))):
            continue
        t = _parse_ts(e.get("ts_packet") or e.get("ts"))
        if (since and t and t < since) or (until and t and t > until):
            continue
        if text:
            blob = json.dumps(e["raw"])
            if (is_regex and not re.search(text, blob, re.I)) or (not is_regex and text.lower() not in blob.lower()):
                continue
        evs.append(e)

    # 2) Tulip flows
    q = {}
    if since:
        q["time_from"] = since.isoformat()
    if until:
        q["time_to"] = until.isoformat()
    if port:
        q["port_dst"] = int(port)
    if text:
        q["regex_insensitive"] = text if is_regex else re.escape(text)
    queries = [{**q, "ip_src": ip + "/32"}, {**q, "ip_dst": ip + "/32"}] if ip else [q]
    flows, flow_err = {}, None
    try:
        for res in await asyncio.gather(*(asyncio.to_thread(_tulip_query, x) for x in queries)):
            for f in res:
                flows[f["id"]] = f
    except Exception as e:
        flow_err = f"Tulip query failed: {e}"
    flist = sorted(flows.values(), key=lambda f: f.get("time") or "", reverse=True)[:500]

    # 3) summary
    by_type = Counter(e["type"] for e in evs)
    peers = Counter()
    for f in flist:
        peers[f["ip_src"]] += 1
    times = [x for x in [*(e.get("ts_packet") or e.get("ts") for e in evs), *(f.get("time") for f in flist)] if x]
    return {
        "summary": {"events": len(evs), "flows": len(flows), "flows_shown": len(flist),
                    "first_seen": min(times) if times else None, "last_seen": max(times) if times else None,
                    "event_types": by_type.most_common(), "top_clients": peers.most_common(10)},
        "events": evs[:500],
        "flows": [{"id": f["id"], "time": f.get("time"), "src": f"{f['ip_src']}:{f['port_src']}",
                   "dst": f"{f['ip_dst']}:{f['port_dst']}", "tags": f.get("tags"),
                   "size": f.get("packets_size")} for f in flist],
        "flow_error": flow_err,
    }
