"""Pull a captured flow's raw request/response out of Tulip, so the Rules tab
can turn "the exploit I'm looking at" directly into a rule. The dashboard
joins Tulip's internal network for this (see docker-compose.yml)."""
import asyncio
import base64
import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from ..core.config import TULIP_API_URL, load_services_config
from .. import decoders  # defence-side decode engine; Tulip itself stays vanilla

router = APIRouter(prefix="/api/tulip")

_UUID = re.compile(r"^[0-9a-fA-F-]{32,36}$")


def _fetch(url: str, body: dict | None = None):
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.loads(r.read())


# ── event -> Tulip flow ─────────────────────────────────────────────────────
# Detection / Suricata alerts are packet-level and carry no Tulip id. We find
# the flow by time window + IPs/ports (+ the flag text when there is one) via
# Tulip's own /query API. Results are cached: flows never change once stored.
_FLAG_IN_MSG = re.compile(r"(?:outbound|service): (\S+)")
_resolved: dict[tuple, dict] = {}


def _parse_ts(v: str | None):
    if not v:
        return None
    v = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", v.replace("Z", "+00:00"))
    try:
        t = datetime.fromisoformat(v)
    except ValueError:
        return None
    return t if t.tzinfo else t.replace(tzinfo=timezone.utc)


def _event_key(e: dict) -> tuple | None:
    raw = e.get("raw") or e
    ts = raw.get("ts_packet") or e.get("ts_packet") or raw.get("ts") or e.get("ts")
    src, dst = raw.get("src_ip") or e.get("src_ip"), raw.get("dst_ip") or e.get("dst_ip")
    if not ts or not (src or dst):
        return None
    flag = raw.get("flag")
    if not flag and str(raw.get("type", "")).startswith(("flag", "honeytoken")):
        m = _FLAG_IN_MSG.search(raw.get("message") or "")
        flag = m.group(1) if m else None
    return (ts, src, dst, raw.get("src_port"), raw.get("dst_port") or raw.get("port"), flag)


def _resolve_one(key: tuple) -> dict:
    ts, src, dst, sport, dport, flag = key
    t = _parse_ts(ts)
    if not t:
        return {"flow_id": None, "why": "event has no usable timestamp"}
    win = {"time_from": (t - timedelta(seconds=120)).isoformat(),
           "time_to": (t + timedelta(seconds=30)).isoformat()}
    queries = []
    if flag:
        queries.append({**win, "regex_insensitive": re.escape(flag)})
    for a, b in ((src, dst), (dst, src)):
        if a and b:
            queries.append({**win, "ip_src": a + "/32", "ip_dst": b + "/32"})
    flows = {}
    for q in queries:
        for f in _fetch(f"{TULIP_API_URL}/query", q):
            flows[f["id"]] = f
    if not flows:
        return {"flow_id": None, "why": "no Tulip flow in that time window (pcap not imported yet, or filtered by BPF)"}

    def score(f):
        s = 0
        pair = {f.get("ip_src"), f.get("ip_dst")}
        ports = {f.get("port_src"), f.get("port_dst")}
        if src in pair and dst in pair:
            s += 50
        elif src in pair or dst in pair:
            s += 10
        s += 20 * len({sport, dport} & ports - {None})
        if flag and ("flag-out" in (f.get("tags") or []) or "flag-in" in (f.get("tags") or [])):
            s += 5
        ft = _parse_ts(f.get("time"))
        if ft:
            s -= min(abs((ft - t).total_seconds()), 150) / 10
        return s

    ranked = sorted(flows.values(), key=score, reverse=True)
    best = ranked[0]
    exact = bool({src, dst} <= {best.get("ip_src"), best.get("ip_dst")})
    return {
        "flow_id": best["id"],
        "exact": exact,
        "why": "matched IPs" + (" + flag text" if flag else "") if exact else "closest flow in time — verify",
        "candidates": [{"id": f["id"], "src": f"{f['ip_src']}:{f['port_src']}", "dst": f"{f['ip_dst']}:{f['port_dst']}",
                        "time": f.get("time"), "tags": f.get("tags")} for f in ranked[:5]],
    }


def resolve_event(e: dict) -> dict:
    if e.get("flow_id"):
        return {"flow_id": e["flow_id"], "exact": True, "why": "event carries its flow id"}
    key = _event_key(e)
    if not key:
        return {"flow_id": None, "why": "event has no IP/time to search by"}
    if key not in _resolved:
        try:
            res = _resolve_one(key)
        except Exception as ex:
            return {"flow_id": None, "why": f"Tulip API unreachable: {ex}"}
        if not res["flow_id"]:
            return res           # don't cache misses: the pcap may still be importing
        if len(_resolved) > 20000:
            _resolved.clear()
        _resolved[key] = res
    return _resolved[key]


@router.post("/resolve")
async def resolve(body: dict):
    """body: {"events": [event, ...]} (max 100) -> list of {flow_id, exact, why, candidates}"""
    events = (body.get("events") or [])[:100]
    return await asyncio.to_thread(lambda: [resolve_event(e) for e in events])


@router.get("/flow/{flow_id}")
async def get_flow(flow_id: str):
    if not _UUID.match(flow_id):
        return JSONResponse({"error": "not a Tulip flow id (uuid)"}, status_code=400)
    try:
        flow = await asyncio.to_thread(_fetch, f"{TULIP_API_URL}/flow/{flow_id}")
    except urllib.error.HTTPError as e:
        return JSONResponse({"error": f"Tulip returned HTTP {e.code} (unknown flow id?)"}, status_code=404)
    except Exception as e:
        return JSONResponse({"error": f"Tulip API unreachable: {e}"}, status_code=502)
    # Tulip is vanilla here (no decoder), so every item is the raw conversation.
    # We decode on the dashboard side instead: for each message we run the decode
    # engine and surface any decoding that reveals a flag the raw bytes did not
    # already show (base64/gzip/xor/... exfil). The decodings go in `decoded`,
    # NOT in `messages`: the Rules tab builds rule content from client messages,
    # and bytes lifted from a *decoded* payload never appear on the wire, so a
    # rule written from them would never match.
    flag_re = decoders.compile_regex(
        (load_services_config().get("flag") or {}).get("regex"))
    messages, decoded = [], []
    for item in flow.get("items") or []:
        try:
            raw = base64.b64decode(item.get("data") or "")
        except (ValueError, TypeError):
            raw = b""
        direction = "client" if item.get("direction") == "c" else "server"
        entry = {"direction": direction, "time": item.get("time"),
                 "text": raw.decode("latin-1")}
        kind = item.get("kind") or "raw"
        if kind != "raw":
            # Back-compat: if a non-vanilla Tulip already produced a decoding.
            decoded.append({**entry, "kind": kind})
            continue
        messages.append(entry)
        if flag_re is None or not decoders.looks_encoded(raw):
            continue
        known = set(flag_re.findall(raw))
        for fnd in decoders.find_flags(raw, flag_re, known=known):
            decoded.append({
                "direction": direction,
                "time": item.get("time"),
                "kind": f"decode: {fnd.path}",
                "flags": [f.decode(errors="replace") for f in fnd.flags],
                "text": fnd.data.decode("latin-1", "replace")[:8000],
            })
    return {
        "id": flow.get("id"),
        "time": flow.get("time"),
        "src": f"{flow.get('ip_src')}:{flow.get('port_src')}",
        "dst": f"{flow.get('ip_dst')}:{flow.get('port_dst')}",
        "tags": flow.get("tags"),
        "flags": flow.get("flags"),
        "messages": messages,
        "decoded": decoded,
    }
