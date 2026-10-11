"""Events tab: every source normalized into one shape, searchable, exportable
as plain text. Sources each push JSON into their own Redis list; this module is
the only place that knows how to read all of them."""
import json

from fastapi import APIRouter
from fastapi.responses import PlainTextResponse

from ..core.redisclient import get_redis

router = APIRouter()

EVENT_SOURCES = {"alerts": 10000, "hints": 5000, "ioc_results": 1000, "audit": 1000}
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


def severity_of(e: dict) -> str:
    t = (e.get("type") or "").lower()
    if t in ("flag-out", "honeytoken", "honeytoken-out"):
        return "CRITICAL"
    if t == "suricata":
        return "CRITICAL" if (e.get("severity") or 3) <= 1 else "HIGH"
    if t == "sla-down":
        return "HIGH"
    if t == "proxy-blocked":
        return "MEDIUM"
    if t == "flag-echo":
        return "LOW"
    if t == "flag-planted":
        return "INFO"
    if t in ("sla-slow", "rule-change-failed", "service-control-failed", "retention-failed"):
        return "MEDIUM"
    if t == "ioc-analysis":
        sev = str((e.get("ioc") or {}).get("severity", "")).upper()
        return sev if sev in SEVERITIES else "INFO"
    if t == "bot-deviation-hint":
        return "LOW"
    return "INFO"


def normalize(raw: str, list_name: str) -> dict:
    e = json.loads(raw)
    if e.get("type") == "ioc-analysis":
        ioc = e.get("ioc") or {}
        msg = ioc.get("technique") or ioc.get("analysis_notes") or "IOC analysis"
        src = ioc.get("attacker_ip")
    else:
        msg = e.get("message") or e.get("type") or ""
        src = e.get("src_ip")
    return {
        "ts": e.get("ts") or "",
        "severity": severity_of(e),
        "source": e.get("source") or ("ioc-brain" if list_name == "ioc_results" else list_name),
        "type": e.get("type") or "?",
        "src_ip": src,
        "dst_ip": e.get("dst_ip"),
        "dst_port": e.get("dst_port") or e.get("port"),
        "service": e.get("service"),
        "flow_id": e.get("flow_id"),
        "ts_packet": e.get("ts_packet"),
        "sid": e.get("sid"),
        "message": str(msg),
        "raw": e,
    }


async def collect(q: str, source: str, severity: str, limit: int) -> list[dict]:
    rdb = get_redis()
    ql = q.lower().strip()
    out = []
    for name, cap in EVENT_SOURCES.items():
        for raw in await rdb.lrange(name, 0, cap - 1):
            if ql and ql not in raw.lower():
                continue
            try:
                ev = normalize(raw, name)
            except (ValueError, TypeError):
                continue
            if source and ev["source"] != source:
                continue
            if severity and ev["severity"] != severity:
                continue
            out.append(ev)
    out.sort(key=lambda e: e["ts"], reverse=True)
    return out[:limit]


def to_log_line(e: dict) -> str:
    flow = f"{e['src_ip'] or '-'} -> {e['dst_ip'] or '-'}" + (f":{e['dst_port']}" if e["dst_port"] else "")
    kind = (e["source"] + "/" + e["type"])[:32]
    return f"{e['ts'][:19]:19}  {e['severity']:8}  {kind:32}  {flow:38}  {e['message']}"


@router.get("/api/events")
async def get_events(q: str = "", source: str = "", severity: str = "", limit: int = 500):
    return await collect(q, source, severity, min(limit, 5000))


@router.get("/api/events.log")
async def get_events_log(q: str = "", source: str = "", severity: str = "", limit: int = 5000):
    """Same events as /api/events, one plain-text line each, oldest first —
    readable with less/grep even if the dashboard UI itself is broken."""
    evs = await collect(q, source, severity, min(limit, 20000))
    header = "# time(UTC)            SEVERITY  source/type                       src -> dst:port                         message\n"
    body = "\n".join(to_log_line(e) for e in reversed(evs))
    return PlainTextResponse(header + body + "\n", headers={"Content-Disposition": "inline; filename=ctf-events.log"})
