"""Rules tab. Reads are local (Suricata rules are a read-only mount) or via
host_agent (ctf_proxy filters live on the vulnbox-host). Every WRITE goes
through host_agent, which validates before touching anything live and keeps a
backup for rollback."""
import ast
import re

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from ..core.config import LIBRARY_DIR, RULES_PATH, load_services_config
from ..core.ops import run_op
from ..core.redisclient import get_redis
from ..rulegen import ctfproxy, suricata

router = APIRouter(prefix="/api/rules")

_SID_RE = re.compile(r'sid\s*:\s*(\d+)')
_MSG_RE = re.compile(r'msg\s*:\s*"((?:[^"\\]|\\.)*)"')
# Same Redis keys hostagent/actions/{suricata,ctfproxy}.py write to on apply/delete.
_ADDED_KEY = "suricata_rule_added"
_CF_ADDED_KEY_PREFIX = "ctfproxy_rule_added:"


def _ctfproxy_services() -> list[dict]:
    """Mirrors hostagent/actions/ctfproxy.py's eligible_services() -- duplicated
    here because the dashboard container and host_agent.py (which runs directly
    on the monitor host, not in a container) don't share a Python module, only
    the same services.json. Keep both in sync if the eligibility rule
    (proto == "tcp") ever changes. UDP services are never eligible -- ctf_proxy
    only proxies TCP/HTTP."""
    c = load_services_config()
    ins = c.get("ctf_proxy", {}).get("insertion", {})
    out = []
    for s in c.get("services", []):
        if s.get("proto", "tcp") != "tcp":
            continue
        out.append({
            "name": s["name"],
            "http": s.get("layer") in ("l7-http", "l7-https"),
            "compose_service": s.get("compose_service") or ins.get("remote_compose_service") or "",
        })
    return out


def _live_suricata_rules() -> str:
    return RULES_PATH.read_text() if RULES_PATH.exists() else ""


def _parse_rules(text: str, added: dict) -> list[dict]:
    """One row per active (non-comment, non-blank) line -- a numbered,
    structured view of the same file the raw-text editor shows, so the UI can
    list/delete one rule at a time instead of one wall of text."""
    rows = []
    n = 0
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        n += 1
        sid_m = _SID_RE.search(s)
        msg_m = _MSG_RE.search(s)
        sid = sid_m.group(1) if sid_m else None
        rows.append({
            "n": n,
            "sid": sid,
            "msg": msg_m.group(1) if msg_m else s[:80],
            "line": s,
            "added": added.get(sid) if sid else None,
        })
    return rows


# ── Suricata ──────────────────────────────────────────────────────────────────
@router.get("/suricata")
async def get_suricata():
    if not RULES_PATH.exists():
        return JSONResponse({"rules": "", "parsed": [], "note": f"{RULES_PATH} not mounted"}, status_code=404)
    text = _live_suricata_rules()
    try:
        added = await get_redis().hgetall(_ADDED_KEY)
    except Exception:
        added = {}
    return {"rules": text, "parsed": _parse_rules(text, added)}


@router.post("/suricata")
async def apply_suricata(body: dict):
    return await run_op("suricata_apply", {"rules": body.get("rules", "")})


@router.post("/suricata/rollback")
async def rollback_suricata():
    return await run_op("suricata_rollback")


@router.post("/suricata/delete")
async def delete_suricata(body: dict):
    """One-click removal of a single live rule by sid — the undo button for
    APPLIED when a rule turns out to be hurting SLA."""
    return await run_op("suricata_delete_rule", {"sid": str(body.get("sid", ""))})


@router.post("/suricata/build")
async def build_suricata(spec: dict):
    """Form → rule text. Nothing is applied; the UI shows the rule, then the
    user can test it against traffic and/or add it to the ruleset."""
    return suricata.build_rule(spec, _live_suricata_rules())


@router.post("/suricata/test-traffic")
async def test_suricata_on_traffic(body: dict):
    """Run candidate rule(s) over the most recent captured pcaps in a separate,
    throwaway Suricata process and report what WOULD have matched — the way to
    catch a rule that also fires on the checker bot before it goes live."""
    files = max(1, min(int(body.get("files", 30)), 300))
    return await run_op("suricata_test_traffic", {"rules": body.get("rules", ""), "files": files}, wait_s=300)


def _parse_ctfproxy_methods(source: str, added: dict) -> list[dict]:
    """One row per rule method on class Module (excluding execute/dunders) --
    the structured view the UI table shows, mirroring Suricata's _parse_rules."""
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    rows, n = [], 0
    for node in ast.walk(tree):
        if not (isinstance(node, ast.ClassDef) and node.name == "Module"):
            continue
        for f in node.body:
            if not isinstance(f, ast.FunctionDef) or f.name == "execute" or f.name.startswith("__"):
                continue
            n += 1
            doc = (ast.get_docstring(f) or "").split(" [generated")[0].strip()
            rows.append({"n": n, "name": f.name, "desc": doc or f.name, "added": added.get(f.name)})
    return rows


# ── ctf_proxy filters (remote) ────────────────────────────────────────────────
@router.get("/ctfproxy/services")
async def list_ctfproxy_services():
    """Pure local config read (no host_agent round-trip) so the service picker
    in the UI populates instantly. One ctf_proxy deployment fronts every TCP
    service in services.json; UDP services are never eligible here."""
    return {"ok": True, "services": _ctfproxy_services()}


@router.get("/ctfproxy")
async def get_ctfproxy(service: str = ""):
    result = await run_op("ctfproxy_get", {"service": service})
    if result.get("ok") and isinstance(result.get("source"), str):
        svc = result.get("service") or service
        try:
            added = await get_redis().hgetall(_CF_ADDED_KEY_PREFIX + svc) if svc else {}
        except Exception:
            added = {}
        result["parsed"] = _parse_ctfproxy_methods(result["source"], added)
    return result


@router.post("/ctfproxy")
async def apply_ctfproxy(body: dict):
    source = body.get("source", "")
    errs = ctfproxy.validate_module(source)
    if errs:
        return {"ok": False, "output": "Not uploaded — the filter file has problems:\n" + "\n".join(errs)}
    return await run_op("ctfproxy_apply", {"source": source, "service": body.get("service", "")})


@router.post("/ctfproxy/rollback")
async def rollback_ctfproxy(body: dict = None):
    return await run_op("ctfproxy_rollback", {"service": (body or {}).get("service", "")})


@router.post("/ctfproxy/delete")
async def delete_ctfproxy(body: dict):
    """One-click removal of a single live rule method by name — the undo
    button for APPLIED when a rule turns out to be blocking the checker."""
    return await run_op("ctfproxy_delete_method",
                         {"name": str(body.get("name", "")), "service": body.get("service", "")}, wait_s=40)


@router.post("/ctfproxy/build")
async def build_ctfproxy(body: dict):
    """Form → Python method, spliced into the current filter source the UI
    sends along. Returns the new full source for review; nothing is uploaded.
    stream_type follows the picked service's layer: raw TCP services only get
    target="raw" (no HTTP parsing to pull url/path/param/header from)."""
    source = body.get("source", "")
    service = body.get("service", "")
    svc_info = next((s for s in _ctfproxy_services() if s["name"] == service), None) if service else None
    stream_type = "tcp" if svc_info and not svc_info["http"] else "http"
    res = ctfproxy.build_filter(body.get("spec") or {}, source, stream_type=stream_type)
    if res["errors"]:
        return res
    try:
        res["source"] = ctfproxy.insert_method(source, res["code"])
    except ValueError as e:
        res["errors"] = [str(e)]
        return res
    res["errors"] = ctfproxy.validate_module(res["source"])
    return res


# ── Prepared rule library (contest-runtime/detection/rules-library/*.rules, read-only mount) ──
def _lib_files():
    d = LIBRARY_DIR / "suricata"
    return sorted(d.glob("*.rules")) if d.is_dir() else []


@router.get("/library")
async def list_library():
    out = []
    for f in _lib_files():
        text = f.read_text(errors="replace")
        first = next((ln.lstrip("# ").strip() for ln in text.splitlines() if ln.startswith("#")), f.stem)
        out.append({"file": f.name, "title": first,
                    "count": sum(1 for ln in text.splitlines() if ln.startswith(("alert", "drop", "pass")))})
    return {"dir": "contest-runtime/detection/rules-library/", "files": out}


@router.get("/library/{name}")
async def get_library_file(name: str):
    for f in _lib_files():
        if f.name == name:
            return {"file": f.name, "text": f.read_text(errors="replace")}
    return JSONResponse({"error": "no such library file"}, status_code=404)
