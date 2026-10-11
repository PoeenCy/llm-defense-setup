"""Rules tab. Reads are local (Suricata rules are a read-only mount) or via
host_agent (ctf_proxy filters live on the vulnbox-host). Every WRITE goes
through host_agent, which validates before touching anything live and keeps a
backup for rollback."""
from fastapi import APIRouter
from fastapi.responses import JSONResponse

from ..core.config import LIBRARY_DIR, RULES_PATH
from ..core.ops import run_op
from ..rulegen import ctfproxy, suricata

router = APIRouter(prefix="/api/rules")


def _live_suricata_rules() -> str:
    return RULES_PATH.read_text() if RULES_PATH.exists() else ""


# ── Suricata ──────────────────────────────────────────────────────────────────
@router.get("/suricata")
async def get_suricata():
    if not RULES_PATH.exists():
        return JSONResponse({"rules": "", "note": f"{RULES_PATH} not mounted"}, status_code=404)
    return {"rules": _live_suricata_rules()}


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


# ── ctf_proxy filters (remote) ────────────────────────────────────────────────
@router.get("/ctfproxy")
async def get_ctfproxy():
    return await run_op("ctfproxy_get")


@router.post("/ctfproxy")
async def apply_ctfproxy(body: dict):
    source = body.get("source", "")
    errs = ctfproxy.validate_module(source)
    if errs:
        return {"ok": False, "output": "Not uploaded — the filter file has problems:\n" + "\n".join(errs)}
    return await run_op("ctfproxy_apply", {"source": source})


@router.post("/ctfproxy/rollback")
async def rollback_ctfproxy():
    return await run_op("ctfproxy_rollback")


@router.post("/ctfproxy/delete")
async def delete_ctfproxy(body: dict):
    """One-click removal of a single live rule method by name — the undo
    button for APPLIED when a rule turns out to be blocking the checker."""
    return await run_op("ctfproxy_delete_method", {"name": str(body.get("name", ""))}, wait_s=40)


@router.post("/ctfproxy/build")
async def build_ctfproxy(body: dict):
    """Form → Python method, spliced into the current filter source the UI
    sends along. Returns the new full source for review; nothing is uploaded."""
    source = body.get("source", "")
    res = ctfproxy.build_filter(body.get("spec") or {}, source)
    if res["errors"]:
        return res
    try:
        res["source"] = ctfproxy.insert_method(source, res["code"])
    except ValueError as e:
        res["errors"] = [str(e)]
        return res
    res["errors"] = ctfproxy.validate_module(res["source"])
    return res


# ── Prepared rule library (rules-library/suricata/*.rules, read-only mount) ──
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
    return {"dir": "rules-library/suricata/", "files": out}


@router.get("/library/{name}")
async def get_library_file(name: str):
    for f in _lib_files():
        if f.name == name:
            return {"file": f.name, "text": f.read_text(errors="replace")}
    return JSONResponse({"error": "no such library file"}, status_code=404)
