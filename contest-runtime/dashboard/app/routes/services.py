"""Services tab (start/stop/restart) and Config tab (edit services.json).
Both are host-side actions; the whitelist of what may be controlled, and how,
lives in hostagent/registry.py — the dashboard can only name an id + op."""
import json
import re

from fastapi import APIRouter

from ..core.config import CONFIG_PATH
from ..core.ops import run_op

router = APIRouter()
_ID = re.compile(r"^[a-z0-9_-]{1,64}$")


@router.get("/api/services")
async def list_services():
    return await run_op("services_list", wait_s=60)


@router.post("/api/services/{svc_id}/{op}")
async def control_service(svc_id: str, op: str):
    if not _ID.match(svc_id) or op not in ("start", "stop", "restart", "pause_filter", "resume_filter", "uninstall"):
        return {"ok": False, "output": "invalid service id or operation"}
    return await run_op("service_control", {"id": svc_id, "op": op}, wait_s=180)


@router.get("/api/config")
async def get_config():
    return {"text": CONFIG_PATH.read_text() if CONFIG_PATH.exists() else ""}


@router.post("/api/config/validate")
async def validate_config(body: dict):
    text = body.get("text", "")
    try:
        json.loads(text)
    except ValueError as e:
        return {"ok": False, "output": f"Not valid JSON: {e}"}
    return await run_op("config_validate", {"text": text}, wait_s=60)


@router.post("/api/config")
async def save_config(body: dict):
    text = body.get("text", "")
    try:
        json.loads(text)
    except ValueError as e:
        return {"ok": False, "output": f"Not valid JSON: {e}"}
    return await run_op("config_apply", {"text": text, "restart": bool(body.get("restart", True))}, wait_s=300)


@router.post("/api/config/rollback")
async def rollback_config():
    return await run_op("config_rollback")


@router.get("/api/config/redeploy-log")
async def redeploy_log():
    return await run_op("config_redeploy_log", wait_s=20)


# ── Fallback firewall (vulnbox iptables) — block an attacker IP when ctf_proxy
#    isn't in the path. See hostagent/actions/firewall.py for the why. ──
@router.get("/api/firewall")
async def firewall_list():
    return await run_op("firewall_list", wait_s=40)


@router.post("/api/firewall/{op}")
async def firewall_op(op: str, body: dict):
    if op not in ("block", "unblock"):
        return {"ok": False, "output": "op must be block or unblock"}
    return await run_op(f"firewall_{op}", {"ip": body.get("ip", "")}, wait_s=40)


# ── Content-based fallback block — drops TCP packets by payload literal
#    (iptables string match), works even if attacker shares an IP with the
#    checker bot. See hostagent/actions/firewall.py for the why. ──
@router.get("/api/firewall/content")
async def firewall_content_list():
    return await run_op("firewall_content_list", wait_s=40)


@router.post("/api/firewall/content/{op}")
async def firewall_content_op(op: str, body: dict):
    if op not in ("block", "unblock"):
        return {"ok": False, "output": "op must be block or unblock"}
    return await run_op(f"firewall_content_{op}",
                        {"pattern": body.get("pattern", ""), "port": body.get("port")}, wait_s=40)


# ── OS-watchdog allowlist — mark a specific (alert type, detail substring)
#    as known-good (e.g. the organizer's checker legitimately exec'ing in to
#    plant/verify a flag) so the baseline-diff watchdog stops re-reporting
#    exactly that, without silencing any other/new kind of alert. ──
@router.get("/api/oswatchdog/allowlist")
async def oswatchdog_allowlist():
    return await run_op("oswatchdog_list_allowed", wait_s=20)


@router.post("/api/oswatchdog/allow")
async def oswatchdog_allow(body: dict):
    return await run_op("oswatchdog_allow", {"alert_type": body.get("alert_type", ""), "pattern": body.get("pattern", "")}, wait_s=20)


@router.post("/api/oswatchdog/unallow")
async def oswatchdog_unallow(body: dict):
    return await run_op("oswatchdog_unallow", {"alert_type": body.get("alert_type", ""), "pattern": body.get("pattern", "")}, wait_s=20)
