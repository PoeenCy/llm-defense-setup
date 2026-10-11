"""System Status panel + small metadata endpoint the UI uses for defaults."""
import json
import time

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from ..core.config import load_services_config
from ..core.redisclient import get_redis

router = APIRouter()


@router.get("/api/status")
async def get_status():
    """Written by host_agent.py every 15s with a 120s TTL; a missing key means
    the agent itself isn't running, which is worth surfacing as such."""
    raw = await get_redis().get("system_status")
    if raw is None:
        return JSONResponse({
            "checked_at": 0, "items": [], "stale": True,
            "note": "No status data — host_agent.py is not running. Re-run deploy-all.sh, or: python3 host_agent.py &",
        })
    data = json.loads(raw)
    data["stale"] = (time.time() - data.get("checked_at", 0)) > 60
    return data


@router.get("/api/meta")
async def get_meta():
    cfg = load_services_config()
    return {
        "team_id": cfg.get("team_id"),
        "vulnbox_ip": cfg.get("vulnbox", {}).get("ip"),
        "monitor_ip": cfg.get("monitor_host", {}).get("ip"),
        "tulip_port": cfg.get("tulip", {}).get("web_port", 3000),
        "flag_regex": cfg.get("flag", {}).get("regex"),
        "services": [{"name": s.get("name"), "port": s.get("port"), "layer": s.get("layer")}
                     for s in cfg.get("services", [])],
        "ctfproxy_enabled": cfg.get("ctf_proxy", {}).get("insertion", {}).get("mode") == "docker-compose",
    }
