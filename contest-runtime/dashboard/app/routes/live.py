"""Monitor tab: real-time alert feed (WebSocket) + the original list endpoints."""
import asyncio
import json
import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..core.config import MONITOR_IP, VULNBOX_IP
from ..core.redisclient import get_redis

log = logging.getLogger("dashboard.live")
router = APIRouter()


class ConnectionManager:
    def __init__(self):
        self.active: set[WebSocket] = set()

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.active.add(ws)

    def disconnect(self, ws: WebSocket):
        self.active.discard(ws)

    async def broadcast(self, msg: dict):
        dead = set()
        for ws in self.active:
            try:
                await ws.send_json(msg)
            except Exception:
                dead.add(ws)
        self.active -= dead


manager = ConnectionManager()


async def redis_subscriber():
    """Relay Redis pub/sub to every open browser tab. Reconnects forever —
    a Redis restart must not leave the dashboard silently deaf."""
    while True:
        try:
            pubsub = get_redis().pubsub()
            await pubsub.subscribe("alerts_channel", "hints_channel")
            log.info("Redis subscriber ready")
            async for msg in pubsub.listen():
                if msg["type"] != "message":
                    continue
                try:
                    data = json.loads(msg["data"])
                    data["channel"] = msg["channel"]
                    await manager.broadcast(data)
                except Exception as e:
                    log.debug("Relay error: %s", e)
        except Exception as e:
            log.warning("Redis subscriber lost (%s), retrying in 3s", e)
            await asyncio.sleep(3)


def _loads(items):
    out = []
    for raw in items:
        try:
            out.append(json.loads(raw))
        except ValueError:
            pass
    return out


@router.get("/health")
async def health():
    return {"status": "ok", "service": "dashboard"}


@router.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    rdb = get_redis()
    try:
        wstatus = await rdb.hgetall("watchdog_status")
        await ws.send_json({
            "type": "initial_state",
            "alerts": _loads(await rdb.lrange("alerts", 0, 49)),
            "hints": _loads(await rdb.lrange("hints", 0, 29)),
            "watchdog": {k: json.loads(v) for k, v in wstatus.items()},
            "iocs": _loads(await rdb.lrange("ioc_results", 0, 9)),
            "config": {"monitor_ip": MONITOR_IP, "vulnbox_ip": VULNBOX_IP},
        })
    except Exception as e:
        log.error("Initial state error: %s", e)
    try:
        while True:
            await ws.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(ws)


@router.get("/api/alerts")
async def get_alerts(n: int = 100):
    return _loads(await get_redis().lrange("alerts", 0, n - 1))


@router.get("/api/hints")
async def get_hints(n: int = 50):
    return _loads(await get_redis().lrange("hints", 0, n - 1))


@router.get("/api/watchdog")
async def get_watchdog():
    raw = await get_redis().hgetall("watchdog_status")
    return {k: json.loads(v) for k, v in raw.items()}


@router.get("/api/iocs")
async def get_iocs(n: int = 20):
    return _loads(await get_redis().lrange("ioc_results", 0, n - 1))
