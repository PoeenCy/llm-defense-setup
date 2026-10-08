#!/usr/bin/env python3
"""
dashboard_server.py — CTF Monitor Hub: Unified Dashboard Backend (Item 8)

Serves the single-page dashboard and a WebSocket feed for real-time alerts.
Aggregates: alert queue (detection), ML hints, watchdog status, IOC results.
"""
import asyncio
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Set

import redis.asyncio as aioredis
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
import uvicorn

logging.basicConfig(level=logging.INFO, format="%(asctime)s [DASHBOARD] %(levelname)s %(message)s")
log = logging.getLogger("dashboard")

REDIS_HOST    = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT    = int(os.environ.get("REDIS_PORT", 6379))
TULIP_URL     = os.environ.get("TULIP_URL", "http://localhost:3000")
IOC_API_URL   = os.environ.get("IOC_API_URL", "http://ioc-brain:5001")
MONITOR_IP    = os.environ.get("MONITOR_IP", "10.0.0.50")
VULNBOX_IP    = os.environ.get("VULNBOX_IP", "10.0.0.2")

CONFIG_PATH = Path(os.environ.get("CONFIG", "/app/services.json"))
if CONFIG_PATH.exists():
    with open(CONFIG_PATH) as f:
        CFG = json.load(f)
else:
    CFG = {}

app = FastAPI(title="CTF Monitor Dashboard", docs_url=None)

# ── WebSocket connection manager ──────────────────────────────────────────────
class ConnectionManager:
    def __init__(self):
        self.active: Set[WebSocket] = set()

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

# ── Redis pub/sub relay → WebSocket ──────────────────────────────────────────
async def redis_subscriber():
    """Subscribe to Redis channels and relay to WebSocket clients."""
    rdb = aioredis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    pubsub = rdb.pubsub()
    await pubsub.subscribe("alerts_channel", "hints_channel")
    log.info("Redis subscriber ready")
    async for msg in pubsub.listen():
        if msg["type"] == "message":
            try:
                data = json.loads(msg["data"])
                data["channel"] = msg["channel"]
                await manager.broadcast(data)
            except Exception as e:
                log.debug("Relay error: %s", e)

@app.on_event("startup")
async def startup():
    asyncio.create_task(redis_subscriber())
    log.info("Dashboard started. Tulip: %s  IOC API: %s", TULIP_URL, IOC_API_URL)

@app.get("/health")
async def health():
    return {"status": "ok", "service": "dashboard"}

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket):
    await manager.connect(ws)
    # Send current state on connect
    rdb = aioredis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    try:
        alerts = await rdb.lrange("alerts", 0, 49)
        hints  = await rdb.lrange("hints", 0, 29)
        wstatus = await rdb.hgetall("watchdog_status")
        iocs = await rdb.lrange("ioc_results", 0, 9)

        await ws.send_json({
            "type": "initial_state",
            "alerts": [json.loads(a) for a in alerts],
            "hints":  [json.loads(h) for h in hints],
            "watchdog": {k: json.loads(v) for k, v in wstatus.items()},
            "iocs": [json.loads(i) for i in iocs],
            "config": {
                "tulip_url": TULIP_URL,
                "monitor_ip": MONITOR_IP,
                "vulnbox_ip": VULNBOX_IP,
            }
        })
    except Exception as e:
        log.error("Initial state error: %s", e)

    try:
        while True:
            data = await ws.receive_text()
            # Echo commands back (for future interactivity)
            await ws.send_json({"type": "ack", "echo": data})
    except WebSocketDisconnect:
        manager.disconnect(ws)

@app.get("/api/alerts")
async def get_alerts(n: int = 100):
    rdb = aioredis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    raw = await rdb.lrange("alerts", 0, n - 1)
    return [json.loads(r) for r in raw]

@app.get("/api/hints")
async def get_hints(n: int = 50):
    rdb = aioredis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    raw = await rdb.lrange("hints", 0, n - 1)
    return [json.loads(r) for r in raw]

@app.get("/api/watchdog")
async def get_watchdog():
    rdb = aioredis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    raw = await rdb.hgetall("watchdog_status")
    return {k: json.loads(v) for k, v in raw.items()}

@app.get("/api/iocs")
async def get_iocs(n: int = 20):
    rdb = aioredis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    raw = await rdb.lrange("ioc_results", 0, n - 1)
    return [json.loads(r) for r in raw]

@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Serve the single-page dashboard."""
    html_path = Path(__file__).parent / "index.html"
    if html_path.exists():
        return HTMLResponse(html_path.read_text())
    return HTMLResponse("<h1>Dashboard loading...</h1>")

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")
