"""CTF Monitor Hub dashboard — app wiring only. Each tab's API lives in its own
module under routes/; the UI is plain static files under static/ (one JS file
per tab, no build step, works offline)."""
import asyncio
import logging

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .core.config import MODE, STATIC_DIR
from .routes import applied, events, flagtrace, hunt, live, rules, services, status, tulip

logging.basicConfig(level=logging.INFO, format="%(asctime)s [DASHBOARD] %(levelname)s %(name)s: %(message)s")
logging.getLogger("dashboard").info("MODE=%s", MODE)

app = FastAPI(title="CTF Monitor Dashboard", docs_url=None, redoc_url=None)

for module in (live, status, events, rules, services, tulip, applied, hunt, flagtrace):
    app.include_router(module.router)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-cache"})


@app.on_event("startup")
async def startup():
    asyncio.create_task(live.redis_subscriber())
