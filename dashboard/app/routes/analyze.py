"""LLM analysis proxy, so the browser never needs a direct route to ioc-brain."""
import asyncio
import json
import urllib.request

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from ..core.config import IOC_API_URL

router = APIRouter()


@router.post("/api/analyze")
async def analyze(body: dict):
    def call():
        req = urllib.request.Request(f"{IOC_API_URL}/analyze", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=240) as r:
            return json.loads(r.read())
    try:
        return await asyncio.to_thread(call)
    except Exception as e:
        return JSONResponse({"error": f"IOC Brain unreachable or failed: {e}"}, status_code=502)
