"""Bridge to the Flag-trace API; database files stay out of the dashboard.

Only the routes below are forwarded, so this is not a general proxy into the
internal network. There are two writes, and only their one field is passed on:
a retrace request (its idempotency key), which enqueues an analysis job, and
the decoder mode ingest reads before each capture.
"""
import asyncio
import json
import os
import re
import urllib.error
import urllib.request

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

router = APIRouter(prefix="/api/flagtrace")
BASE = os.environ.get("FLAGTRACE_API_URL", "http://flagtrace:8095")
H = "[0-9a-f]{64}"
READ_ROUTES = re.compile(rf"(status|health|transactions|flagouts|trace-status|traces|decoder|trace-groups"
                         rf"|trace-groups/{H}/members|chain-groups|chain-groups/{H}"
                         rf"|transactions/{H}|transactions/{H}/evidence"
                         rf"|traces/{H}|traces/{H}/runs|traces/{H}/runs/{H}"
                         rf"|traces/{H}/runs/{H}/scripts/{H})")
RETRACE_ROUTE = re.compile(rf"traces/{H}/retrace")
IDEMPOTENCY_KEY = re.compile(r"[A-Za-z0-9_.:-]{1,128}")
DECODER_MODES = ("full", "gated", "off", "default")


def _call(path, body=None):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(BASE + path, data=data, method="GET" if body is None else "POST",
                                     headers={"Content-Type": "application/json"} if data else {})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return JSONResponse(json.loads(response.read()), status_code=response.status)
    except urllib.error.HTTPError as exc:
        with exc:
            try:
                return JSONResponse(json.loads(exc.read()), status_code=exc.code)
            except ValueError:
                return JSONResponse({"error": f"Flag-trace returned HTTP {exc.code}"}, status_code=exc.code)
    except (OSError, ValueError):
        return JSONResponse({"error": "Flag-trace unavailable; check enabled config and service status"},
                            status_code=503)


@router.get("/{path:path}")
async def read(path: str, request: Request):
    if not READ_ROUTES.fullmatch(path):
        return JSONResponse({"error": "unknown endpoint"}, status_code=404)
    query = ("?" + request.url.query) if request.url.query else ""
    return await asyncio.to_thread(_call, "/" + path + query)


@router.post("/{path:path}")
async def write(path: str, request: Request):
    try:
        body = await request.json()
    except ValueError:
        body = None
    if path == "decoder":
        mode = body.get("mode") if isinstance(body, dict) else None
        if mode not in DECODER_MODES:
            return JSONResponse({"error": "mode must be one of " + ", ".join(DECODER_MODES)}, status_code=400)
        return await asyncio.to_thread(_call, "/decoder", {"mode": mode})
    if not RETRACE_ROUTE.fullmatch(path):
        return JSONResponse({"error": "unknown endpoint"}, status_code=404)
    key = body.get("idempotency_key") if isinstance(body, dict) else None
    if not isinstance(key, str) or not IDEMPOTENCY_KEY.fullmatch(key):
        return JSONResponse({"error": "idempotency_key required"}, status_code=400)
    return await asyncio.to_thread(_call, "/" + path, {"idempotency_key": key})
