#!/usr/bin/env python3
"""
mock-vulnbox svc1 — toy HTTP service standing in for a real vulnbox service.

Intentional flaw (for ctf_proxy filter testing): /login builds a SQL-style
query by string formatting instead of parameterizing, so a payload containing
"' OR '1'='1" bypasses auth. This is deliberate — it's the target for the
example ctf_proxy filter module.
"""
import os
import random
import string
import time
import threading

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

FLAG_REGEX_LEN = 31  # matches services.json flag.regex [A-Z0-9]{31}=
USERS = {"admin": "sup3rs3cr3t"}
SESSIONS = set()

app = FastAPI(title="mock-vulnbox svc1")

_current_flag = {"value": None}


def _gen_flag() -> str:
    body = "".join(random.choices(string.ascii_uppercase + string.digits, k=FLAG_REGEX_LEN))
    return f"{body}="


def _flag_rotator():
    while True:
        _current_flag["value"] = _gen_flag()
        time.sleep(120)  # rotate once per tick (matches TICK_LENGTH=120000ms in Tulip)


threading.Thread(target=_flag_rotator, daemon=True).start()


@app.get("/health")
async def health():
    return {"status": "ok", "service": "mock-vulnbox-svc1"}


def _vulnerable_check(username: str, password: str) -> bool:
    """Deliberately vulnerable: naive string-built query, classic SQLi bypass."""
    query = f"SELECT 1 FROM users WHERE user='{username}' AND pass='{password}'"
    if "' OR '1'='1" in query or "OR 1=1" in query.upper():
        return True  # the "injection" succeeds
    return USERS.get(username) == password


@app.post("/login")
async def login(request: Request):
    body = await request.json()
    username = str(body.get("username", ""))
    password = str(body.get("password", ""))
    if _vulnerable_check(username, password):
        token = "".join(random.choices(string.ascii_letters + string.digits, k=16))
        SESSIONS.add(token)
        return {"status": "ok", "token": token}
    return JSONResponse(status_code=401, content={"status": "denied"})


@app.get("/flag")
async def get_flag(request: Request):
    token = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if token not in SESSIONS:
        return JSONResponse(status_code=403, content={"status": "forbidden"})
    return {"flag": _current_flag["value"]}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("SVC1_PORT", 9001)))
