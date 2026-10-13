"""Bridge to host_agent.py. This container has no docker socket and no SSH
keys; anything needing host privileges is queued here as a named action and
executed (or refused) by host_agent's whitelist."""
import asyncio
import json
import uuid

from .redisclient import get_redis

AGENT_DOWN = {
    "ok": False,
    "output": "host_agent.py did not answer — is it running? Re-run deploy-all.sh, or: python3 host_agent.py &",
}


async def run_op(action: str, payload: dict | None = None, wait_s: int = 120) -> dict:
    rdb = get_redis()
    req_id = uuid.uuid4().hex
    await rdb.rpush("ops_requests", json.dumps({"id": req_id, "action": action, "payload": payload or {}}))
    for _ in range(wait_s * 4):
        res = await rdb.get(f"ops_result:{req_id}")
        if res:
            return json.loads(res)
        await asyncio.sleep(0.25)
    return AGENT_DOWN
