import redis.asyncio as aioredis

from .config import REDIS_HOST, REDIS_PORT

_client = None


def get_redis() -> aioredis.Redis:
    """One shared connection pool for the whole app (the old single-file server
    opened a new client per request)."""
    global _client
    if _client is None:
        _client = aioredis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
    return _client
