"""Helpers shared by every host-agent action."""
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import redis

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "services.json"


def cfg() -> dict:
    return json.loads(CONFIG_PATH.read_text())


def redis_client() -> redis.Redis:
    port = cfg().get("monitor_host", {}).get("alert_queue_port", 6380)
    return redis.Redis(host="localhost", port=port, decode_responses=True)


def run(args, timeout=60, input_text=None) -> tuple[int, str]:
    """Never uses a shell: args is a list, so no value from a request can be
    interpreted as shell syntax."""
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout, input=input_text)
        return r.returncode, (r.stdout + r.stderr).strip()
    except subprocess.TimeoutExpired:
        return -1, f"timed out after {timeout}s"
    except FileNotFoundError as e:
        return -1, str(e)


def ssh(alias: str, remote_cmd: str, timeout=30, input_text=None) -> tuple[int, str]:
    """remote_cmd is built only from config values + fixed strings, never from
    request payloads (payload data goes over stdin instead)."""
    return run(["ssh", "-o", "ConnectTimeout=6", "-o", "BatchMode=yes", alias, remote_cmd],
               timeout=timeout, input_text=input_text)


def stamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def audit(rdb, message: str, ok: bool, kind: str = "rule-change"):
    """Every change made through the dashboard becomes an event in the unified log."""
    rdb.lpush("audit", json.dumps({
        "ts": datetime.now(timezone.utc).isoformat(),
        "source": "host-agent",
        "type": kind if ok else f"{kind}-failed",
        "confidence": "INFO" if ok else "MEDIUM",
        "message": message,
    }))
    rdb.ltrim("audit", 0, 1999)


def container_state(name: str) -> str:
    code, out = run(["docker", "inspect", "-f", "{{.State.Status}}", name], timeout=10)
    return out.strip() if code == 0 and out.strip() else "absent"


def find_container(substr: str) -> str | None:
    code, out = run(["docker", "ps", "--filter", f"name={substr}", "--format", "{{.Names}}"], timeout=10)
    names = [n for n in out.splitlines() if n.strip()] if code == 0 else []
    return names[0] if names else None
