"""Settings shared by every route. Environment comes from docker-compose;
services.json is mounted read-only at CONFIG."""
import json
import os
from pathlib import Path

REDIS_HOST = os.environ.get("REDIS_HOST", "redis")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
IOC_API_URL = os.environ.get("IOC_API_URL", "http://ioc-brain:5001")
TULIP_API_URL = os.environ.get("TULIP_API_URL", "http://api:5000")
MONITOR_IP = os.environ.get("MONITOR_IP", "")
VULNBOX_IP = os.environ.get("VULNBOX_IP", "")
CONFIG_PATH = Path(os.environ.get("CONFIG", "/srv/services.json"))
RULES_PATH = Path(os.environ.get("RULES_PATH", "/srv/rules/suricata.rules"))
LIBRARY_DIR = Path(os.environ.get("LIBRARY_DIR", "/srv/rules-library"))
STATIC_DIR = Path(__file__).resolve().parent.parent.parent / "static"


def load_services_config() -> dict:
    """Re-read on every call: services.json can be edited from the Config tab
    while the dashboard keeps running."""
    try:
        return json.loads(CONFIG_PATH.read_text())
    except (OSError, ValueError):
        return {}
