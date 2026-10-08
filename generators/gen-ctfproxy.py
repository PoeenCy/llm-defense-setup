#!/usr/bin/env python3
"""
gen-ctfproxy.py — Generate ctf_proxy's proxy/config/config.json from services.json.

services.json is the single source of truth: each entry in services[] becomes one
proxied service (listen_port == target_port by convention — same port number, but
listen_port is bound by the ctf_proxy container and target_port by mock-vulnbox).
The "keyword" MUST come from this file only — detection/capture configs that need
to recognize blocked-attack packets must read the exact same services.json field,
never a hardcoded copy, or they will drift out of sync.
"""
import json
import os

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.environ.get("CONFIG", os.path.join(PROJECT_ROOT, "services.json"))
CTF_PROXY_DIR = os.environ.get(
    "CTF_PROXY_DIR", os.path.join(PROJECT_ROOT, "offline-bundle", "repos", "ctf_proxy")
)

with open(CONFIG_PATH) as f:
    cfg = json.load(f)

mock_vb = cfg.get("mock_vulnbox", {})
proxy_cfg = cfg.get("ctf_proxy", {})
target_host = mock_vb.get("hostname", "mock-vulnbox")

services = []
for svc in cfg["services"]:
    entry = {
        "name": svc["name"],
        "target_ip": target_host,
        "target_port": svc["port"],
        "listen_port": svc["port"],
    }
    if svc.get("layer") == "l7-http":
        entry["http"] = True
    services.append(entry)

out = {
    "services": services,
    "global_config": {
        "keyword": proxy_cfg["keyword"],
        "verbose": False,
        "nginx": proxy_cfg.get("nginx", {"connect_timeout": 5, "max_fails": 1, "fail_timeout": 20}),
        "dos": proxy_cfg.get("dos", {"enabled": False, "duration": 60, "interval": 2}),
        "max_stored_messages": 10,
        "max_message_size": 65535,
    },
}

out_path = os.path.join(CTF_PROXY_DIR, "proxy", "config", "config.json")
os.makedirs(os.path.dirname(out_path), exist_ok=True)
with open(out_path, "w") as f:
    json.dump(out, f, indent=2)
    f.write("\n")

print(f"[gen-ctfproxy] Written: {out_path}")
print(f"  services = {[s['name'] for s in services]}")
print(f"  keyword  = {out['global_config']['keyword']}")
