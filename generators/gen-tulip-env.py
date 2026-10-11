#!/usr/bin/env python3
"""
gen-tulip-env.py — Generate Tulip's .env from services.json
Run this before starting Tulip. Called automatically by bringup.sh.
"""
import json, sys, os
from datetime import datetime, timezone

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.environ.get("CONFIG", os.path.join(PROJECT_ROOT, "services.json"))
TULIP_DIR   = os.environ.get("TULIP_DIR", os.path.join(PROJECT_ROOT, "offline-bundle", "repos", "tulip"))

with open(CONFIG_PATH) as f:
    cfg = json.load(f)

flag_regex   = cfg["flag"]["regex"]
vulnbox_ip   = cfg["vulnbox"]["ip"]
vulnbox_port = cfg["vulnbox"]["pcap_broker_port"]
team_id      = cfg["team_id"]
bind_ip      = cfg.get("monitor_host", {}).get("bind_ip", "127.0.0.1")
mock_vulnbox_enabled = cfg.get("mock_vulnbox", {}).get("enabled", False)
live_pcap_broker = cfg.get("vulnbox", {}).get("live_pcap_broker", False)
traffic_dir  = os.path.join(PROJECT_ROOT, "traffic")
suricata_dir = os.path.join(PROJECT_ROOT, "suricata")

os.makedirs(traffic_dir, exist_ok=True)
os.makedirs(os.path.join(suricata_dir, "log"), exist_ok=True)
os.makedirs(os.path.join(suricata_dir, "etc"), exist_ok=True)
os.makedirs(os.path.join(suricata_dir, "lib"), exist_ok=True)

# Build BPF filter from services
# capture_port, if set, is the port actually visible at the capture point
# (e.g. a docker bridge sees the post-NAT internal port, not the public
# listen port) — falls back to "port" for a traditional vulnbox with no NAT
# between the capture point and the service.
service_ports = [str(s.get("capture_port", s["port"])) for s in cfg["services"]]
bpf = " or ".join(f"port {p}" for p in service_ports) if service_ports else ""

# Generate tick start as now (will be overridden at match start)
tick_start = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# Directory-watch mode (empty PCAP_OVER_IP) is the default: Tulip picks up
# pcaps dropped into traffic/ instead of needing a live PCAP-over-IP broker
# running on the vulnbox. This covers both mock-vulnbox testing AND a real
# vulnbox fed via a pull-based capture script (vulnbox-deploy/deploy-capture-
# pull.sh) that scp/rsyncs rotated pcaps into traffic/ — set
# vulnbox.live_pcap_broker=true only if you actually have a PCAP-over-IP
# broker (e.g. fox-it/pcap-broker) running and reachable at vulnbox_port.
pcap_over_ip = f"host.docker.internal:{vulnbox_port}" if live_pcap_broker else ""

env_content = f"""##############################
# Tulip config — AUTO-GENERATED from services.json
# Do not edit by hand; run: python3 scripts/gen-tulip-env.py
##############################

TIMESCALE="postgres://tulip@timescale:5432/tulip"

# Interface Tulip's published ports (web UI, postgres) bind to — see
# services.json monitor_host.bind_ip
BIND_IP="{bind_ip}"

TRAFFIC_DIR_HOST="{traffic_dir}"
TRAFFIC_DIR_DOCKER="/traffic"

SURICATA_DIR_HOST="{suricata_dir}"

BPF="{bpf}"

##############################
# Game config
##############################

TICK_START="{tick_start}"
TICK_LENGTH=120000

FLAG_REGEX="{flag_regex}"

VM_IP="{vulnbox_ip}"
TEAM_ID="{team_id}"

##############################
# PCAP_OVER_IP — receive from vulnbox pcap-broker
##############################
PCAP_OVER_IP="{pcap_over_ip}"

##############################
# DUMP_PCAPS — off: in directory-watch mode the pcaps already ARE on disk, and
# /traffic is mounted read-only, so dumping only spams "read-only file system"
##############################
DUMP_PCAPS=""
DUMP_PCAPS_INTERVAL="1m"
DUMP_PCAPS_FILENAME="2006-01-02_15-04-05.pcap"

##############################
# FLAGID CONFIGS
##############################
FLAGID_SCRAPE=
FLAGID_SCAN=
FLAG_LIFETIME=
FLAGID_ENDPOINT="http://flagidendpoint:8000/flagids.json"

##############################
# FLAG_VALIDATOR
##############################
FLAG_VALIDATOR_TYPE=
FLAG_VALIDATOR_TEAM=42
"""

# Upstream Tulip compose files publish "3000:3000" / "5433:5432" on every
# interface. Rewrite them (idempotently) to bind ${BIND_IP} instead, every run,
# so a fresh clone of the upstream repo can't silently re-expose them.
import re
for fname in ("docker-compose.yml", "docker-compose-suricata.yml"):
    fp = os.path.join(TULIP_DIR, fname)
    if not os.path.exists(fp):
        continue
    txt = open(fp).read()
    patched = re.sub(r'(- *")(3000:3000|5433:5432)(")', r'\1${BIND_IP:-127.0.0.1}:\2\3', txt)
    if patched != txt:
        open(fp, "w").write(patched)
        print(f"[gen-tulip-env] Bound published ports to BIND_IP in {fname}")

env_path = os.path.join(TULIP_DIR, ".env")
with open(env_path, "w") as f:
    f.write(env_content)

print(f"[gen-tulip-env] Written: {env_path}")
print(f"  FLAG_REGEX = {flag_regex}")
print(f"  VM_IP      = {vulnbox_ip}")
print(f"  PCAP_OVER_IP = {pcap_over_ip or '(empty — directory-watch mode, vulnbox.live_pcap_broker=false)'}")
print(f"  TRAFFIC_DIR_HOST = {traffic_dir}")
print(f"  BPF = {bpf}")
print(f"  BIND_IP = {bind_ip}")
