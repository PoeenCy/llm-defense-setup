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
mock_vulnbox_enabled = cfg.get("mock_vulnbox", {}).get("enabled", False)
traffic_dir  = os.path.join(PROJECT_ROOT, "traffic")
suricata_dir = os.path.join(PROJECT_ROOT, "suricata")

os.makedirs(traffic_dir, exist_ok=True)
os.makedirs(os.path.join(suricata_dir, "log"), exist_ok=True)
os.makedirs(os.path.join(suricata_dir, "etc"), exist_ok=True)
os.makedirs(os.path.join(suricata_dir, "lib"), exist_ok=True)

# Build BPF filter from services
service_ports = [str(s["port"]) for s in cfg["services"]]
bpf = " or ".join(f"port {p}" for p in service_ports) if service_ports else ""

# Generate tick start as now (will be overridden at match start)
tick_start = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

# mock_vulnbox mode has no real pcap-broker to stream from — use directory-
# watch mode (empty PCAP_OVER_IP) so Tulip picks up pcaps dropped into
# traffic/ instead of retrying a dead connection forever. Real competition
# mode (mock_vulnbox.enabled=false) streams live from the vulnbox as before.
pcap_over_ip = "" if mock_vulnbox_enabled else f"host.docker.internal:{vulnbox_port}"

env_content = f"""##############################
# Tulip config — AUTO-GENERATED from services.json
# Do not edit by hand; run: python3 scripts/gen-tulip-env.py
##############################

TIMESCALE="postgres://tulip@timescale:5432/tulip"

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
# DUMP_PCAPS — save pcaps for offline analysis
##############################
DUMP_PCAPS="/traffic"
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

env_path = os.path.join(TULIP_DIR, ".env")
with open(env_path, "w") as f:
    f.write(env_content)

print(f"[gen-tulip-env] Written: {env_path}")
print(f"  FLAG_REGEX = {flag_regex}")
print(f"  VM_IP      = {vulnbox_ip}")
print(f"  PCAP_OVER_IP = {pcap_over_ip or '(empty — directory-watch mode, mock_vulnbox.enabled=true)'}")
print(f"  TRAFFIC_DIR_HOST = {traffic_dir}")
print(f"  BPF = {bpf}")
