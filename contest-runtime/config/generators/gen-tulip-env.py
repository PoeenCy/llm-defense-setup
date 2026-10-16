#!/usr/bin/env python3
"""
gen-tulip-env.py — Generate Tulip's .env from services.json
Run this before starting Tulip. Called automatically by bringup.sh.
"""
import json, sys, os
from datetime import datetime, timezone

# This file lives at contest-runtime/config/generators/ — three levels below
# the repo root.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
CONFIG_PATH = os.environ.get("CONFIG", os.path.join(REPO_ROOT, "contest-runtime", "config", "services.json"))
TULIP_DIR   = os.environ.get("TULIP_DIR", os.path.join(REPO_ROOT, "offline-bundle", "repos", "tulip"))

with open(CONFIG_PATH) as f:
    cfg = json.load(f)

flag_regex   = cfg["flag"]["regex"]
vulnboxes    = cfg["vulnboxes"]  # one or more hosts, each with its own services[]
# Tulip's .env has a single informational VM_IP field (shown in its UI, not
# used to filter traffic -- BPF + directory-watch do that). With multiple
# hosts there's no one "the" vulnbox IP; the first host stands in for it.
vulnbox_ip   = vulnboxes[0]["ip"]
vulnbox_port = vulnboxes[0]["pcap_broker_port"]
team_id      = cfg["team_id"]
bind_ip      = cfg.get("monitor_host", {}).get("bind_ip", "127.0.0.1")
mock_vulnbox_enabled = cfg.get("mock_vulnbox", {}).get("enabled", False)
# Live PCAP-over-IP brokers aren't supported per-host yet -- only the
# pull-based directory-watch capture (capture_pull.py) handles multiple
# hosts. Force this off for a multi-host config rather than silently using
# just the first host's broker setting.
live_pcap_broker = vulnboxes[0].get("live_pcap_broker", False) if len(vulnboxes) == 1 else False
traffic_dir  = os.path.join(REPO_ROOT, "traffic")
suricata_dir = os.path.join(REPO_ROOT, "contest-runtime", "detection", "suricata")

os.makedirs(traffic_dir, exist_ok=True)
os.makedirs(os.path.join(suricata_dir, "log"), exist_ok=True)
os.makedirs(os.path.join(suricata_dir, "etc"), exist_ok=True)
os.makedirs(os.path.join(suricata_dir, "lib"), exist_ok=True)

# Build BPF filter from every host's services, combined. Tulip's assembler
# reads whatever lands in traffic/ regardless of which host it came from
# (capture_pull.py prefixes pcap filenames by session, not by host, so this
# BPF only needs to be permissive enough to match every service across every
# host -- it doesn't need to be host-aware).
# capture_port, if set, is the port actually visible at the capture point
# (e.g. a docker bridge sees the post-NAT internal port, not the public
# listen port) — falls back to "port" for a traditional vulnbox with no NAT
# between the capture point and the service.
service_ports = sorted({str(s.get("capture_port", s["port"])) for vb in vulnboxes for s in vb.get("services", [])})
bpf = " or ".join(f"port {p}" for p in service_ports) if service_ports else ""

# Generate tick start as now (will be overridden at match start)
tick_start = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
game = cfg.get("game") or {}
if game.get("start_time"):
    tick_start = datetime.fromisoformat(game["start_time"].replace("Z", "+00:00")).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
tick_length = int(game.get("tick_seconds", 120) * 1000)

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
TICK_LENGTH={tick_length}

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
# CONVERTER (DECODER) CONFIGS
##############################
# decode_all tries a wide matrix of decodings (base64/32/58/85, hex, url,
# html, escapes, quoted-printable, gzip/zlib/deflate/bz2/lzma, rot13, reverse,
# single-byte xor), stacked a few layers deep, on every flow. It only adds a
# representation when a decoding reveals a flag the raw traffic did not already
# show, so it is gated on FLAG_REGEX above and a wrong flag regex silently
# disables it. The decoded text is indexed too, which is what makes an encoded
# flag findable by its plaintext -- both in Tulip's own search and in the
# dashboard's event -> flow resolution (/api/tulip/resolve).
# Empty CONVERTERS turns the pass off; DECODE_ALL_EMIT=all shows every
# successful decoding instead of only the flag-bearing ones (noisy, for
# hunting an unknown encoding by hand); lower DECODE_ALL_BUDGET if the
# assembler cannot keep up with the traffic.
CONVERTERS="decode_all"
DECODE_ALL_EMIT="flags"
DECODE_ALL_BUDGET="0.4"

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
# interface. Rewrite them every run so a fresh clone of the upstream repo
# can't silently re-expose them:
#   - 3000 (web UI) follows BIND_IP -- this is the one meant to be opened to
#     a trusted LAN so teammates can see it.
#   - 5433 (raw Postgres, no auth beyond the DB password baked into the
#     image) is ALWAYS forced to 127.0.0.1 regardless of BIND_IP. Before this,
#     both ports shared the same variable, so following services.json's own
#     bind_ip_note/CONFIG.md advice ("set bind_ip to a LAN IP so teammates can
#     see the Dashboard") would have also handed the whole flow database to
#     anyone on that LAN. The regex matches whatever prefix is currently
#     there (raw, already-BIND_IP, or already-127.0.0.1) so it self-heals
#     regardless of which version of this script wrote it last.
import re
for fname in ("docker-compose.yml", "docker-compose-suricata.yml"):
    fp = os.path.join(TULIP_DIR, fname)
    if not os.path.exists(fp):
        continue
    txt = open(fp).read()
    patched = re.sub(r'- "[^"]*?5433:5432"', '- "127.0.0.1:5433:5432"', txt)
    patched = re.sub(r'- "(?:\$\{BIND_IP:-127\.0\.0\.1\}:)?3000:3000"', '- "${BIND_IP:-127.0.0.1}:3000:3000"', patched)
    if patched != txt:
        open(fp, "w").write(patched)
        print(f"[gen-tulip-env] Bound published ports in {fname} (3000->BIND_IP, 5433->127.0.0.1 always)")

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
