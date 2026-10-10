#!/usr/bin/env bash
# validate-config.sh — Validate services.json against required schema
# Exit 1 with loud messages on any missing/invalid field.
set -uo pipefail

CONFIG="${1:-services.json}"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

ERRORS=0
ok()   { echo -e "${GREEN}[OK]${NC}    $1"; }
fail() { echo -e "${RED}[FAIL]${NC}  $1"; ERRORS=$((ERRORS+1)); }
warn() { echo -e "${YELLOW}[WARN]${NC}  $1"; }

if [[ ! -f "$CONFIG" ]]; then
    echo -e "${RED}[FATAL]${NC} Config file not found: $CONFIG"; exit 1
fi

if ! python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$CONFIG" 2>/dev/null; then
    echo -e "${RED}[FATAL]${NC} $CONFIG is not valid JSON"; exit 1
fi
ok "JSON syntax valid"

# Run the bulk of validation in Python (avoids shell quoting nightmares with dotted paths)
python3 - "$CONFIG" << 'PYEOF'
import json, re, sys, ipaddress

CONFIG = sys.argv[1] if len(sys.argv) > 1 else "services.json"

RED    = "\033[0;31m"
GREEN  = "\033[0;32m"
YELLOW = "\033[1;33m"
NC     = "\033[0m"

errors = 0

def ok(msg):   print(f"{GREEN}[OK]{NC}    {msg}")
def fail(msg):
    global errors
    print(f"{RED}[FAIL]{NC}  {msg}")
    errors += 1
def warn(msg): print(f"{YELLOW}[WARN]{NC}  {msg}")

def get(d, *keys):
    """Drill into nested dict, return (value, found_bool)."""
    cur = d
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return None, False
        cur = cur[k]
    return cur, True

with open(CONFIG) as f:
    d = json.load(f)

print(f"\n=== Validating: {CONFIG} ===\n")

# ---- team_id, teams_cidr ----
for key in ["team_id", "teams_cidr"]:
    v, found = get(d, key)
    if not found or not v:
        fail(f"Missing required field: {key}")
    else:
        ok(f"{key} = \"{v}\"")

# ---- teams_cidr CIDR check ----
cidr, found = get(d, "teams_cidr")
if found and cidr:
    try:
        ipaddress.ip_network(cidr, strict=False)
        ok(f"teams_cidr is valid CIDR: {cidr}")
    except ValueError:
        fail(f"teams_cidr is not valid CIDR: {cidr}")

# ---- vulnbox ----
for dotted in ["vulnbox.ip", "vulnbox.ssh_user", "vulnbox.capture_iface", "vulnbox.pcap_broker_port"]:
    keys = dotted.split(".")
    v, found = get(d, *keys)
    if not found or v is None or v == "":
        fail(f"Missing required field: {dotted}")
    else:
        ok(f"{dotted} = {v}")

ip, found = get(d, "vulnbox", "ip")
if found and ip:
    try:
        ipaddress.ip_address(ip)
        ok(f"vulnbox.ip is valid IPv4: {ip}")
    except ValueError:
        fail(f"vulnbox.ip is not a valid IP: {ip}")

# ---- monitor_host ----
for dotted in ["monitor_host.ip", "monitor_host.dashboard_port",
               "monitor_host.alert_queue_port", "monitor_host.ioc_api_port"]:
    keys = dotted.split(".")
    v, found = get(d, *keys)
    if not found or v is None or v == "":
        fail(f"Missing required field: {dotted}")
    else:
        ok(f"{dotted} = {v}")

# ---- flag ----
flag_regex, found = get(d, "flag", "regex")
if not found or not flag_regex:
    fail("Missing required field: flag.regex")
else:
    try:
        re.compile(flag_regex)
        ok(f"flag.regex is valid regex: {flag_regex}")
    except re.error as e:
        fail(f"flag.regex is not a valid Python regex: {e}")

# ---- honeytoken ----
for dotted in ["honeytoken.flag", "honeytoken.endpoint_port"]:
    keys = dotted.split(".")
    v, found = get(d, *keys)
    if not found or v is None or v == "":
        fail(f"Missing required field: {dotted}")
    else:
        ok(f"{dotted} = {v}")

hflag, hfound = get(d, "honeytoken", "flag")
if hfound and hflag and found and flag_regex:
    if re.search(flag_regex, hflag):
        ok("honeytoken.flag matches flag.regex")
    else:
        warn("honeytoken.flag does NOT match flag.regex (OK if format differs intentionally)")

# ---- tulip ----
for dotted in ["tulip.web_port", "tulip.ingestor_port"]:
    keys = dotted.split(".")
    v, found = get(d, *keys)
    if not found or v is None:
        fail(f"Missing required field: {dotted}")
    else:
        ok(f"{dotted} = {v}")

# ---- mock_vulnbox ----
for dotted in ["mock_vulnbox.enabled", "mock_vulnbox.hostname"]:
    keys = dotted.split(".")
    v, found = get(d, *keys)
    if not found or v is None or v == "":
        fail(f"Missing required field: {dotted}")
    else:
        ok(f"{dotted} = {v}")

# ---- ctf_proxy ----
for dotted in ["ctf_proxy.keyword", "ctf_proxy.listen_ip"]:
    keys = dotted.split(".")
    v, found = get(d, *keys)
    if not found or v is None or v == "":
        fail(f"Missing required field: {dotted}")
    else:
        ok(f"{dotted} = {v}")

# ---- mcp ----
for dotted in ["mcp.postgres_role", "mcp.postgres_db", "mcp.postgres_host_port", "mcp.port"]:
    keys = dotted.split(".")
    v, found = get(d, *keys)
    if not found or v is None or v == "":
        fail(f"Missing required field: {dotted}")
    else:
        ok(f"{dotted} = {v}")

# ---- ollama ----
host_v, host_found = get(d, "ollama", "host")
if host_found and host_v:
    ok(f"ollama.host = {host_v} (remote LLM machine — see docs/REMOTE_LLM.md)")
else:
    ok("ollama.host = (empty — Ollama runs on this machine)")

for dotted in ["ollama.port", "ollama.llm_model", "ollama.embed_model", "ollama.gpu_layers"]:
    keys = dotted.split(".")
    v, found = get(d, *keys)
    if not found or v is None or v == "":
        fail(f"Missing required field: {dotted}")
    else:
        ok(f"{dotted} = {v}")

# ---- anythingllm ----
v, found = get(d, "anythingllm", "port")
if not found or v is None:
    fail("Missing required field: anythingllm.port")
else:
    ok(f"anythingllm.port = {v}")

# ---- services array ----
services, sfound = get(d, "services")
if not sfound or not isinstance(services, list) or len(services) == 0:
    fail("services array is missing or empty — at least one service required")
else:
    ok(f"services: {len(services)} service(s) defined")
    valid_protos = {"tcp", "udp"}
    valid_layers = {"l7-http", "l7-https", "l4-raw", "l4-udp"}
    for i, svc in enumerate(services):
        for req in ["name", "port", "proto", "layer"]:
            if req not in svc or svc[req] is None or svc[req] == "":
                fail(f"services[{i}] missing required field: {req}")
            else:
                ok(f"services[{i}].{req} = {svc[req]}")
        if "proto" in svc and svc["proto"] not in valid_protos:
            fail(f"services[{i}].proto must be tcp|udp, got: {svc['proto']}")
        if "layer" in svc and svc["layer"] not in valid_layers:
            warn(f"services[{i}].layer unknown value: {svc['layer']} (known: {valid_layers})")

# ---- keyword sync: ctf_proxy's generated config.json must byte-match services.json ----
import os
ctf_proxy_cfg_path = os.path.join(
    os.path.dirname(os.path.abspath(CONFIG)) or ".",
    "offline-bundle", "repos", "ctf_proxy", "proxy", "config", "config.json",
)
keyword, kfound = get(d, "ctf_proxy", "keyword")
if kfound and os.path.isfile(ctf_proxy_cfg_path):
    try:
        with open(ctf_proxy_cfg_path) as f:
            generated_keyword = json.load(f).get("global_config", {}).get("keyword")
        if generated_keyword == keyword:
            ok(f"ctf_proxy keyword in sync with generated config.json ({keyword!r})")
        else:
            fail(
                f"ctf_proxy keyword DRIFTED: services.json={keyword!r} but "
                f"generated config.json={generated_keyword!r} — re-run "
                f"generators/gen-ctfproxy.py"
            )
    except Exception as e:
        warn(f"Could not read generated ctf_proxy config to check keyword sync: {e}")
elif kfound:
    warn("ctf_proxy config.json not generated yet — run generators/gen-ctfproxy.py "
         "before bringing ctf_proxy up")

print()
if errors == 0:
    print(f"{GREEN}=== All checks passed. services.json is valid. ==={NC}")
    sys.exit(0)
else:
    print(f"{RED}=== FAILED: {errors} error(s) found in services.json ==={NC}")
    sys.exit(1)
PYEOF
