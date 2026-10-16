#!/usr/bin/env bash
# validate-config.sh — Validate services.json against required schema
# Exit 1 with loud messages on any missing/invalid field.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
CONFIG="${1:-$SCRIPT_DIR/services.json}"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

ERRORS=0
ok()   { echo -e "${GREEN}[OK]${NC}    $1"; }
fail() { echo -e "${RED}[FAIL]${NC}  $1"; ERRORS=$((ERRORS+1)); }
warn() { echo -e "${YELLOW}[WARN]${NC}  $1"; }

if [[ ! -f "$CONFIG" ]]; then
    echo -e "${RED}[FATAL]${NC} Config file not found: $CONFIG"; exit 1
fi

if ! python3 -c "import json,sys; json.load(open('$CONFIG'))" 2>/dev/null; then
    echo -e "${RED}[FATAL]${NC} $CONFIG is not valid JSON"; exit 1
fi
ok "JSON syntax valid"

# Run the bulk of validation in Python (avoids shell quoting nightmares with dotted paths)
python3 - "$CONFIG" "$REPO_ROOT" << 'PYEOF'
import json, os, re, sys, ipaddress

CONFIG = sys.argv[1] if len(sys.argv) > 1 else "services.json"
REPO_ROOT = sys.argv[2] if len(sys.argv) > 2 else os.path.dirname(os.path.abspath(CONFIG))

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

sys.path.insert(0, os.path.join(REPO_ROOT, "contest-runtime"))
try:
    from flagtrace.app.config import validate_optional
    validate_optional(d)
except (ValueError, KeyError, TypeError) as exc:
    fail(f"Flag-trace config: {exc}")

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

# ---- vulnboxes (one or more hosts; each carries its own services[]) ----
vulnboxes, vfound = get(d, "vulnboxes")
if not vfound or not isinstance(vulnboxes, list) or len(vulnboxes) == 0:
    fail("vulnboxes array is missing or empty — at least one host required")
else:
    ok(f"vulnboxes: {len(vulnboxes)} host(s) defined")
    seen_names = set()
    valid_protos = {"tcp", "udp"}
    valid_layers = {"l7-http", "l7-https", "l4-raw", "l4-udp"}
    for vi, vb in enumerate(vulnboxes):
        for req in ["name", "ip", "ssh_user", "capture_iface", "pcap_broker_port", "capture_ssh_alias"]:
            if req not in vb or vb[req] is None or vb[req] == "":
                fail(f"vulnboxes[{vi}] missing required field: {req}")
            else:
                ok(f"vulnboxes[{vi}].{req} = {vb[req]}")
        name = vb.get("name")
        if name:
            if name in seen_names:
                fail(f"vulnboxes[{vi}].name is a duplicate: {name!r} — every host needs a unique name")
            seen_names.add(name)
        ip = vb.get("ip")
        if ip:
            try:
                ipaddress.ip_address(ip)
                ok(f"vulnboxes[{vi}].ip is valid IPv4: {ip}")
            except ValueError:
                fail(f"vulnboxes[{vi}].ip is not a valid IP: {ip}")
        # ---- this host's own services[] (may be empty while still being reconnoitered) ----
        svcs = vb.get("services")
        if not isinstance(svcs, list):
            fail(f"vulnboxes[{vi}].services must be a list (use [] if not known yet)")
            svcs = []
        elif len(svcs) == 0:
            warn(f"vulnboxes[{vi}] ({name}): services[] is empty — capture/ctf_proxy have nothing to do here yet")
        else:
            ok(f"vulnboxes[{vi}] ({name}): {len(svcs)} service(s) defined")
        for si, svc in enumerate(svcs):
            for req in ["name", "port", "proto", "layer"]:
                if req not in svc or svc[req] is None or svc[req] == "":
                    fail(f"vulnboxes[{vi}].services[{si}] missing required field: {req}")
                else:
                    ok(f"vulnboxes[{vi}].services[{si}].{req} = {svc[req]}")
            if "proto" in svc and svc["proto"] not in valid_protos:
                fail(f"vulnboxes[{vi}].services[{si}].proto must be tcp|udp, got: {svc['proto']}")
            if "layer" in svc and svc["layer"] not in valid_layers:
                warn(f"vulnboxes[{vi}].services[{si}].layer unknown value: {svc['layer']} (known: {valid_layers})")

# ---- monitor_host ----
for dotted in ["monitor_host.ip", "monitor_host.dashboard_port",
               "monitor_host.alert_queue_port"]:
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

# ---- ml_classifier (compliance gate — see docs/COMPLIANCE.md) ----
v, found = get(d, "ml_classifier", "enabled")
if not found or not isinstance(v, bool):
    fail("ml_classifier.enabled must be present and a boolean (true/false)")
else:
    ok(f"ml_classifier.enabled = {v}")
    if v:
        warn("ml_classifier.enabled=true — has NO EFFECT in MODE=contest; only ever starts "
             "under MODE=prep, and only with BTC's written sign-off. See services.json's own note.")

# ---- keyword sync: ctf_proxy's generated config.json must byte-match services.json ----
ctf_proxy_cfg_path = os.path.join(
    REPO_ROOT,
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
                f"contest-runtime/config/generators/gen-ctfproxy.py"
            )
    except Exception as e:
        warn(f"Could not read generated ctf_proxy config to check keyword sync: {e}")
elif kfound:
    warn("ctf_proxy config.json not generated yet — run contest-runtime/config/generators/gen-ctfproxy.py "
         "before bringing ctf_proxy up")

print()
if errors == 0:
    print(f"{GREEN}=== All checks passed. services.json is valid. ==={NC}")
    sys.exit(0)
else:
    print(f"{RED}=== FAILED: {errors} error(s) found in services.json ==={NC}")
    sys.exit(1)
PYEOF
