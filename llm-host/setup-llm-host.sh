#!/usr/bin/env bash
# setup-llm-host.sh — Prepare a DEDICATED machine to serve Ollama over the
# network for the CTF Monitor Hub (see ../docs/REMOTE_LLM.md).
#
# Run this ON THE LLM MACHINE (not the monitor host). Clone this same repo
# there too — it only needs this directory + ../ioc-brain/Foundation-Sec.Modelfile.
#
# Usage: sudo bash setup-llm-host.sh <monitor-host-ip> [--allow-all]
#   <monitor-host-ip>   the monitor host's LAN IP — firewall will allow ONLY
#                        this IP to reach Ollama's port. Required unless
#                        --allow-all is passed.
#   --allow-all          skip the firewall restriction (NOT recommended on a
#                        shared/competition network — see security note below).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODELFILE="$SCRIPT_DIR/../ioc-brain/Foundation-Sec.Modelfile"
OLLAMA_PORT=11434
MONITOR_IP="${1:-}"
ALLOW_ALL=false
[[ "${2:-}" == "--allow-all" || "${1:-}" == "--allow-all" ]] && ALLOW_ALL=true

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${CYAN}[LLM-HOST]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC}       $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}     $*"; }
die()  { echo -e "${RED}[FATAL]${NC}    $*"; exit 1; }

if [[ "$ALLOW_ALL" == false && -z "$MONITOR_IP" ]]; then
    die "Usage: sudo bash setup-llm-host.sh <monitor-host-ip> [--allow-all]"
fi
[[ "$ALLOW_ALL" == false ]] && [[ "$MONITOR_IP" == "--allow-all" ]] && die "Pass the monitor host's IP first, or use --allow-all alone"

echo ""
echo -e "${CYAN}══ CTF Monitor Hub — Dedicated LLM Host Setup ══${NC}"
echo ""

# ───────────────────────────────────────────────────────────────────────────
# 1. Install Ollama if missing
# ───────────────────────────────────────────────────────────────────────────
if ! command -v ollama &>/dev/null; then
    log "Installing Ollama..."
    curl -fsSL https://ollama.com/install.sh | sh
else
    ok "Ollama already installed ($(ollama --version 2>&1 | head -1))"
fi

# ───────────────────────────────────────────────────────────────────────────
# 2. Configure Ollama to listen on all interfaces (default is 127.0.0.1 only,
#    unreachable from another machine)
# ───────────────────────────────────────────────────────────────────────────
log "Configuring Ollama to listen on 0.0.0.0:$OLLAMA_PORT..."
mkdir -p /etc/systemd/system/ollama.service.d
cat > /etc/systemd/system/ollama.service.d/override.conf <<EOF
[Service]
Environment="OLLAMA_HOST=0.0.0.0:$OLLAMA_PORT"
EOF
systemctl daemon-reload
systemctl enable ollama 2>/dev/null || true
systemctl restart ollama
sleep 2
ok "Ollama listening on 0.0.0.0:$OLLAMA_PORT"

# ───────────────────────────────────────────────────────────────────────────
# 3. Firewall — restrict access to the monitor host only
# ───────────────────────────────────────────────────────────────────────────
# SECURITY: a CTF competition network has every other team on it. An
# unauthenticated Ollama API reachable by anyone lets them burn your GPU/CPU,
# read whatever you prompt it with, or just DoS it. Always restrict unless
# you have a specific reason not to.
if [[ "$ALLOW_ALL" == true ]]; then
    warn "Firewall restriction SKIPPED (--allow-all) — Ollama is reachable by anyone who can"
    warn "route to this machine. Only do this on a trusted/isolated network."
elif command -v ufw &>/dev/null; then
    log "Restricting port $OLLAMA_PORT to $MONITOR_IP via ufw..."
    ufw allow from "$MONITOR_IP" to any port "$OLLAMA_PORT" proto tcp comment "ctf-monitor-hub" || true
    ufw deny "$OLLAMA_PORT"/tcp || true
    ok "ufw rule added: only $MONITOR_IP may reach port $OLLAMA_PORT"
elif command -v iptables &>/dev/null; then
    log "Restricting port $OLLAMA_PORT to $MONITOR_IP via iptables..."
    iptables -I INPUT -p tcp --dport "$OLLAMA_PORT" -s "$MONITOR_IP" -j ACCEPT
    iptables -A INPUT -p tcp --dport "$OLLAMA_PORT" -j DROP
    warn "iptables rule added but NOT persisted across reboot — install iptables-persistent"
    warn "or re-run this script after reboot if you restart this machine."
    ok "iptables rule added: only $MONITOR_IP may reach port $OLLAMA_PORT"
else
    warn "Neither ufw nor iptables found — could not restrict access. Install one of them"
    warn "and re-run, or firewall this port at your network's router/switch instead."
fi

# ───────────────────────────────────────────────────────────────────────────
# 4. Build the model (base GGUF has no chat template — see the Modelfile's
#    own comment for why this wrapper is needed)
# ───────────────────────────────────────────────────────────────────────────
if [[ -f "$MODELFILE" ]]; then
    log "Building foundation-sec-8b-chat (pulls the base GGUF, ~5GB, first time)..."
    ollama create foundation-sec-8b-chat -f "$MODELFILE"
    ok "Model ready: foundation-sec-8b-chat"
else
    die "Modelfile not found at $MODELFILE — clone the full repo here, not just this directory"
fi

log "Pulling embedding model (nomic-embed-text)..."
ollama pull nomic-embed-text
ok "Embedding model ready"

# ───────────────────────────────────────────────────────────────────────────
# 5. Summary
# ───────────────────────────────────────────────────────────────────────────
THIS_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "<run: ip addr>")
echo ""
echo -e "${GREEN}══ Done ══${NC}"
echo "This machine's LLM is reachable at: ${THIS_IP}:${OLLAMA_PORT}"
echo ""
echo "On the MONITOR HOST, edit services.json:"
echo "  \"ollama\": { \"host\": \"${THIS_IP}\", ... }"
echo "then re-run bringup.sh there. See docs/REMOTE_LLM.md for the full checklist."
