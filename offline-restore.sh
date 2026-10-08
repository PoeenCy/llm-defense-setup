#!/usr/bin/env bash
# offline-restore.sh — Restore the entire CTF hub stack from offline-bundle/
# Run on air-gapped machine. Makes ZERO outbound network calls.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE="$SCRIPT_DIR/offline-bundle"
CONFIG="$BUNDLE/services.json"
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'

log()  { echo -e "${CYAN}[RESTORE]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC}      $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}    $*"; }
die()  { echo -e "${RED}[FATAL]${NC}   $*"; exit 1; }

[[ -d "$BUNDLE" ]] || die "offline-bundle/ not found at $SCRIPT_DIR"
[[ -f "$CONFIG" ]] || die "services.json not found in offline-bundle/"

echo ""
echo "======================================================"
echo "  CTF Monitor Hub — Offline Restore"
echo "  Bundle: $BUNDLE"
echo "======================================================"
echo ""

# ============================================================
# 0. Copy services.json to project root if not present
# ============================================================
if [[ ! -f "$SCRIPT_DIR/services.json" ]]; then
    cp "$CONFIG" "$SCRIPT_DIR/services.json"
    ok "Restored services.json to project root"
fi

# Parse config
LLM_MODEL=$(python3 -c "import json; d=json.load(open('$SCRIPT_DIR/services.json')); print(d['ollama']['llm_model'])")
EMBED_MODEL=$(python3 -c "import json; d=json.load(open('$SCRIPT_DIR/services.json')); print(d['ollama']['embed_model'])")

# ============================================================
# 1. Load Docker Images
# ============================================================
log "Loading Docker images from offline-bundle/images/..."
IMAGE_COUNT=0
FAIL_COUNT=0

for tarfile in "$BUNDLE/images/"*.tar; do
    [[ -f "$tarfile" ]] || continue
    name=$(basename "$tarfile" .tar)
    log "  Loading: $name"
    if docker load -i "$tarfile" 2>&1 | tail -2; then
        IMAGE_COUNT=$((IMAGE_COUNT+1))
    else
        warn "  Failed to load: $tarfile"
        FAIL_COUNT=$((FAIL_COUNT+1))
    fi
done

ok "Loaded $IMAGE_COUNT image(s) [${FAIL_COUNT} failed]"
echo ""
docker images --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}" | head -30
echo ""

# ============================================================
# 2. Install Python Wheels (into a venv for isolation)
# ============================================================
VENV="$SCRIPT_DIR/.venv"
log "Setting up Python virtual environment at $VENV..."

if [[ ! -d "$VENV" ]]; then
    python3 -m venv "$VENV" --without-pip
fi

# Bootstrap pip from wheel if needed
if ! "$VENV/bin/python" -m pip --version &>/dev/null 2>&1; then
    PIP_WHEEL=$(ls "$BUNDLE/wheels/pip-"*.whl 2>/dev/null | head -1)
    if [[ -n "$PIP_WHEEL" ]]; then
        "$VENV/bin/python" "$PIP_WHEEL/pip" install --no-index --find-links "$BUNDLE/wheels" pip
    else
        warn "pip wheel not found — trying ensurepip"
        python3 -m ensurepip --root "$VENV" 2>/dev/null || true
    fi
fi

log "Installing Python wheels from offline-bundle/wheels/..."
"$VENV/bin/python" -m pip install \
    --no-index \
    --find-links "$BUNDLE/wheels" \
    --quiet \
    fastapi uvicorn pymongo redis scapy requests python-dotenv \
    numpy scikit-learn httpx pydantic aiofiles websockets \
    dpkt colorama rich typer schedule pyzmq watchdog psutil \
    paramiko jinja2 aiohttp ollama 2>/dev/null || \
warn "Some wheels failed to install — check $BUNDLE/wheels/ for missing packages"

ok "Python environment ready at $VENV"

# ============================================================
# 3. Restore Ollama Models
# ============================================================
log "Restoring Ollama models..."
# Same path-detection as pull-and-save.sh: a systemd-managed install runs as
# user "ollama" and stores models under /usr/share/ollama/.ollama (mode 700,
# unreadable/unwritable by other users without sudo).
if [[ -n "${OLLAMA_MODELS:-}" ]]; then
    OLLAMA_HOME="$OLLAMA_MODELS"
elif [[ -w "$HOME/.ollama" || ! -e "$HOME/.ollama" ]]; then
    OLLAMA_HOME="$HOME/.ollama"
elif [[ -d "/usr/share/ollama/.ollama" ]]; then
    OLLAMA_HOME="/usr/share/ollama/.ollama"
else
    OLLAMA_HOME="$HOME/.ollama"
fi

if [[ -d "$BUNDLE/ollama-models/blobs" ]]; then
    if [[ -w "$(dirname "$OLLAMA_HOME")" ]] || mkdir -p "$OLLAMA_HOME" 2>/dev/null; then
        rsync -a --ignore-existing "$BUNDLE/ollama-models/" "$OLLAMA_HOME/" 2>/dev/null || \
        cp -rn "$BUNDLE/ollama-models/." "$OLLAMA_HOME/"
        ok "Ollama models restored to $OLLAMA_HOME"
    else
        warn "Cannot write to $OLLAMA_HOME as $(whoami) — run:"
        warn "  sudo rsync -a $BUNDLE/ollama-models/ $OLLAMA_HOME/ && sudo chown -R ollama:ollama $OLLAMA_HOME"
    fi
else
    warn "No Ollama model blobs found in bundle — models must be pulled manually"
fi

# Verify models available
if command -v ollama &>/dev/null; then
    # Briefly start ollama to verify
    if ! pgrep -x ollama > /dev/null; then
        ollama serve &>/dev/null &
        OLLAMA_PID=$!
        sleep 3
        ollama list 2>/dev/null || warn "Could not list Ollama models"
        kill $OLLAMA_PID 2>/dev/null || true
    else
        ollama list 2>/dev/null || warn "Could not list Ollama models"
    fi
fi

# ============================================================
# 4. Verify repos
# ============================================================
log "Verifying cloned repos..."
for repo in tulip pcap-broker; do
    if [[ -d "$BUNDLE/repos/$repo" ]]; then
        ok "Repo present: $repo"
    else
        warn "Repo missing: $repo — some features may not work"
    fi
done

# ============================================================
# 5. Final summary
# ============================================================
echo ""
echo -e "${GREEN}======================================================"
echo "  Offline restore complete!"
echo ""
echo "  Next step: run  bash bringup.sh"
echo -e "======================================================${NC}"
echo ""

# Sanity check: confirm no internet was used
log "Network sanity check (these should all FAIL on air-gapped machine)..."
if curl -s --connect-timeout 2 https://google.com &>/dev/null; then
    warn "WARNING: Machine appears to have internet access — verify air-gap!"
else
    ok "No internet detected (expected on air-gapped machine)"
fi
