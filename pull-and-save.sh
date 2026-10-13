#!/usr/bin/env bash
# pull-and-save.sh — Pull all required Docker images, Python wheels, and clone
#                     repos into offline-bundle/ for air-gapped deployment.
# Run this ONCE while you have internet. Takes ~20-40 min depending on bandwidth.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="$SCRIPT_DIR/contest-runtime/config/services.json"
BUNDLE="$SCRIPT_DIR/offline-bundle"
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YELLOW='\033[1;33m'; NC='\033[0m'

log()  { echo -e "${CYAN}[PULL]${NC}  $*"; }
ok()   { echo -e "${GREEN}[OK]${NC}    $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC}  $*"; }
die()  { echo -e "${RED}[FATAL]${NC} $*"; exit 1; }

[[ -f "$CONFIG" ]] || die "services.json not found at $SCRIPT_DIR"

mkdir -p "$BUNDLE/images" "$BUNDLE/wheels" "$BUNDLE/repos"

echo ""
echo "======================================================"
echo "  CTF Monitor Hub — Offline Bundle Builder"
echo "  Bundle path: $BUNDLE"
echo "======================================================"
echo ""

# ============================================================
# 1. Docker Images
# ============================================================
log "Pulling Docker images..."

IMAGES=(
    "redis:7-alpine"
    "jasonish/suricata:7.0"
    "python:3.11-slim"
    "alpine:3.19"
)

for img in "${IMAGES[@]}"; do
    log "  Pulling: $img"
    docker pull "$img" || warn "Failed to pull $img — will skip"
done

# Build/pull Tulip images
log "Cloning Tulip for image build..."
TULIP_DIR="$BUNDLE/repos/tulip"
if [[ -d "$TULIP_DIR/.git" ]]; then
    git -C "$TULIP_DIR" pull --rebase || warn "Tulip git pull failed, using existing"
else
    git clone --depth 1 https://github.com/enowars/tulip.git "$TULIP_DIR"
fi

log "Building Tulip Docker images..."
cd "$TULIP_DIR"
docker compose build 2>&1 | tail -5 || warn "Tulip build had issues"
cd "$SCRIPT_DIR"

# Save all images
log "Saving all Docker images to offline-bundle/images/..."
ALL_IMAGES=$(docker images --format "{{.Repository}}:{{.Tag}}" | grep -v '<none>' | grep -v "sagemath" | grep -v "bagisto" | sort -u)

while IFS= read -r img; do
    safe_name=$(echo "$img" | tr '/:' '_')
    tarfile="$BUNDLE/images/${safe_name}.tar"
    if [[ ! -f "$tarfile" ]]; then
        log "  Saving: $img → ${safe_name}.tar"
        docker save "$img" -o "$tarfile" && ok "  Saved $img" || warn "  Failed to save $img"
    else
        ok "  Already saved: $img"
    fi
done <<< "$ALL_IMAGES"

# Also save Tulip-built images specifically
log "Saving Tulip-specific images..."
for tulip_img in $(docker images --format "{{.Repository}}:{{.Tag}}" | grep -i tulip | grep -v '<none>'); do
    safe_name=$(echo "$tulip_img" | tr '/:' '_')
    tarfile="$BUNDLE/images/${safe_name}.tar"
    [[ -f "$tarfile" ]] && continue
    log "  Saving Tulip image: $tulip_img"
    docker save "$tulip_img" -o "$tarfile" || warn "  Failed: $tulip_img"
done

# ============================================================
# 2. Python Wheels
# ============================================================
log "Downloading Python wheels..."
PACKAGES=(
    "fastapi>=0.111.0"
    "uvicorn[standard]>=0.29.0"
    "redis>=5.0.0"
    "scapy>=2.5.0"
    "requests>=2.31.0"
    "python-dotenv>=1.0.0"
    "numpy>=1.26.0"
    "scikit-learn>=1.4.0"
    "httpx>=0.27.0"
    "pydantic>=2.7.0"
    "aiofiles>=23.2.0"
    "websockets>=12.0"
    "dpkt>=1.9.8"
    "netifaces>=0.11.0"
    "colorama>=0.4.6"
    "rich>=13.7.0"
    "typer>=0.12.0"
    "schedule>=1.2.0"
    "pyzmq>=25.1.0"
    "watchdog>=4.0.0"
    "psutil>=5.9.0"
    "paramiko>=3.4.0"
    "jinja2>=3.1.0"
    "aiohttp>=3.9.0"
)

pip download "${PACKAGES[@]}" \
    --dest "$BUNDLE/wheels" \
    --python-version 3.11 \
    --platform manylinux_2_28_x86_64 \
    --only-binary=:all: \
    2>/dev/null || true

# Also download platform-agnostic pure-python wheels
pip download "${PACKAGES[@]}" \
    --dest "$BUNDLE/wheels" \
    --no-deps \
    2>/dev/null || warn "Some wheels may be missing — check $BUNDLE/wheels"

WHEEL_COUNT=$(ls "$BUNDLE/wheels/"*.whl 2>/dev/null | wc -l)
ok "Downloaded $WHEEL_COUNT wheel files"

# ============================================================
# 3. Clone repos
# ============================================================
log "Cloning required repositories..."

declare -A REPOS=(
    ["pcap-broker"]="https://github.com/fox-it/pcap-broker.git"
)

for name in "${!REPOS[@]}"; do
    url="${REPOS[$name]}"
    dest="$BUNDLE/repos/$name"
    if [[ -d "$dest/.git" ]]; then
        log "  Updating: $name"
        git -C "$dest" pull --rebase || warn "git pull failed for $name"
    else
        log "  Cloning: $name"
        git clone --depth 1 "$url" "$dest" || warn "Clone failed: $name ($url)"
    fi
done

# ============================================================
# 4. Copy services.json into bundle
# ============================================================
cp "$CONFIG" "$BUNDLE/services.json"
ok "Copied services.json into bundle"

# ============================================================
# 5. Write manifest
# ============================================================
cat > "$BUNDLE/MANIFEST.txt" << MANIFEST
CTF Monitor Hub — Offline Bundle Manifest
Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")
Host: $(hostname)

== Docker Images ==
$(ls "$BUNDLE/images/"*.tar 2>/dev/null | xargs -I{} basename {} || echo "none")

== Python Wheels ==
$(ls "$BUNDLE/wheels/"*.whl 2>/dev/null | wc -l) wheel files

== Repos ==
$(ls "$BUNDLE/repos/" 2>/dev/null || echo "none")
MANIFEST

ok "Bundle manifest written"

echo ""
echo -e "${GREEN}======================================================"
echo "  Bundle complete! Contents:"
du -sh "$BUNDLE"/images "$BUNDLE"/wheels "$BUNDLE"/repos 2>/dev/null || true
echo -e "======================================================${NC}"
echo ""
echo "To restore on an air-gapped machine:"
echo "  rsync -a offline-bundle/ target-machine:/path/to/Setup_tool/offline-bundle/"
echo "  Then run: bash offline-restore.sh"
