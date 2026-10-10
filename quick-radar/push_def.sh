#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"
GD1_CONFIG="${GD1_CONFIG:-$SCRIPT_DIR/config.env}"
gd1_load_config
gd1_ssh_args

CANDIDATE="${1:-$SCRIPT_DIR/service.conf.hardened}"
TARGET_SITE="${2:-/etc/nginx/sites-enabled/default}"

[[ -f "$CANDIDATE" ]] || { echo "[-] Không tìm thấy file WAF: $CANDIDATE" >&2; exit 1; }

echo "======================================================================"
echo "    [*] ĐẨY WAF NGINX LÊN VULNBOX (${SSH_USER}@${VULNBOX_IP}:${SSH_PORT})"
echo "======================================================================"

cat "$CANDIDATE" | "${GD1_SSH[@]}" "cat > /tmp/service.conf.hardened && \
    cp /tmp/service.conf.hardened $TARGET_SITE && \
    nginx -t && systemctl reload nginx && echo '[+] Nginx WAF reload thành công!'"

echo "[+] Hoàn tất triển khai WAF lên $TARGET_SITE"
