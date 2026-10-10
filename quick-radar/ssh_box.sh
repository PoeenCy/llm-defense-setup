#!/usr/bin/env bash
# ==============================================================================
# ssh_box.sh - KẾT NỐI SSH NHANH VÀO VULNBOX THEO CẤU HÌNH TẬP TRUNG
# Dùng để vào shell hoặc chạy lệnh từ xa:
#   ./ssh_box.sh                      -> Mở bash shell trên Vulnbox
#   ./ssh_box.sh "ss -tulpn"          -> Chạy 1 lệnh và in kết quả
# ==============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config.env"

if [ -f "$CONFIG_FILE" ]; then
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
fi

VULNBOX_IP="${VULNBOX_IP:-10.13.2.10}"
SSH_PORT="${SSH_PORT:-2201}"
SSH_USER="${SSH_USER:-root}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/cyberknight_id}"
SSH_KEY="${SSH_KEY/#\~/$HOME}"

SSH_KEY_OPT=""
if [ -n "$SSH_KEY" ] && [ -f "$SSH_KEY" ]; then
    SSH_KEY_OPT="-i $SSH_KEY -o IdentitiesOnly=yes"
fi

SSH_OPTS="-F /dev/null -p $SSH_PORT -o StrictHostKeyChecking=no $SSH_KEY_OPT"

if [ $# -eq 0 ]; then
    echo "[*] Đang kết nối SSH tới ${SSH_USER}@${VULNBOX_IP}:${SSH_PORT}..."
    ssh $SSH_OPTS "${SSH_USER}@${VULNBOX_IP}"
else
    ssh $SSH_OPTS "${SSH_USER}@${VULNBOX_IP}" "$@"
fi
