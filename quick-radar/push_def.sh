#!/usr/bin/env bash
# ==============================================================================
# push_def.sh - ĐẨY TOÀN BỘ BỘ CÔNG CỤ DEF LÊN VULNBOX TRONG 1 GIÂY
# Tự động đọc IP, Port, SSH Key từ config.env
# ==============================================================================
set -e

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

echo "======================================================================"
echo "    [*] ĐẨY BỘ CÔNG CỤ DEF LÊN VULNBOX (${SSH_USER}@${VULNBOX_IP}:${SSH_PORT})"
echo "======================================================================"

if [ ! -d "$SCRIPT_DIR/DEF" ]; then
    echo "[-] Lỗi: Không tìm thấy thư mục $SCRIPT_DIR/DEF!"
    exit 1
fi

# Đồng bộ config.env vào DEF để trên box có sẵn cấu hình
cp "$CONFIG_FILE" "$SCRIPT_DIR/DEF/config.env" 2>/dev/null || true

echo "[*] Đang nén và truyền luồng DEF lên ${SSH_USER}@${VULNBOX_IP}:/root/..."
# Dùng Tar Stream qua SSH: Cực nhanh, bảo toàn phân quyền, không bao giờ bị nghẽn như scp
tar -czf - -C "$SCRIPT_DIR" DEF | ssh $SSH_OPTS "${SSH_USER}@${VULNBOX_IP}" "tar -xzf - -C /root/ && chmod +x /root/DEF/*.sh 2>/dev/null || true"

echo "======================================================================"
echo "[+] HOÀN TẤT! ĐÃ ĐỒNG BỘ DEF LÊN VULNBOX."
echo "    Bây giờ bạn có thể vào box bằng: ./ssh_box.sh"
echo "    Sau đó kích hoạt phòng thủ: cd /root/DEF && ./one_click_def.sh"
echo "======================================================================"
