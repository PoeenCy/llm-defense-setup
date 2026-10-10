#!/usr/bin/env bash
# ==============================================================================
# set_target.sh - CẤU HÌNH NHANH IP / PORT / SSH CHO TOÀN BỘ HỆ THỐNG
# Dùng khi nhận Vulnbox mới hoặc thay đổi IP/Port/SSH Key
# ==============================================================================
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config.env"

# Load cấu hình cũ nếu có
if [ -f "$CONFIG_FILE" ]; then
    # shellcheck source=/dev/null
    source "$CONFIG_FILE"
fi

# Giá trị mặc định
VULNBOX_IP="${VULNBOX_IP:-10.13.2.10}"
SSH_PORT="${SSH_PORT:-2201}"
SSH_USER="${SSH_USER:-root}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/cyberknight_id}"
SERVICE_PORTS="${SERVICE_PORTS:-80 8000 8001 8002 8003 9000}"
MY_TEAM_ID="${MY_TEAM_ID:-1}"
TOTAL_TEAMS="${TOTAL_TEAMS:-20}"
TARGET_IP_TEMPLATE="${TARGET_IP_TEMPLATE:-10.13.2.10}"
TARGET_PORT_TEMPLATE="${TARGET_PORT_TEMPLATE:-800{team}}"
LOCAL_PCAP_DIR="${LOCAL_PCAP_DIR:-/mnt/d/Tools/tulip/pcaps}"
PCAP_SYNC_INTERVAL="${PCAP_SYNC_INTERVAL:-10}"

# Kiểm tra nếu truyền tham số dòng lệnh:
# Cú pháp: ./set_target.sh <IP> [SSH_PORT] [SSH_KEY] [SERVICE_PORTS] [MY_TEAM_ID]
if [ -n "$1" ]; then
    VULNBOX_IP="$1"
    [ -n "$2" ] && SSH_PORT="$2"
    [ -n "$3" ] && SSH_KEY="$3"
    [ -n "$4" ] && SERVICE_PORTS="$4"
    [ -n "$5" ] && MY_TEAM_ID="$5"
else
    echo "======================================================================"
    echo "    [+] CẤU HÌNH MỤC TIÊU VÀ VULNBOX (INTERACTIVE TARGET SETUP)        "
    echo "======================================================================"
    echo "Nhấn [Enter] để giữ nguyên giá trị trong ngoặc vuông vuông [...]."
    echo "----------------------------------------------------------------------"

    read -r -p "[?] Vulnbox IP [$VULNBOX_IP]: " input_ip
    [ -n "$input_ip" ] && VULNBOX_IP="$input_ip"

    read -r -p "[?] SSH Port [$SSH_PORT]: " input_port
    [ -n "$input_port" ] && SSH_PORT="$input_port"

    read -r -p "[?] SSH User [$SSH_USER]: " input_user
    [ -n "$input_user" ] && SSH_USER="$input_user"

    read -r -p "[?] SSH Key Path [$SSH_KEY]: " input_key
    [ -n "$input_key" ] && SSH_KEY="$input_key"

    read -r -p "[?] Service Ports [$SERVICE_PORTS]: " input_sports
    [ -n "$input_sports" ] && SERVICE_PORTS="$input_sports"

    read -r -p "[?] Team ID của bạn [$MY_TEAM_ID]: " input_team
    [ -n "$input_team" ] && MY_TEAM_ID="$input_team"
fi

# Chuẩn hóa đường dẫn key
SSH_KEY="${SSH_KEY/#\~/$HOME}"

# Ghi lại file config.env
cat <<EOF > "$CONFIG_FILE"
# ==============================================================================
# GD1 MASTER CONFIGURATION FILE (CẤU HÌNH TẬP TRUNG CHO ATTACK & DEFENSE)
# Tự động đồng bộ IP, Port, SSH Key cho toàn bộ các script Workstation & Vulnbox
# ==============================================================================

# 1. THÔNG TIN VULNBOX ĐỘI NHÀ (DEFENSE)
VULNBOX_IP="$VULNBOX_IP"
SSH_PORT="$SSH_PORT"
SSH_USER="$SSH_USER"
SSH_KEY="$SSH_KEY"

# 2. CÁC CỔNG DỊCH VỤ CỦA GIẢI ĐẤU (Dùng cho tcpdump & scan)
SERVICE_PORTS="$SERVICE_PORTS"

# 3. THÔNG TIN ĐỘI NHÀ & ĐỐI THỦ (ATTACK / RECON)
MY_TEAM_ID="$MY_TEAM_ID"
TOTAL_TEAMS="$TOTAL_TEAMS"
TARGET_IP_TEMPLATE="$TARGET_IP_TEMPLATE"
TARGET_PORT_TEMPLATE="$TARGET_PORT_TEMPLATE"

# 4. TULIP IDS (ĐƯỜNG DẪN PCAP TRÊN WORKSTATION)
LOCAL_PCAP_DIR="$LOCAL_PCAP_DIR"
PCAP_SYNC_INTERVAL=$PCAP_SYNC_INTERVAL
EOF

echo ""
echo "[+] Đã lưu cấu hình mới vào: $CONFIG_FILE"
echo "----------------------------------------------------------------------"
echo "  - Vulnbox : ${SSH_USER}@${VULNBOX_IP}:${SSH_PORT}"
echo "  - SSH Key : $SSH_KEY"
echo "  - Ports   : $SERVICE_PORTS"
echo "  - Team ID : $MY_TEAM_ID"
echo "----------------------------------------------------------------------"

# Kiểm tra SSH nhanh
echo "[*] Đang kiểm tra kết nối SSH thử nghiệm..."
SSH_KEY_OPT=""
if [ -n "$SSH_KEY" ] && [ -f "$SSH_KEY" ]; then
    SSH_KEY_OPT="-i $SSH_KEY -o IdentitiesOnly=yes"
fi
SSH_CMD="ssh -F /dev/null -p $SSH_PORT -o StrictHostKeyChecking=no -o ConnectTimeout=5 $SSH_KEY_OPT ${SSH_USER}@${VULNBOX_IP}"

if $SSH_CMD "echo SSH_TEST_OK" >/dev/null 2>&1; then
    echo -e "\033[0;32m[+] KẾT NỐI SSH THÀNH CÔNG TỚI VULNBOX!\033[0m"
else
    echo -e "\033[1;33m[!] CẢNH BÁO: Chưa kết nối được SSH tới ${SSH_USER}@${VULNBOX_IP}:${SSH_PORT}!\033[0m"
    echo "    Vui lòng kiểm tra lại IP, Port, SSH Key hoặc trạng thái mạng VPN."
fi

# Đồng bộ config.env vào các thư mục con DEF và ATK
cp "$CONFIG_FILE" "$SCRIPT_DIR/DEF/config.env" 2>/dev/null || true
cp "$CONFIG_FILE" "$SCRIPT_DIR/ATK/config.env" 2>/dev/null || true

# Tự động sinh danh sách toàn bộ mục tiêu vào ATK/targets.json
TARGETS_JSON="$SCRIPT_DIR/ATK/targets.json"
if [ -d "$SCRIPT_DIR/ATK" ]; then
    python3 - <<PYEOF
import json

total = int("$TOTAL_TEAMS")
my_team = int("$MY_TEAM_ID")
ip_tmpl = "$TARGET_IP_TEMPLATE"
port_tmpl = "$TARGET_PORT_TEMPLATE"
default_ports = [int(p) for p in "$SERVICE_PORTS".split() if p.isdigit()]

targets = []
for t in range(1, total + 1):
    ip = ip_tmpl.replace("{team}", str(t)) if "{team}" in ip_tmpl else "$VULNBOX_IP"
    if "{team}" in port_tmpl:
        try:
            ports = [int(port_tmpl.replace("{team}", str(t)))]
        except:
            ports = default_ports
    else:
        ports = default_ports
    targets.append({
        "team_id": t,
        "ip": ip,
        "open_ports": ports,
        "is_own": (t == my_team),
        "is_alive": True,
        "latency": 1.0
    })

with open("$TARGETS_JSON", "w", encoding="utf-8") as f:
    json.dump(targets, f, indent=2)
PYEOF
    echo "[+] Đã tự động cập nhật danh sách các đội vào: $TARGETS_JSON"
fi

echo "======================================================================"
echo "[+] CÁC PHÍM TẮT TIỆN LỢI ĐÃ SẴN SÀNG:"
echo "  1. SSH nhanh vào Vulnbox       : ./ssh_box.sh"
echo "  2. Đẩy bộ công cụ DEF lên box : ./push_def.sh"
echo "  3. Bật đồng bộ PCAP về Tulip   : ./pull_pcaps.sh"
echo "======================================================================"
