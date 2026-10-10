#!/usr/bin/env bash
# ==============================================================================
# reset_tulip_session.sh - DỌN SẠCH TULIP IDS & PCAPS CHO PHIÊN THI ĐẤU MỚI
# ==============================================================================
# Chức năng:
# 1. Lưu trữ (Archive) toàn bộ file .pcap cũ sang thư mục lưu trữ có đánh dấu thời gian.
# 2. Xóa sạch volume database TimescaleDB của Tulip (docker compose down -v).
# 3. Khởi động lại Tulip với cơ sở dữ liệu trống 100% sẵn sàng cho trận đấu mới.
# 4. Tùy chọn dọn sạch cả PCAP trên Vulnbox (--remote).
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${GD1_CONFIG:-$SCRIPT_DIR/config.env}"

# Đọc cấu hình LOCAL_PCAP_DIR
LOCAL_PCAP_DIR="/mnt/d/Tools/tulip/pcaps"
if [ -f "$CONFIG_FILE" ]; then
    VAL=$(grep -E "^LOCAL_PCAP_DIR=" "$CONFIG_FILE" | cut -d'=' -f2- | tr -d '"' | tr -d "'" || true)
    if [ -n "$VAL" ]; then LOCAL_PCAP_DIR="$VAL"; fi
fi

TULIP_ROOT="$(dirname "$LOCAL_PCAP_DIR")"
TULIP_COMPOSE="$TULIP_ROOT/docker-compose.yml"

REMOTE_CLEAN=0
RESTART_CONTAINERS=1

while (($#)); do
    case "$1" in
        --remote) REMOTE_CLEAN=1; shift;;
        --no-restart) RESTART_CONTAINERS=0; shift;;
        -h|--help)
            echo "Cách dùng: ./reset_tulip_session.sh [OPTIONS]"
            echo "Options:"
            echo "  --remote      Dọn sạch cả file PCAP cũ trên máy Vulnbox từ xa"
            echo "  --no-restart  Dọn dữ liệu nhưng không tự khởi động lại container Tulip"
            exit 0
            ;;
        *) echo "Tùy chọn không hợp lệ: $1. Dùng --help để xem hướng dẫn." >&2; exit 2;;
    esac
done

echo "======================================================================"
echo "    🌷 TULIP IDS & PCAP CLEANUP TOOL (CHUẨN BỊ CHO CTF MỚI)           "
echo "======================================================================"

# 1. DỌN VÀ ARCHIVE TOÀN BỘ PCAP CỤC BỘ
if [ -d "$LOCAL_PCAP_DIR" ]; then
    PCAP_COUNT=$(find "$LOCAL_PCAP_DIR" -maxdepth 1 -name "*.pcap" | wc -l)
    if [ "$PCAP_COUNT" -gt 0 ]; then
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        ARCHIVE_DIR="${TULIP_ROOT}/pcaps_local_archive/session_${TIMESTAMP}"
        mkdir -p "$ARCHIVE_DIR"
        
        echo "[*] Tìm thấy $PCAP_COUNT file PCAP cũ trong $LOCAL_PCAP_DIR."
        echo "[*] Đang chuyển toàn bộ vào thư mục lưu trữ: $ARCHIVE_DIR..."
        mv "$LOCAL_PCAP_DIR"/*.pcap "$ARCHIVE_DIR/" 2>/dev/null || true
        echo "[+] Đã dọn sạch thư mục $LOCAL_PCAP_DIR (bảo toàn dữ liệu cũ tại $ARCHIVE_DIR)."
    else
        echo "[+] Thư mục PCAP cục bộ ($LOCAL_PCAP_DIR) đã sạch, không có file thừa."
    fi
else
    echo "[!] Không tìm thấy thư mục: $LOCAL_PCAP_DIR, tạo mới..."
    mkdir -p "$LOCAL_PCAP_DIR"
fi

# 2. XÓA SẠCH DATABASE TIMESCALEDB CỦA TULIP (RESET GIAO DIỆN WEB :3000)
if [ -f "$TULIP_COMPOSE" ] && command -v docker &>/dev/null; then
    echo "----------------------------------------------------------------------"
    echo "[*] Đang dừng Tulip và xóa sạch database TimescaleDB cũ..."
    docker compose -f "$TULIP_COMPOSE" down -v 2>/dev/null || true
    echo "[+] Đã xóa sạch toàn bộ flow/packet cũ trong Database của Tulip."

    if [ "$RESTART_CONTAINERS" -eq 1 ]; then
        echo "[*] Đang khởi động lại Tulip với cơ sở dữ liệu hoàn toàn mới..."
        docker compose -f "$TULIP_COMPOSE" up -d
        echo "[+] Tulip đã khởi động lại thành công!"
        echo "    👉 Truy cập Tulip Web UI: http://localhost:3000"
    fi
else
    echo "[!] Không tìm thấy $TULIP_COMPOSE hoặc máy chưa bật Docker."
    echo "    (Nếu chạy Tulip trên máy khác hoặc qua WSL, hãy chạy 'docker compose down -v && docker compose up -d' tại thư mục Tulip)."
fi

# 3. DỌN SẠCH PCAP TRÊN VULNBOX TỪ XA (NẾU CÓ CỜ --remote)
if [ "$REMOTE_CLEAN" -eq 1 ]; then
    echo "----------------------------------------------------------------------"
    echo "[*] Đang dọn sạch PCAP cũ trên máy Vulnbox..."
    if [ -f "$SCRIPT_DIR/ssh_box.sh" ]; then
        bash "$SCRIPT_DIR/ssh_box.sh" "mkdir -p /var/lib/gd1/pcaps_archive && mv /var/lib/gd1/pcaps/*.pcap /var/lib/gd1/pcaps_archive/ 2>/dev/null || true; echo '[+] Đã archive PCAP trên Vulnbox thành công!'"
    fi
fi

echo "======================================================================"
echo "    ✅ HOÀN TẤT! TULIP ĐÃ SẠCH 100% SẴN SÀNG CHO TRẬN ĐẤU MỚI         "
echo "======================================================================"
