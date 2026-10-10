#!/usr/bin/env bash
# ==============================================================================
# start_dashboard.sh - KHỞI ĐỘNG BẢNG ĐIỀU KHIỂN TÁC CHIẾN DEFENSE UI & AI RADAR
# Mở trình duyệt tại http://localhost:8888 để xem trực tiếp lưu lượng 20 đội
# ==============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="python3"
if [ -d "$HOME/ctf_env" ]; then
    PYTHON_BIN="$HOME/ctf_env/bin/python3"
fi

PORT="${1:-8888}"

echo "======================================================================"
echo "    [*] KHỞI ĐỘNG CTF LIVE DEFENSE RADAR (WEB UI & AI OLLAMA)         "
echo "======================================================================"
echo "[+] Truy cập Dashboard tại: http://localhost:$PORT"
echo "[+] Nhấn Ctrl+C để dừng."
echo "======================================================================"

exec $PYTHON_BIN "$SCRIPT_DIR/DEF/live_dashboard.py" "$PORT"
