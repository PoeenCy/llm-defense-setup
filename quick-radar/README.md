# ⚡ CTF Attack-Defense Quick-Radar & Live Defense Stack

> **Dành cho đồng đội (Defense Team)**: Module phòng thủ siêu tốc, không cần Docker nặng, triển khai và bảo vệ trong vòng **3 phút đầu trận**.

---

## 🚀 3 Bước Triển Khai Nhanh Khi Vào Trận

### Bước 1: Thiết lập mục tiêu Vulnbox
```bash
# Cú pháp: ./set_target.sh <TEAM_ID> [SSH_PORT]
./set_target.sh 2 2201

# Hoặc tùy biến chi tiết IP/Port:
./set_target.sh -i 10.13.2.10 -p 2201 -t 2
```

### Bước 2: Đẩy cấu hình WAF Nginx 5 tầng lên Vulnbox
```bash
./push_def.sh
```
*Script sẽ tự động scp file cấu hình hardened lên Vulnbox, kiểm tra cú pháp bằng `nginx -t` và reload `systemctl reload nginx` một cách an toàn.*

### Bước 3: Mở Live Defense Radar & Web UI
```bash
./start_dashboard.sh 8888
```
Mở trình duyệt: **`http://localhost:8888`**
- **SLA Watch**: Giám sát liên tục trạng thái Checker Bot (tỷ lệ 200/201 vs 403/500).
- **Enemy Radar**: Tự động bóc tách IP đối thủ (từ Team 1 đến Team 20) xem đội nào đang spam đòn gì.
- **Threat Alert**: Đánh dấu đỏ các truy vấn nguy hiểm (webshell `.php`, dump flag `/api/messages`, chèn lệnh OS `cmd`, `cat`, `select`).
- **AI Cyber Assistant**: Click nút **"Hỏi AI Phân Tích (Ollama)"** để model `Foundation-Sec-8B` giải thích ngay kỹ thuật tấn công và chỉ cách vá trong 15 giây.

---

## 🛡️ Cấu Trúc Các File Trong Thư Mục

| File | Chức năng |
| :--- | :--- |
| **`live_dashboard.py`** | Server Python (aiohttp + WebSocket) nhận log streaming SSH từ Vulnbox và phục vụ giao diện Web. |
| **`start_dashboard.sh`** | Script 1-click khởi chạy Dashboard và tự động kích hoạt môi trường ảo/python. |
| **`service.conf.hardened`** | Cấu hình Nginx WAF 5 tầng tối ưu SLA, đã test thực chiến chặn 100% webshell và SQLi dump mà không làm gãy Checker Bot. |
| **`push_def.sh`** | 1-click deploy WAF lên Vulnbox và reload an toàn. |
| **`set_target.sh`** | 1-click đổi IP/Port/Team ID cho toàn bộ hệ thống. |
| **`ssh_box.sh`** | Phím tắt SSH vào Vulnbox mà không cần gõ dài. |
| **`HUONG_DAN_THUC_CHIEN.md`** | **Sổ tay tác chiến chi tiết**: Phân chia theo từng giai đoạn (5 phút đầu, 10 phút, khi bị khai thác, các case dị và cách xử lý). |

---

## ⚠️ Lưu Ý Quan Trọng Về Checker SLA
- Checker Bot gửi `POST /api/messages?select=id,msg` và `POST /api/chats?select=id,name` để cắm flag: **WAF cho phép POST hoàn toàn bình thường**.
- Đối thủ gửi `GET /api/messages` hoặc `GET /api/messages?select=id,msg` để dump sạch cờ: **WAF trả 403 Forbidden chặn đứng**.
- Checker kiểm tra MathSays gửi phép tính nhân chia `*` (`%2A`) và chấm phẩy `;` (`%3B`): **Đã được cô lập vào location riêng, không bị chặn**.
