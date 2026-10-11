# START.md — Khởi chạy (đọc file này đầu tiên)

Toàn bộ hệ thống bật bằng **một lệnh**, chạy trên **máy của bạn** (máy monitor), trong thư mục repo này.

```bash
bash deploy-all.sh
```

Chạy lại bao nhiêu lần cũng an toàn (idempotent). Bước nào lỗi thì tự lùi về chế độ an toàn, không làm sập phần còn lại.

---

## Trước khi chạy — cần gì
- **Docker + docker compose** đang chạy (rootless podman cũng được).
- File **`services.json`** đúng thông tin BTC cấp: IP/port vulnbox, flag regex, SSH alias. Sửa nhanh ở tab CONFIG hoặc bằng tay rồi `bash validate-config.sh`.
- **SSH tới vulnbox** (alias `vulnbox.capture_ssh_alias`) nếu muốn bắt traffic / cài ctf_proxy. Không có cũng chạy được phần giám sát.
- Không cần root trên máy bạn. Bắt packet trên vulnbox cần sudo ở đó (không có thì bỏ qua, phần khác vẫn chạy).

## `deploy-all.sh` làm gì (6 bước)
1. Kiểm tra `services.json`.
2. Bật stack local (Tulip, Suricata, detection, watchdog, ML, LLM, dashboard) + tiến trình nền `host_agent.py`.
3. Bắt traffic trên vulnbox (tcpdump) và kéo pcap về `traffic/`.
4. Cài bẫy trên vulnbox: honeytoken + OS watchdog (bỏ qua nếu không SSH/sudo được).
5. Cài ctf_proxy (chặn). Không được thì tự lùi về **chỉ giám sát**.
6. Health check — in ra cái gì ✓/✗ kèm lệnh sửa.

## Sau khi chạy — kiểm tra
1. Mở **http://localhost:8080** → góc phải phải ghi **LIVE**.
2. Tab **SERVICES**: mọi dòng nên **✓ RUNNING**. Dòng **✗** → bấm **Start**. (Các dòng vulnbox sẽ ✗ nếu VM chưa bật — bình thường.)
3. Hoặc chạy `bash health-check.sh` để xem nhanh cái gì sống/chết.

## Lệnh hữu ích
```bash
bash deploy-all.sh                      # bật / bật lại tất cả
bash health-check.sh                    # cái gì đang chết + lệnh sửa
bash bringup.sh                         # chỉ bật lại stack local (deploy-all gọi sẵn)
docker logs ctf-dashboard --tail 50     # lỗi backend dashboard
tail -50 .host-agent.log                # lỗi khi áp rule / điều khiển service
```

## Đọc tiếp
- **Dùng Dashboard thế nào:** `docs/DASHBOARD_GUIDE.md`
- **Tra nhanh lúc đang thi (đổi port/IP/rule gấp):** `CONFIG.md`
- **Viết rule khi gặp đòn lạ (kể cả RCE, offline):** `docs/RULE_COOKBOOK.md`
- **Chuyển từ diễn tập sang thi thật:** `docs/GOLIVE.md`
- **Sự cố chi tiết:** `docs/RUNBOOK.md`
- **Thư viện rule sẵn:** `rules-library/` (Suricata cảnh báo + ctf_proxy/nginx chặn)

## Nếu không mở được Dashboard
```bash
bash health-check.sh
docker logs ctf-dashboard --tail 50
bash deploy-all.sh
```
Sửa config bằng tay khi không có Dashboard: sửa `services.json` → `bash validate-config.sh` → `bash deploy-all.sh`.
