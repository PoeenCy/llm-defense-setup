# START.md — Khởi chạy (đọc file này đầu tiên)

Toàn bộ hệ thống bật bằng **một lệnh**, chạy trên **máy của bạn** (máy monitor), trong thư mục repo này.

```bash
MODE=contest bash deploy-all.sh
```

(`MODE=prep` chỉ dùng khi diễn tập ở nhà — bật thêm `mock-vulnbox`/`ml-fingerprint` nếu
`services.json` cho phép. **Không bao giờ dùng `MODE=prep` lúc thi thật.**)

Chạy lại bao nhiêu lần cũng an toàn (idempotent). Bước nào lỗi thì tự lùi về chế độ an toàn, không làm sập phần còn lại.

> Repo này **không còn tính năng LLM/AI** nào (đã bỏ hẳn — xem `docs/STATUS.md`). Toàn bộ pipeline
> chạy rule-based (Suricata/ctf_proxy/regex), không cần GPU.

---

## Trước khi chạy — cần gì
- **Docker + docker compose** đang chạy (rootless podman cũng được).
- File **`contest-runtime/config/services.json`** đúng thông tin BTC cấp: IP/port vulnbox, flag
  regex, SSH alias. Sửa nhanh ở tab CONFIG hoặc bằng tay rồi
  `bash contest-runtime/config/validate-config.sh`.
- **SSH tới vulnbox** (alias `vulnbox.capture_ssh_alias`) nếu muốn bắt traffic / cài ctf_proxy. Không có cũng chạy được phần giám sát.
- Không cần root trên máy bạn. Bắt packet trên vulnbox cần sudo ở đó (không có thì bỏ qua, phần khác vẫn chạy).
- Python module `redis` cho `host_agent.py` (chạy trực tiếp trên host, không phải trong
  container) — `deploy-all.sh` tự kiểm tra và tự cài qua pip ở bước đầu tiên; nếu không cài được
  nó sẽ báo `[FAIL]` rõ ràng kèm lệnh sửa tay, không để lỗi âm thầm.

## `deploy-all.sh` làm gì (7 bước)
1. **Preflight** — kiểm tra docker/docker compose/python3 có sẵn, module `redis` import được
   (tự cài qua pip nếu thiếu). Thiếu gì báo `[FAIL]` rõ ràng và dừng ngay, chưa đụng gì cả.
2. Kiểm tra `services.json`.
3. Bật stack local (Tulip, Suricata, detection, watchdog, dashboard) + tiến trình nền `host_agent.py`.
4. Bắt traffic trên vulnbox (tcpdump) và kéo pcap về `traffic/`.
5. Cài bẫy trên vulnbox: honeytoken + OS watchdog (bỏ qua nếu không SSH/sudo được).
6. Cài ctf_proxy (chặn). Không được thì tự lùi về **chỉ giám sát**.
7. Health check — in ra cái gì ✓/✗ kèm lệnh sửa.

## Sau khi chạy — kiểm tra
1. Mở **http://localhost:8080** → góc phải phải ghi **LIVE**.
2. Tab **SERVICES**: mọi dòng nên **✓ RUNNING**. Dòng **✗** → bấm **Start**. (Các dòng vulnbox sẽ ✗ nếu VM chưa bật — bình thường.)
3. Hoặc chạy `bash health-check.sh` để xem nhanh cái gì sống/chết.

## Lệnh hữu ích
```bash
MODE=contest bash deploy-all.sh         # bật / bật lại tất cả
bash health-check.sh                    # cái gì đang chết + lệnh sửa
MODE=contest bash bringup.sh            # chỉ bật lại stack local (deploy-all gọi sẵn)
docker logs ctf-dashboard --tail 50     # lỗi backend dashboard
tail -50 .host-agent.log                # lỗi khi áp rule / điều khiển service
```

## Đọc tiếp
- **Dùng Dashboard thế nào:** `docs/DASHBOARD_GUIDE.md`
- **Tra nhanh lúc đang thi (đổi port/IP/rule gấp):** `CONFIG.md`
- **Viết rule khi gặp đòn lạ (kể cả RCE, offline):** `docs/RULE_COOKBOOK.md`
- **Chuyển từ diễn tập sang thi thật:** `docs/GOLIVE.md`
- **Sự cố chi tiết:** `docs/RUNBOOK.md`
- **Thư viện rule sẵn:** `contest-runtime/detection/rules-library/` (Suricata cảnh báo),
  `contest-runtime/defense/rules-library/` (ctf_proxy/nginx chặn)

## Nếu không mở được Dashboard
```bash
bash health-check.sh
docker logs ctf-dashboard --tail 50
MODE=contest bash deploy-all.sh
```
Sửa config bằng tay khi không có Dashboard: sửa `contest-runtime/config/services.json` →
`bash contest-runtime/config/validate-config.sh` → `MODE=contest bash deploy-all.sh`.
