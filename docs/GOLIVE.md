# GOLIVE.md — Chuyển từ test (mock-vulnbox) sang thi thật

> Viết trong lúc diễn tập (2026-10-10), để dùng lại khi thi thật. Đọc từ trên xuống, làm theo
> đúng thứ tự. Đừng nhảy cóc.

## Tổng quan sự khác biệt

| | Test (hiện tại) | Thi thật |
|---|---|---|
| Vulnbox | `mock-vulnbox` container, giả | VM thật của bạn, do ban tổ chức cấp |
| Traffic vào Tulip | Đọc file pcap tĩnh trong `traffic/` | Live stream qua `PCAP_OVER_IP` từ pcap-broker trên vulnbox |
| ctf_proxy | Chạy, chặn SQLi giả | **CHƯA chạy** — xem Phase 2 ở dưới |
| `services.json` | IP/port giả (`10.0.0.2`, `svc1`/`svc2`) | IP/port/flag regex **thật** do ban tổ chức cho |

Hôm nay (diễn tập) bạn chọn: **chỉ bật Phase 1 (monitor/detect), chưa bật ctf_proxy thật.**
Quyết định này hợp lý — ctf_proxy auto-block traffic sai có thể làm rớt SLA, nên cần test kỹ
trước khi bật thật trong lúc thi (không có thời gian debug giữa trận).

---

## PHASE 1 — Monitor + Detect (làm được ngay hôm nay)

### Bước 0 — Thu thập thông tin từ ban tổ chức

Trước khi đổi config, cần có:
- [ ] IP của vulnbox của team mình
- [ ] SSH user + cách auth (key hay password?) vào vulnbox
- [ ] Regex flag thật (ví dụ `ENOFLAG[A-Za-z0-9+/=]{32}` — mỗi giải khác nhau)
- [ ] CIDR của teams network (để phân biệt traffic đồng nghiệp vs đối thủ)
- [ ] URL submit flag (gameserver) — không bắt buộc cho monitor, chỉ cần nếu muốn tự động nộp
- [ ] Danh sách service + port thật trên vulnbox (tên, port, http hay raw tcp)
- [ ] IP của máy monitor này trên mạng thi (dùng lệnh `ip addr` hoặc hỏi ban tổ chức)

### Bước 1 — Sửa `services.json`

```bash
nano services.json
```

Sửa đúng các field sau (đừng đổi tên field, chỉ đổi giá trị):

```json
"vulnbox": {
  "ip": "<IP vulnbox thật>",
  "ssh_user": "<user SSH thật>",
  "ssh_port": 22,
  "capture_iface": "eth0",          // interface mạng thật trên vulnbox — hỏi ban tổ chức nếu không chắc
  "pcap_broker_port": 4242
},
"monitor_host": {
  "ip": "<IP máy monitor này trên mạng thi>",
  ...
},
"flag": {
  "regex": "<regex flag thật>",
  "submit_url": "<URL submit thật, nếu có>"
},
"teams_cidr": "<CIDR mạng teams thật>",
"mock_vulnbox": {
  "enabled": false        // ⚠️ QUAN TRỌNG — xem giải thích dưới
},
"services": [
  { "name": "...", "port": ..., "proto": "tcp", "layer": "l7-http" },
  ...                      // sửa đúng danh sách service thật trên vulnbox
]
```

**`mock_vulnbox.enabled: false` làm 3 việc tự động** (đã code sẵn, không cần sửa gì khác):
1. `bringup.sh` **không khởi động** container `mock-vulnbox` nữa.
2. `bringup.sh` **không khởi động** `ctf_proxy` nữa (vì nó chưa được wire để front vulnbox
   thật — xem Phase 2).
3. `generators/gen-tulip-env.py` tự đổi `PCAP_OVER_IP` từ rỗng sang
   `host.docker.internal:<pcap_broker_port>` — Tulip sẽ nhận traffic **live** từ vulnbox
   thay vì đọc file pcap tĩnh.

```bash
bash validate-config.sh     # phải PASS trước khi tiếp tục
```

### Bước 2 — Deploy lên vulnbox thật (qua SSH)

> ⚠️ **3 script này chưa từng được chạy thật trên vulnbox thật trong session trước** (chỉ
> code xong, chưa test — xem `docs/STATUS.md`). Deploy xong, kiểm tra kỹ output từng bước,
> đừng tin "chạy xong không lỗi" là đủ.

```bash
# Đảm bảo SSH vào vulnbox được trước (test tay 1 lần):
ssh -p 22 <ssh_user>@<vulnbox_ip> echo ok

# 1. Deploy capture (tcpdump/pcap-broker) — bắt buộc, không có cái này Tulip không thấy gì
bash vulnbox-deploy/deploy-capture.sh

# 2. Deploy OS watchdog (file-integrity + process monitor) — khuyến nghị
bash vulnbox-deploy/deploy-os-watchdog.sh

# 3. Deploy honeytoken (đặt flag giả làm bẫy) — khuyến nghị
bash vulnbox-deploy/deploy-honeytoken.sh
```

Nếu script nào fail: đọc lỗi SSH trước (sai user/key/port là nguyên nhân phổ biến nhất),
đừng đoán.

### Bước 3 — Bật hệ thống monitor

```bash
bash bringup.sh
```

Kỳ vọng thấy trong log:
- `mock_vulnbox.enabled=false — skipping the toy vulnerable app (real vulnbox mode)`
- `mock_vulnbox.enabled=false — skipping ctf_proxy (not yet wired for a real vulnbox...)`
- Health checks: Detection/Dashboard/IOC-Brain/Tulip UI đều `UP`

### Bước 4 — Xác nhận traffic thật đang vào

```bash
# Assembler phải thấy traffic LIVE, không phải "Monitoring dir: /traffic"
docker logs tulip-assembler-1 --tail 20
# Kỳ vọng: "Connecting to PCAP-over-IP: host.docker.internal:4242" rồi KHÔNG còn
# "connection refused" liên tục — nếu vẫn refused, pcap-broker trên vulnbox
# chưa chạy đúng, quay lại Bước 2.

# Dashboard — mở trình duyệt
xdg-open http://localhost:8080

# Watchdog phải thấy service thật đang sống
docker logs ctf-watchdog --tail 10
```

**Dấu hiệu mọi thứ ổn:** `assembler` không còn log lỗi connection refused liên tục, Tulip UI
(`localhost:3000`) hiện flow thật đang chạy qua, watchdog không báo `SERVICE DOWN` liên tục.

---

## PHASE 2 — ctf_proxy thật (CHƯA LÀM — để sau)

Ghi lại để không quên khi cần làm:

**Vấn đề:** `ctf_proxy` hiện chỉ biết front `mock-vulnbox` (container ảo trên cùng máy, cùng
Docker network). Để chặn traffic thật trước vulnbox thật, cần **redirect traffic trên chính
vulnbox** vào `ctf_proxy` — việc này **chưa có script**, cần làm thêm:

1. Viết `vulnbox-deploy/deploy-ctfproxy-redirect.sh`: SSH vào vulnbox, dùng `iptables` NAT
   (`PREROUTING`/`REDIRECT` hoặc `DNAT`) để chuyển port thật (ví dụ 9001) sang port mà
   `ctf_proxy` đang listen trên máy monitor — **hoặc** chạy hẳn `ctf_proxy` ngay trên vulnbox
   nếu vulnbox đủ tài nguyên (tránh thêm 1 hop network).
2. Sửa `generators/gen-ctfproxy.py`: khi `mock_vulnbox.enabled=false`, `target_ip`/`target_port`
   phải trỏ vào **service thật trên vulnbox** (IP thật + port thật), không phải
   `mock-vulnbox` hostname.
3. **Test bằng `harness.py` trước khi tin** — và test ở giờ nghỉ/tick không quan trọng trước,
   không bật lúc đang bị tính điểm SLA liên tục. Risk thật: filter block sai traffic hợp lệ
   của checker bot → mất điểm SLA cả trận.
4. Có kế hoạch rollback nhanh: nếu ctf_proxy gây lỗi, phải tắt được trong vài giây
   (`docker compose down` trên `offline-bundle/repos/ctf_proxy/`) mà không làm rớt service.

**Khuyến nghị:** chỉ bật Phase 2 sau khi Phase 1 đã chạy ổn ít nhất 1 tick đầy đủ, và có thời
gian test riêng (không phải lúc đang live).

---

## Rollback về chế độ test

```bash
bash teardown.sh
# services.json: đổi mock_vulnbox.enabled lại thành true
bash bringup.sh
```
