# Tra nhanh lúc đang thi

**Bật mọi thứ:** `MODE=contest bash deploy-all.sh` (chạy lại bao nhiêu lần cũng an toàn).
**Mọi việc còn lại làm trong Dashboard:** http://localhost:8080 — 7 tab: **MONITOR · EVENTS · HUNT · RULES · APPLIED · SERVICES · CONFIG**.
**Hướng dẫn dùng Dashboard đầy đủ:** `docs/DASHBOARD_GUIDE.md`.
Dashboard hỏng hẳn? Xem mục cuối ("Không mở được Dashboard").

> Repo này **không còn tính năng LLM/AI nào** (đã bỏ hẳn — xem `docs/STATUS.md`). Mọi thứ dưới
> đây chạy thuần rule-based (Suricata, ctf_proxy, regex), không có bước nào cần GPU/model.

---

## Quy trình chặn một đòn tấn công (tab RULES)

1. **Tìm request độc hại** — trong Tulip (nút 🌷 Tulip UI) hoặc tab EVENTS → bấm **Make rule** trên sự kiện.
2. Dán **flow id** của Tulip vào ô (1) → **Load flow** → **bôi đen** đúng phần độc hại → **Use selection**.
   Công cụ tự đoán phần đó nằm ở đâu (URL, tham số nào, header nào, body) để rule hẹp nhất có thể.
3. Ở (2) chọn loại rule:
   - **SURICATA (detect)** — chỉ *cảnh báo*, không bao giờ làm gãy service. → **Generate** → **Test on recent traffic**.
   - **CTF_PROXY (block)** — *chặn thật*. → **Generate & insert into filter**.
4. **Test on recent traffic** chạy rule trên các pcap đã bắt và cho biết nó khớp **bao nhiêu lần, từ những IP nào**.
   Nếu có IP của **bot chấm điểm / traffic hợp lệ** trong danh sách → rule quá rộng, **đừng dùng để chặn** — thu hẹp lại
   (thêm điều kiện, giới hạn path/method, chọn đoạn đặc trưng hơn).
5. Áp dụng ở (3a)/(3b): Suricata → **Test syntax & Apply**; ctf_proxy → **Check & Upload**.
   Rule lỗi cú pháp bị từ chối, bản đang chạy giữ nguyên. Mỗi lần áp đều có backup → **Rollback**.

**Nghi rule ctf_proxy chặn nhầm bot (SLA tụt)?** Tab SERVICES → ctf_proxy → **Pause filtering**
(tắt mọi rule chặn ngay lập tức, traffic vẫn đi qua, rule được giữ lại) → sửa rule → **Resume filtering**.
**ctf_proxy tự nó hỏng làm service DOWN?** → **Uninstall (emergency)**: gỡ khỏi đường đi, trả port về service gốc.

---

## Tra theo tình huống

| Tình huống | Làm gì |
|---|---|
| Không biết cái gì đang chạy / chết | Tab MONITOR → System Status, hoặc tab SERVICES. Ký hiệu: **✓** chạy · **✗** dừng · **!** cảnh báo · **?** chưa rõ |
| Một service bị treo | Tab SERVICES → **Restart** (giữ nguyên cấu hình container) |
| Không có traffic mới | Tab SERVICES → *Traffic capture* → **Start**. Vẫn không được → vulnbox mất kết nối (xem bảng dưới) |
| BTC đổi IP / port vulnbox | Tab CONFIG → Quick edit *Vulnbox IP* / *Service public port* → **Validate** → **Save & apply** |
| Đổi flag regex / URL nộp flag | Tab CONFIG → *Flag regex* / *Flag submit URL*. Token nộp flag **không** nằm trong config (xem `team-tokens.txt`) |
| Bật / tắt chặn thật (ctf_proxy) | Tab CONFIG → *ctf_proxy mode*: `disabled` (chỉ giám sát) hoặc `docker-compose` + 4 trường *ctf_proxy SSH alias / Target compose file/service/network*, rồi chạy `bash contest-runtime/defense/deploy-ctfproxy.sh` (tự nối cho MỌI service `"proto": "tcp"` trong `services[]`; mỗi service có thể tự khai `compose_service` riêng trong JSON bên cạnh, nếu không khai thì dùng field *Target compose service* này làm mặc định chung) |
| Xem một flag-out bị lấy bằng chuỗi request nào | Tab **FLAG TRACE** (cần `flagtrace.enabled` + `flagtrace.trace.enabled`). Chọn profile → bấm một *Value link* để xem giá trị đi từ đâu tới đâu. Có traffic đến muộn → **Re-analyse**. Chi tiết: `contest-runtime/flagtrace/README.md` |
| Bị bắn quá nhiều, Flag-trace ingest chậm/tụt lại | Tab **FLAG TRACE** → ô *Ingest decoder*: hạ `full` → `gated` (vẫn bắt flag mã hóa phổ biến, nhanh hơn nhiều khi body nhỏ), chỉ chọn `off` khi thật cần (mất flag chỉ lộ sau decode). Giữ qua restart; System Status báo vàng tới khi bấm *Back to config default* |
| Lỡ sửa config hỏng | Tab CONFIG → **Rollback** (mỗi lần lưu đều có backup trong `contest-runtime/config-backups/`) |
| Không có ctf_proxy, cần chặn gấp mà attacker **chung IP với checker** | Tab SERVICES → khung "Fallback block — theo NỘI DUNG" → dán đúng chuỗi đặc trưng trong payload (không phải IP) → **Block content**. Chặn theo nội dung TCP payload (iptables `string`-match), không quan tâm IP, nên không sợ mất SLA do trùng IP checker — nhưng vẫn nên **Test on recent traffic** (tab RULES) với cùng chuỗi trước |
| Muốn đọc log thuần text | EVENTS → **Open as .log**, hoặc `curl -s localhost:8080/api/events.log \| less` |
| Đồng đội muốn xem Dashboard từ máy khác | Tab CONFIG → *Dashboard bind IP* = IP LAN của máy này. **Chỉ làm trong mạng tin cậy** — các cổng này không có mật khẩu |

---

## Bảo mật cổng (đã khoá sẵn)

Máy này nằm **trong VPN thi đấu**. Mọi cổng điều khiển (Dashboard 8080, Redis 6380, Tulip 3000,
Postgres 5433, ...) chỉ nghe `127.0.0.1`. Chỉ cổng **9999** mở ra ngoài, và chỉ nhận đúng 2 thứ từ
vulnbox: báo honeytoken và báo cáo OS-watchdog. Các API quản trị của detection nằm ở
`127.0.0.1:9998`.

---

## Thiếu quyền / mất kết nối — mất gì, còn gì

| Thiếu gì | Mất gì | Vẫn chạy được |
|---|---|---|
| Không SSH được vào vulnbox-host (VM tắt) | Không có traffic mới, không chặn/sửa rule ctf_proxy được | Dashboard, Tulip, Suricata, Events, dữ liệu cũ |
| SSH được nhưng không có `sudo`/root | Không bắt được packet (`tcpdump` cần root — giới hạn của OS) | Mọi thứ khác; pcap ai đó thả vào `traffic/` vẫn được xử lý |
| `ctf_proxy` chưa cấu hình | Không chặn được | Tự lùi về chỉ giám sát |

---

## Không mở được Dashboard

```bash
bash health-check.sh                     # cái gì đang chết, kèm lệnh sửa
docker logs ctf-dashboard --tail 50      # lỗi backend dashboard
tail -50 .host-agent.log                 # lỗi khi áp rule / điều khiển service / lưu config
MODE=contest bash deploy-all.sh          # bật lại tất cả
```
Sửa config bằng tay khi không có Dashboard: sửa `contest-runtime/config/services.json` →
`bash contest-runtime/config/validate-config.sh` → `MODE=contest bash deploy-all.sh`.

**`deploy-all.sh` dừng ngay ở bước "Preflight checks"?** Đọc đúng dòng `[FAIL]` — nó ghi rõ thiếu
gì (thiếu `docker`, `docker compose`, hoặc module Python `redis`). Script **tự thử cài `redis`**
qua pip trước khi báo lỗi; nếu vẫn fail, xem `/tmp/pip-redis-install.log` rồi cài tay:
`pip3 install --user redis`.

---

## File nào làm gì

| File | Làm gì |
|---|---|
| `contest-runtime/config/services.json` | Config duy nhất (sửa qua tab CONFIG, hoặc tay) |
| `deploy-all.sh` | Bật mọi thứ (preflight → bringup → capture/traps/ctf_proxy → health check) |
| `bringup.sh` | Bật stack local (Tulip/detection/dashboard/watchdog), ghi `.env` (được `deploy-all.sh` gọi) |
| `health-check.sh` / `contest-runtime/health_check.py` | Tự chẩn đoán |
| `contest-runtime/host_agent.py` + `contest-runtime/hostagent/` | Tiến trình nền trên host, thực hiện mọi thay đổi mà Dashboard yêu cầu (chỉ thao tác trong danh sách trắng `hostagent/actions/`, chỉ service trong `hostagent/registry.py`) |
| `contest-runtime/dashboard/` | Giao diện — bản đồ file theo từng tab: `contest-runtime/dashboard/README.md` |
| `contest-runtime/monitor/`, `contest-runtime/detection/`, `contest-runtime/watchdog/`, `contest-runtime/defense/` | Script deploy lên vulnbox (capture, honeytoken, OS-watchdog, ctf_proxy — được gọi tự động bởi `deploy-all.sh`) |
| `docs/RUNBOOK.md` | Giải thích sâu + toàn bộ troubleshooting |
