# Hướng dẫn dùng Dashboard (khi thi — không mạng, không AI)

Mở `http://localhost:8080`. Thanh tab: **MONITOR · EVENTS · HUNT · RULES · APPLIED · SERVICES · CONFIG**.
Ký hiệu trạng thái (không dựa màu): **✓** chạy · **✗** dừng/lỗi · **!** cảnh báo/tạm dừng · **?** chưa rõ.
Mức sự kiện luôn ghi chữ: CRITICAL > HIGH > MEDIUM > LOW > INFO.

Không có LLM/AI nào trong dashboard — mọi phân tích là bạn tự đọc flow. Mọi rule chặn phải do bạn
bấm, không có gì tự động áp dụng.

## 0. Bật hệ thống
1. `MODE=contest bash deploy-all.sh` (ngày thi) hoặc `MODE=prep bash deploy-all.sh` (luyện tập,
   có thêm `mock-vulnbox`). Chạy lại bao nhiêu lần cũng an toàn. Các bước: preflight (kiểm
   python3/`redis` package, docker) → validate config → stack local → capture (tcpdump trên
   vulnbox + kéo pcap về) → honeytoken/OS-watchdog → ctf_proxy (nếu `services.json` có khai) →
   health check. Bước nào lỗi thì lùi về an toàn, không dừng cả hệ thống.
2. Mở Dashboard, góc phải phải ghi **LIVE**. Tab **SERVICES** mọi dòng phải **✓ RUNNING**.

## 1. Mỗi tab làm gì
| Tab | Dùng khi |
|---|---|
| **MONITOR** | Nhìn nhanh alert mới + SLA watchdog (✓ UP / ! SLOW / ✗ DOWN) + tình trạng hệ thống. |
| **EVENTS** | Mọi sự kiện gộp lại, tìm kiếm. Cột **Tulip flow** = kết nối thật đằng sau alert (✓ khớp, ~ gần đúng, — không thấy). Mỗi dòng có 4 nút: **Detail** (xem raw JSON) · **Make rule** (mở tab RULES, nạp sẵn flow, bạn tự chọn chặn bằng gì) · **Alert** (tự sinh + áp ngay 1 rule Suricata — luôn an toàn, không bao giờ chặn gì) · **Block** (tự sinh + upload ngay 1 rule ctf_proxy — có xác nhận, từ chối nếu chỉ khớp 1 đường dẫn trần không tham số, vì dễ chặn nhầm checker). |
| **HUNT** | Dò lại một cuộc tấn công: lọc theo IP, port, khoảng thời gian, chuỗi/regex — trên cả event log **và** mọi flow trong Tulip. |
| **RULES** | Viết rule từ một flow, test trên traffic cũ, áp dụng. Bảng có cấu trúc cho cả Suricata (3a) và ctf_proxy (3b) — số thứ tự, tên/SID, mô tả, thời điểm thêm, Edit/Delete trực tiếp trên bảng. Có **Rule library** (rule mẫu sẵn, chỉ alert). |
| **APPLIED** | Rule nào đang chạy, chạy ở đâu (Suricata trên máy mình / ctf_proxy trên vulnbox — theo từng service nếu vulnbox có nhiều service), kêu/chặn bao nhiêu lần, từ IP nào. Tự load lại mỗi lần mở tab, không cần F5. |
| **SERVICES** | Bật / tắt / restart từng thành phần; tạm dừng hoặc gỡ ctf_proxy (áp dụng cho **mọi** service cùng lúc — không để sót 1 service vẫn đang chặn khi bạn tưởng đã pause hết); chặn IP hoặc chặn theo nội dung packet (iptables fallback). |
| **CONFIG** | BTC đổi IP / port / flag regex / mức giữ pcap → sửa → Validate → Save & apply. |

## 2. Alert flag-out — bị tấn công hay không?
`flag-out` = "một flag vừa rời khỏi service". Checker cũng đọc flag ra, nên **không phải cứ flag-out là bị hack**. Detection đã phân loại sẵn:
- `flag-planted` — flag được **ghi vào** service (thường là checker đặt flag mới). INFO.
- `flag-echo` — response lặp lại flag vừa được ghi trong cùng lần bắt. LOW.
- `flag-out` — flag rời service ở trường hợp khác. Message kèm: *ai đã đặt flag này, lúc nào* và *nhãn ML của bên gửi request* (nếu `ml-fingerprint` đang chạy, chỉ MODE=prep). Vẫn phải tự mở flow đọc **request** để phân biệt checker đọc flag vs kẻ trộm.
- `honeytoken-out` — flag mồi rời service → gần như chắc chắn bị đọc trộm.

Cả bốn loại này (đặc biệt `flag-out`/`honeytoken-out`/`honeytoken`) được cảnh báo **mạnh hơn** mọi
loại khác: toast dính màn hình (bấm mới tắt, không tự biến mất), tiếng beep không bị gộp/bỏ qua dù
nhiều cái tới gần nhau, và thông báo trình duyệt không tự đóng. Vẫn **không có gì tự động chặn** —
chỉ đảm bảo bạn không lướt qua mà bỏ lỡ.

Quy trình: EVENTS → lọc CRITICAL / gõ `flag` → xem cột Tulip flow → **Make rule** (flow nạp vào RULES, flag tô vàng). Request lạ: `' OR 1=1`, `../`, `{{`, `;id`, tham số lạ, ID người khác…

## 3. Viết rule chặn (RULES)
1. **Nạp flow:** từ EVENTS bấm Make rule, hoặc dán flow id / URL Tulip vào ô (1) → Load flow.
2. **Chọn phần độc hại:** bấm một **Quick pick** (path, từng tham số, body, header, file…) hoặc bôi đen bằng chuột → Use selection. Chọn càng hẹp càng tốt.
3. **Loại rule:**
   - **SURICATA (detect, panel 3a):** chỉ cảnh báo, không bao giờ hỏng service — Suricata đọc lại pcap sau khi traffic đã xảy ra, cấu trúc này **không có khả năng chặn** dù rule ghi `alert` hay `drop`. Generate → **Test on recent traffic** → Add to ruleset → Test syntax & Apply. Bảng ở trên khung raw-text hiện ngay dòng mới kèm nhãn "not applied yet" cho tới khi bạn bấm Apply.
   - **CTF_PROXY (block thật, panel 3b):** nếu vulnbox có nhiều service, chọn đúng **service** ở dropdown đầu panel trước — mỗi service có filter riêng. Nếu service đó là raw TCP (không phải HTTP), builder chỉ cho chọn target "raw" (không có url/path/param để đọc). Generate & insert → xem code → Check & Upload.
4. **Luôn test trước khi chặn:** dù định chặn, làm 1 rule Suricata cùng điều kiện → Test on recent traffic. Nếu khớp IP checker / máy mình → rule quá rộng, thu hẹp lại.
5. **Rule library:** chọn file (scanner, SQLi, NoSQLi, SSTI, SSRF, GraphQL, traversal/LFI, cmdi/RCE, deser/XXE, upload/webshell, flag exfil, XSS) → Test on recent traffic → **Add & apply now**. Toàn bộ chỉ **alert**, không chặn.

## 4. ctf_proxy — nơi rule chặn chạy
- Rule chặn nằm trên **vulnbox**, một thư mục riêng cho mỗi service: `ctf-proxy-<team>/proxy/filter_modules/<tên-service>/<tên-service>_in.py`. ctf_proxy tự nạp lại khi file đổi, không restart.
- Chỉ áp dụng cho service khai `"proto": "tcp"` trong `services.json`. Service `"proto": "udp"` **không** có ctf_proxy — dùng chặn-theo-nội-dung ở tab SERVICES thay thế.
- **Nginx chỉ chuyển tiếp/failover**, không viết rule vào nginx (nginx tự sinh lại từ config mỗi lần ctf_proxy khởi động).
- Rule Suricata nằm trên **máy mình**: `suricata/lib/rules/suricata.rules`, chỉ alert.

## 5. Xem rule đang áp (APPLIED)
Liệt kê mọi rule live: Suricata (sid, số lần kêu, IP nguồn) và ctf_proxy theo từng service (method,
số lần chặn, IP bị chặn — có cột "Service" nếu có nhiều hơn 1). Tab này tự tải lại mỗi lần bạn mở
nó (không chỉ lần đầu tiên trong buổi), nên số liệu luôn khớp với RULES/EVENTS. Nếu một rule
ctf_proxy chặn **IP của checker** → rule quá rộng → SERVICES → ctf_proxy → Pause filtering (tạm
dừng TẤT CẢ service cùng lúc, không chỉ 1). Bấm Edit để nhảy tới đúng rule.

## 6. Dò lại tấn công (HUNT)
Điền IP kẻ tấn công + "last 1h" → mọi event và flow của IP đó. Hoặc gõ chuỗi (`huhu.php`, `UNION`, một flag) để tìm trong toàn bộ traffic. Tóm tắt cho biết lần đầu/cuối xuất hiện, các loại sự kiện, client nhiều nhất. Bấm Make rule / open để sang RULES hoặc mở flow trong Tulip.

## 7. Sự cố
| Thấy gì | Làm gì |
|---|---|
| SLA tụt sau khi upload rule ctf_proxy | SERVICES → ctf_proxy → **Pause filtering** (dừng tất cả service) → sửa rule → Resume. Hoặc RULES (3b) → Rollback (đúng service đang chọn). |
| Service DOWN vì ctf_proxy hỏng | SERVICES → ctf_proxy → **Uninstall (emergency)** (trả port về service gốc cho TẤT CẢ service cùng lúc). |
| Không có alert / flow mới | SERVICES → Traffic capture → Start. Vẫn không → vulnbox tắt / mất SSH. |
| Container treo | SERVICES → Restart. |
| BTC đổi IP/port (ngay cả trong lúc thi) | CONFIG → Quick edit → Validate → Save & apply. Không cần sửa code gì — mọi nơi đọc port đều đọc động từ `services.json`. Sai → Rollback. |
| Đầy đĩa | pcap tự dọn theo 3 tầng (xoá pcap cũ → dọn Docker build cache → tùy chọn dọn flow cũ trong Tulip, xem CONFIG → retention). |
| Dashboard không mở | `bash health-check.sh` rồi `MODE=contest bash deploy-all.sh`. |

## 8. Ghi nhớ
- Không có gì tự động chặn, và không có LLM/AI nào trong hệ thống — mọi rule chặn do bạn tự đọc flow rồi bấm.
- Mọi thay đổi (rule, config, bật/tắt service, dọn pcap) được ghi vào EVENTS nguồn `host-agent`.
- Log text thuần: EVENTS → Open as .log, hoặc `curl -s localhost:8080/api/events.log | less`.
- Sửa code dashboard: bản đồ file trong `contest-runtime/dashboard/README.md`.
