# Hướng dẫn dùng Dashboard (khi thi — không mạng, không AI)

Mở `http://localhost:8080`. Thanh tab: **MONITOR · EVENTS · HUNT · RULES · APPLIED · SERVICES · CONFIG**.
Ký hiệu trạng thái (không dựa màu): **✓** chạy · **✗** dừng/lỗi · **!** cảnh báo/tạm dừng · **?** chưa rõ.
Mức sự kiện luôn ghi chữ: CRITICAL > HIGH > MEDIUM > LOW > INFO.

## 0. Bật hệ thống
1. `bash deploy-all.sh` (chạy lại bao nhiêu lần cũng an toàn). 6 bước: validate → stack local → capture (tcpdump trên vulnbox + kéo pcap về) → OS watchdog → ctf_proxy → health check. Bước nào lỗi thì lùi về an toàn, không dừng cả hệ thống.
2. Mở Dashboard, góc phải phải ghi **LIVE**. Tab **SERVICES** mọi dòng phải **✓ RUNNING**.

## 1. Mỗi tab làm gì
| Tab | Dùng khi |
|---|---|
| **MONITOR** | Nhìn nhanh alert mới + SLA watchdog (✓ UP / ! SLOW / ✗ DOWN) + tình trạng hệ thống. |
| **EVENTS** | Mọi sự kiện gộp lại, tìm kiếm. Cột **Tulip flow** = kết nối thật đằng sau alert (✓ khớp, ~ gần đúng, — không thấy). Nút Make rule / Ask LLM. |
| **HUNT** | Dò lại một cuộc tấn công: lọc theo IP, port, khoảng thời gian, chuỗi/regex — trên cả event log **và** mọi flow trong Tulip. |
| **RULES** | Viết rule từ một flow, test trên traffic cũ, áp dụng. Có **Rule library** (rule mẫu sẵn). |
| **APPLIED** | Rule nào đang chạy, chạy ở đâu (Suricata trên máy mình / ctf_proxy trên vulnbox), kêu/chặn bao nhiêu lần, từ IP nào. |
| **SERVICES** | Bật / tắt / restart từng thành phần; tạm dừng hoặc gỡ ctf_proxy. |
| **CONFIG** | BTC đổi IP / port / flag regex / mức giữ pcap → sửa → Validate → Save & apply. |

## 2. Alert flag-out — bị tấn công hay không?
`flag-out` = "một flag vừa rời khỏi service". Checker cũng đọc flag ra, nên **không phải cứ flag-out là bị hack**. Detection đã phân loại sẵn:
- `flag-planted` — flag được **ghi vào** service (thường là checker đặt flag mới). INFO.
- `flag-echo` — response lặp lại flag vừa được ghi trong cùng lần bắt. LOW.
- `flag-out` — flag rời service ở trường hợp khác. Message kèm: *ai đã đặt flag này, lúc nào* và *nhãn ML của bên gửi request*. Vẫn phải tự mở flow đọc **request** để phân biệt checker đọc flag vs kẻ trộm.
- `honeytoken-out` — flag mồi rời service → gần như chắc chắn bị đọc trộm.

Quy trình: EVENTS → lọc CRITICAL / gõ `flag` → xem cột Tulip flow → **Make rule** (flow nạp vào RULES, flag tô vàng). Request lạ: `' OR 1=1`, `../`, `{{`, `;id`, tham số lạ, ID người khác…

## 3. Viết rule chặn (RULES)
1. **Nạp flow:** từ EVENTS bấm Make rule, hoặc dán flow id / URL Tulip vào ô (1) → Load flow.
2. **Chọn phần độc hại:** bấm một **Quick pick** (path, từng tham số, body, header, file…) hoặc bôi đen bằng chuột → Use selection. Chọn càng hẹp càng tốt.
3. **Loại rule:**
   - **SURICATA (detect):** chỉ cảnh báo, không bao giờ hỏng service. Generate → **Test on recent traffic** → Add to ruleset → (3a) Test syntax & Apply.
   - **CTF_PROXY (block):** chặn thật. Generate & insert → xem code (3b) → Check & Upload.
4. **Luôn test trước khi chặn:** dù định chặn, làm 1 rule Suricata cùng điều kiện → Test on recent traffic. Nếu khớp IP checker / máy mình → rule quá rộng, thu hẹp lại.
5. **Rule library:** chọn file (scanner, SQLi, NoSQLi, SSTI, SSRF, GraphQL, traversal/LFI, cmdi/RCE, deser/XXE, upload/webshell, flag exfil, XSS) → Test on recent traffic → **Add & apply now**. Toàn bộ chỉ **alert**, không chặn.

## 4. ctf_proxy — nơi rule chặn chạy
- Rule chặn nằm trên **vulnbox**: `ctf-proxy-<team>/proxy/filter_modules/web/web_in.py`. ctf_proxy tự nạp lại khi file đổi, không restart.
- **Nginx chỉ chuyển tiếp**, không viết rule vào nginx.
- Rule Suricata nằm trên **máy mình**: `suricata/lib/rules/suricata.rules`, chỉ alert.

## 5. Xem rule đang áp (APPLIED)
Liệt kê mọi rule live: Suricata (sid, số lần kêu, IP nguồn) và ctf_proxy (method, số lần chặn, IP bị chặn). Nếu một rule ctf_proxy chặn **IP của checker** → rule quá rộng → SERVICES → ctf_proxy → Pause filtering. Bấm Edit để nhảy tới đúng rule.

## 6. Dò lại tấn công (HUNT)
Điền IP kẻ tấn công + "last 1h" → mọi event và flow của IP đó. Hoặc gõ chuỗi (`huhu.php`, `UNION`, một flag) để tìm trong toàn bộ traffic. Tóm tắt cho biết lần đầu/cuối xuất hiện, các loại sự kiện, client nhiều nhất. Bấm Make rule / open để sang RULES hoặc mở flow trong Tulip.

## 7. Sự cố
| Thấy gì | Làm gì |
|---|---|
| SLA tụt sau khi upload rule ctf_proxy | SERVICES → ctf_proxy → **Pause filtering** → sửa rule → Resume. Hoặc RULES (3b) → Rollback. |
| Service DOWN vì ctf_proxy hỏng | SERVICES → ctf_proxy → **Uninstall (emergency)** (trả port về service gốc). |
| Không có alert / flow mới | SERVICES → Traffic capture → Start. Vẫn không → vulnbox tắt / mất SSH. |
| Container treo | SERVICES → Restart. |
| BTC đổi IP/port | CONFIG → Quick edit → Validate → Save & apply. Sai → Rollback. |
| Đầy đĩa | pcap tự dọn (xem CONFIG → retention). Hết thì giảm *Max pcap storage*. |
| Dashboard không mở | `bash health-check.sh` rồi `bash deploy-all.sh`. |

## 8. Ask LLM — đọc kết quả
Ask LLM tự tìm flow rồi gửi request/response thật cho model offline (~30–120s). Xem trường `_check`: `evidence:flow` + `grounded:true` = model đọc flow thật (**kết luận vẫn có thể sai**); `evidence:log` = chỉ đọc dòng alert (yếu); `invented_ips` khác rỗng = model bịa IP → bỏ. Quyết định chặn dựa vào flow + Test on recent traffic, không dựa vào LLM.

## 9. Ghi nhớ
- Không có gì tự động chặn — mọi rule chặn do bạn bấm.
- Mọi thay đổi (rule, config, bật/tắt service, dọn pcap) được ghi vào EVENTS nguồn `host-agent`.
- Log text thuần: EVENTS → Open as .log, hoặc `curl -s localhost:8080/api/events.log | less`.
- Sửa code dashboard: bản đồ file trong `dashboard/README.md`.
