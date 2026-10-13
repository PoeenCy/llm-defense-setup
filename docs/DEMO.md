# DEMO.md — Kịch bản trình diễn hệ thống CTF Monitor Hub (live audience)

> **Nguyên tắc vàng:** Mọi bước dưới đây chỉ dùng những gì đã verify thật trong phiên làm việc
> gần nhất (`docs/STATUS.md`, các mục 2026-10-13/14). Không demo bất cứ thứ gì chưa chạy thật.
>
> **Thay đổi so với bản cũ:** không còn bước "LLM phân tích IOC" — toàn bộ nhánh LLM/ioc-brain/
> Ollama đã bị gỡ khỏi repo theo quyết định của người dùng. Phần harness.py/mock-vulnbox-qua-
> ctf_proxy của bản cũ cũng **không còn áp dụng được**: `mock-vulnbox` (nay ở
> `prep-only/training/mock-vulnbox/`) không publish port ra host và **không có ctf_proxy nào
> đứng trước nó** trong layout hiện tại — ctf_proxy chỉ deploy qua SSH vào một vulnbox-host thật
> reachable (`contest-runtime/defense/deploy-ctfproxy.sh`), không có nhánh local/compose cho
> mock-vulnbox. Kịch bản dưới đây dùng đúng những gì thật sự nối với nhau: event thật → dashboard
> → rule → APPLIED, không cần mock-vulnbox.

---

## Tổng thời lượng ước tính

| Giai đoạn | Thời gian |
|---|---|
| Pre-flight (trước khi khán giả vào) | ~10 phút |
| Intro + context cho khán giả | 2 phút |
| Bước 1 — Một event thật xuất hiện | 2 phút |
| Bước 2 — Dashboard phản ứng (EVENTS, cảnh báo) | 2 phút |
| Bước 3 — Sinh rule & test (RULES) | 3 phút |
| Bước 4 — Rule đang chạy ở đâu (APPLIED) | 2 phút |
| Bước 5 — Kill switch / SLA (SERVICES) | 2 phút |
| Q&A buffer | 5 phút |
| **Tổng** | **~28 phút** |

---

## Phần 0 — PRE-FLIGHT (chạy TRƯỚC khi khán giả vào phòng ~10 phút)

### 0-A. Bật hệ thống

Có vulnbox thật (ví dụ DFCD practice arena) reachable qua SSH → dùng `MODE=contest` để demo cả
ctf_proxy thật. Không có gì sẵn → `MODE=prep` (chỉ thêm `mock-vulnbox`, nhưng lưu ý mock-vulnbox
**không demo được ctf_proxy** — xem cảnh báo ở đầu file).

```bash
cd /home/poeency/Documents/Setup_tool
MODE=contest bash deploy-all.sh    # hoặc MODE=prep nếu chưa có vulnbox thật nào cấu hình
```

**Output đúng trông như thế này** (trích đoạn quan trọng — 7 bước, bước nào fail thì lùi về an
toàn, không dừng cả hệ thống):

```
[Preflight] docker/docker-compose/python3/redis module ... OK
[OK] services.json validated
[OK] stack local started
[OK] capture: tcpdump remote + pull loop running
[OK] honeytoken / OS-watchdog deployed
[OK] ctf_proxy deployed (N service(s))   # bỏ qua nếu insertion.mode != docker-compose
[OK] health check: dashboard/detection/redis/tulip all UP
```

### 0-B. Health check nhanh

```bash
curl -s http://localhost:8080/ -o /dev/null -w "dashboard HTTP %{http_code}\n"
curl -s http://localhost:3000 -o /dev/null -w "Tulip UI HTTP %{http_code}\n"
docker exec ctf-redis redis-cli ping
```

Kỳ vọng: `200`, `200`, `PONG`.

### 0-C. Chuẩn bị 1 event thật để chỉ sẵn trên màn hình

Đừng chờ một cuộc tấn công thật xảy ra đúng lúc demo — chuẩn bị sẵn ít nhất 1 alert trước:

```bash
# detection_service.py có sẵn endpoint test này (không phải mock data giả trong UI — alert
# này đi qua đúng đường ống thật: push_alert → Redis "alerts" → publish → dashboard nhận qua WS)
curl -s -X POST http://127.0.0.1:9998/test/inject-flag   # port admin của detection, xem docker-compose
```

Mở sẵn Dashboard ở tab **EVENTS**, xác nhận event `flag-out` "TEST: Fake flag-out injected..." đã
xuất hiện.

> Nếu có vulnbox thật và muốn demo bằng traffic THẬT thay vì inject test: gửi một request chứa
> chuỗi khớp `flag.regex` tới service thật, đợi vài giây cho tcpdump/pcap-pull/Suricata/Tulip xử
> lý xong (chu kỳ pull mặc định 15s). Chậm hơn nhưng thuyết phục hơn — cân nhắc theo thời gian có.

---

## Phần 1 — INTRO (2 phút, nói với khán giả)

> *"Chúng tôi xây một hệ thống phòng thủ cho Attack-Defense CTF — không dùng AI, mọi quyết định
> chặn là con người tự đọc traffic thật rồi bấm. Hệ thống có ba lớp: (1) capture + phát hiện —
> biết ngay khi có traffic lạ hoặc flag bị lấy, (2) công cụ sinh rule từ chính traffic thật, không
> cần biết code, và (3) hai nơi chặn thật — Suricata chỉ cảnh báo, ctf_proxy/iptables mới chặn
> được. Tôi demo toàn bộ vòng lặp này live ngay bây giờ."*

Mở sẵn: Dashboard tab EVENTS trên 1 màn, terminal theo dõi log trên màn khác.

```bash
docker logs -f ctf-detection 2>&1 | grep -iE "alert|flag-out|proxy-blocked"
```

---

## Phần 2 — DEMO THEO KỊCH BẢN

---

### Bước 1 — Một event thật xuất hiện ⏱ ~2 phút

Event `flag-out` đã chuẩn bị ở Pre-flight 0-C đang nằm trong EVENTS. Nếu muốn một cái **mới**,
ngay trước mặt khán giả:

```bash
curl -s -X POST http://127.0.0.1:9998/test/inject-flag | python3 -m json.tool
```

**Nói với khán giả:**

> *"Đây là một flag vừa 'rời' service — alert này đi qua đúng hàng đợi Redis thật mà một traffic
> thật cũng sẽ đi qua, không phải dữ liệu giả hiển thị trong UI."*

---

### Bước 2 — Dashboard phản ứng ⏱ ~2 phút

Chỉ cho khán giả thấy trên tab EVENTS:
- Event mới nằm đầu danh sách, mức **CRITICAL**.
- Toast "🚨 DATA LEFT A SERVICE" **dính màn hình** (không tự biến mất như toast thường) — phải bấm
  mới tắt. Giải thích: `flag-out`/`honeytoken-out` được cố ý làm "khó bỏ lỡ" hơn các loại event
  khác — không tạo rule tự động, chỉ đảm bảo không ai lướt qua mà không thấy.
- Mỗi dòng event có 4 nút: **Detail** (raw JSON) · **Make rule** · **Alert** (tự sinh + áp ngay 1
  rule Suricata, luôn an toàn) · **Block** (tự sinh + upload ctf_proxy, có xác nhận).

**Nói với khán giả:**

> *"Không có bước nào ở đây tự động chặn. Tất cả 4 nút đều cần người bấm — kể cả nút 'Alert', nó
> chỉ tạo một rule CẢNH BÁO, không chặn gì cả."*

---

### Bước 3 — Sinh rule & test trước khi chặn ⏱ ~3 phút

Bấm **Make rule** trên event vừa tạo → chuyển sang tab RULES, flow được nạp sẵn (nếu dùng
inject-flag test thì sẽ không có flow Tulip thật — nói rõ với khán giả, dùng Quick pick tay thay
thế, hoặc chuẩn bị trước một flow thật từ 0-C's traffic thật nếu có).

1. Chọn phần "độc hại" (Quick pick hoặc bôi đen) → Use selection.
2. **SURICATA (panel 3a):** Generate → Test on recent traffic → xem số lần khớp, IP nào khớp →
   Add to ruleset → Test syntax & Apply. Chỉ cho khán giả thấy bảng có cấu trúc (#, SID, Message,
   Added) hiện ngay dòng mới với nhãn "not applied yet" trước khi Apply, rồi đổi thành timestamp
   thật sau khi Apply.
3. **CTF_PROXY (panel 3b, chỉ nếu có vulnbox thật + ctf_proxy đã deploy):** nếu vulnbox có nhiều
   service, chọn đúng service ở dropdown trước. Generate & insert → Check & Upload.

**Nói với khán giả:**

> *"Suricata không bao giờ chặn — nó đọc lại pcap sau khi traffic đã xảy ra, cấu trúc này không
> có khả năng drop packet thật. Chặn thật chỉ có ở ctf_proxy (trên vulnbox) hoặc iptables. Luôn
> Test on recent traffic trước — nếu rule khớp cả traffic của checker, rule quá rộng."*

---

### Bước 4 — Rule đang chạy ở đâu (APPLIED) ⏱ ~2 phút

Chuyển sang tab APPLIED — rule vừa Apply/Upload đã xuất hiện ngay (tab này tự tải lại mỗi lần mở,
không cần F5). Chỉ cho khán giả: số lần rule đã kêu/chặn, IP nguồn, và — nếu demo trên vulnbox có
nhiều service — cột "Service" phân biệt rule nào thuộc service nào.

**Nói với khán giả:**

> *"Đây là nơi duy nhất trả lời câu hỏi: rule nào đang sống, ở đâu, chặn/kêu bao nhiêu lần. Nếu
> một rule ctf_proxy chặn trúng IP của checker, nó sẽ hiện ngay ở đây — và việc cần làm là Pause
> filtering, không phải đoán."*

---

### Bước 5 — Kill switch & SLA ⏱ ~2 phút

Tab SERVICES:

```bash
# (tùy chọn, nếu muốn demo qua terminal thay vì click UI)
curl -s -X POST http://localhost:8080/api/services/ctfproxy/pause_filter | python3 -m json.tool
curl -s http://localhost:8080/api/services | python3 -m json.tool
curl -s -X POST http://localhost:8080/api/services/ctfproxy/resume_filter | python3 -m json.tool
```

**Nói với khán giả:**

> *"Pause filtering tắt TẤT CẢ rule chặn của ctf_proxy ngay lập tức, trên mọi service cùng lúc —
> không để sót 1 service vẫn đang chặn khi tưởng đã dừng hết. Traffic vẫn qua, không service nào
> bị rớt. Đây là nút bấm đầu tiên khi nghi ngờ một rule đang làm hại SLA, trước khi debug."*

Nếu có watchdog SLA đang chạy: chỉ MONITOR tab, cột watchdog — service vẫn ✓ UP suốt quá trình.

---

## Phần 3 — FALLBACK PLANS

> Khi một bước hỏng live: không tắt mic, không xin lỗi quá lâu, chuyển fallback ngay.

### FB-1: Không có event mới xuất hiện (Bước 1 hỏng)

```bash
# Gọi lại test endpoint — idempotent, gọi bao nhiêu lần cũng được
curl -s -X POST http://127.0.0.1:9998/test/inject-flag
```

Nếu endpoint đó cũng không trả lời: `docker logs ctf-detection --tail 30` xem lỗi, chuyển sang
trình bày trực tiếp tab APPLIED/RULES với rule có sẵn từ trước (không cần event mới để demo các
tab đó).

### FB-2: ctf_proxy không có / vulnbox không reachable (Bước 3/5 phần ctf_proxy hỏng)

> *"Phần này cần một vulnbox thật đang chạy — hôm nay môi trường demo không có sẵn một cái, nên
> tôi sẽ chỉ phần Suricata (luôn chạy local, không cần vulnbox) và SLA watchdog thay thế."*

Bỏ qua panel 3b, chỉ demo panel 3a (Suricata) — không cần SSH/vulnbox gì cả.

### FB-3: Dashboard không mở

```bash
bash health-check.sh
MODE=contest bash deploy-all.sh    # (hoặc MODE=prep, giữ đúng mode đã dùng ở Pre-flight)
```

Nếu vẫn không lên kịp giờ demo: trình bày qua `curl` trực tiếp các endpoint (`/api/applied`,
`/api/rules/suricata`, `/api/events...`) + giải thích JSON trả về, không cần UI.

---

## Phần 4 — KHÔNG ĐƯA VÀO DEMO

| Mục | Lý do |
|---|---|
| **mock-vulnbox qua ctf_proxy** | Không có nhánh local/compose nào nối ctf_proxy vào mock-vulnbox trong layout hiện tại — chỉ demo được ctf_proxy thật khi có vulnbox thật reachable qua SSH. |
| **Bất cứ thứ gì liên quan LLM/AI** | Đã gỡ bỏ hoàn toàn khỏi repo. Không có "Ask LLM", không có IOC JSON tự sinh. |
| **ml-fingerprint (DBSCAN)** | Chỉ chạy `MODE=prep` và cần `services.json.ml_classifier.enabled=true` — kết quả cụm cần đủ traffic mới có nghĩa, không đáng tin cho 1 request demo. |

---

## Phần 5 — TEARDOWN & RESET cho nhóm khán giả tiếp theo

```bash
cd /home/poeency/Documents/Setup_tool
MODE=contest bash teardown.sh     # dùng đúng MODE đã bringup ở Pre-flight 0-A
bash deploy-all.sh                 # cùng MODE, bringup lại
# Chạy lại Pre-flight 0-B/0-C
```

**Thời gian reset:** ~3-5 phút (teardown + bringup, không còn warm-up LLM 2 phút như bản cũ).

---

## Checklist nhanh — Invite khán giả khi tất cả ô này tick xanh

```
[ ] deploy-all.sh hoàn thành — không có dòng ERROR/FATAL
[ ] dashboard HTTP 200, Tulip UI HTTP 200, redis PONG
[ ] /test/inject-flag trả {"status":"injected"} và event xuất hiện trong EVENTS tab
[ ] Terminal theo dõi: docker logs -f ctf-detection (đã chạy từ trước)
[ ] (nếu demo ctf_proxy thật) vulnbox SSH reachable, ctf_proxy container đang Up
[ ] Đã quyết định trước: demo bằng inject-flag test, hay chờ traffic thật — không quyết định giữa buổi
```

---

*DEMO.md — cập nhật 2026-10-14. Không còn LLM/mock-vulnbox-qua-ctf_proxy; dựa trên các API đã
verify thật trong `docs/STATUS.md` cùng ngày.*
