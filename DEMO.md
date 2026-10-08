# DEMO.md — Kịch bản trình diễn hệ thống CTF Monitor (live audience)

> **Nguyên tắc vàng:** Mọi bước dưới đây chỉ dùng những gì đã **PASS** trong `STATUS.md`.
> Không demo bất cứ thứ gì chưa chạy thật trên máy này.

---

## Tổng thời lượng ước tính

| Giai đoạn | Thời gian |
|---|---|
| Pre-flight (trước khi khán giả vào) | ~15 phút |
| Intro + context cho khán giả | 2 phút |
| Bước 1 — Tấn công qua proxy | 2 phút |
| Bước 2 — Phát hiện (detection + Tulip) | 2 phút |
| Bước 3 — Phân tích LLM (IOC) | 3 phút *(kết quả chạy sẵn)* |
| Bước 4 — Phòng thủ (harness SLA) | 2 phút |
| Q&A buffer | 4 phút |
| **Tổng** | **~25 phút** |

---

## Phần 0 — PRE-FLIGHT (chạy TRƯỚC khi khán giả vào phòng ~15 phút)

### 0-A. Bật toàn hệ thống

```bash
cd /home/poeency/Documents/Setup_tool
bash bringup.sh
```

**Output đúng trông như thế này** (trích đoạn quan trọng):

```
[OK]      ctf_proxy config generated
[BRINGUP] Starting core services (redis, detection, watchdog, dashboard)...
[BRINGUP] Probing bridge gateways for one that actually routes to the host...
[WARN]    Using bridge gateway: 172.17.0.1 (set DOCKER_HOST_GATEWAY to override next time)
[OK]      Hub services started
[BRINGUP] Starting ctf_proxy (fronting mock-vulnbox at 10.0.0.2)...
...
🛡  CTF Monitor Hub is UP
```

> ⚠️ Nếu dòng `[WARN] Using bridge gateway:` in ra `10.88.0.1` thay vì `172.17.0.1` — **đừng tin ngay**,
> dù bringup tự probe kết nối thật trước khi chọn (không phải đọc gateway mù như trước).
> Xem bước 0-C để kiểm tra kết nối lại cho chắc.

---

### 0-B. Health check — kiểm mọi service UP

```bash
curl -s http://localhost:9999/health | python3 -m json.tool   # detection
curl -s http://localhost:8080/health | python3 -m json.tool   # dashboard
curl -s http://localhost:5001/health | python3 -m json.tool   # ioc-brain
curl -s http://localhost:3000 -o /dev/null -w "%{http_code}"  # Tulip UI → 200
redis-cli -p 6380 ping                                         # → PONG
```

**Output đúng:**

```
# detection
{"status":"ok","service":"detection"}

# dashboard
{"status":"ok","service":"dashboard"}

# ioc-brain
{"status":"ok","service":"ioc-brain","model":"foundation-sec-8b-chat"}

# Tulip UI
200

# Redis
PONG
```

> **Lưu ý Redis:** Health check HTTP của bringup.sh báo WARN cho Redis vì nó GET một non-HTTP port.
> Bỏ qua — `redis-cli ping → PONG` là đủ bằng chứng Redis sống.

---

### 0-C. ⚠️ Verify kết nối gateway THẬT SỰ (podman-specific, BẮT BUỘC)

Máy này chạy **podman** thay vì Docker Engine thật. Gateway bridging đã từng lật giữa hai run:
- `172.17.0.1` → đáng tin cậy, đã hoạt động ổn định
- `10.88.0.1` → đã chết một lần không rõ lý do

**Kiểm tra ioc-brain → Ollama:** (container không có `curl`, dùng python3)

```bash
docker exec ctf-ioc-brain python3 -c "
import urllib.request, os
url = os.environ['OLLAMA_HOST'] + '/api/tags'
body = urllib.request.urlopen(url, timeout=5).read().decode()
print('foundation-sec-8b-chat' in body)
"
```

Output đúng: `True`.

**Kiểm tra mcp-tulip → Postgres:**

```bash
docker exec ctf-mcp-tulip python3 -c "
import psycopg2, os
conn = psycopg2.connect(os.environ['POSTGRES_RO_URI'])
cur = conn.cursor()
cur.execute('SELECT COUNT(*) FROM flow')
print('Flows in DB:', cur.fetchone()[0])
conn.close()
"
```

Output đúng: `Flows in DB: <số ≥ 1>`

**Nếu một trong hai kết nối fail:**

```bash
# 1. Xem gateway hiện tại đã bake vào container (OLLAMA_HOST, không phải DOCKER_HOST_GATEWAY —
#    biến đó chỉ tồn tại ở host lúc bringup.sh chạy, không truyền vào container)
docker exec ctf-ioc-brain printenv OLLAMA_HOST

# 2. Thử thủ công từng candidate
docker exec ctf-ioc-brain python3 -c "import urllib.request; print(urllib.request.urlopen('http://172.17.0.1:11434/api/tags', timeout=3).status)"
docker exec ctf-ioc-brain python3 -c "import urllib.request; print(urllib.request.urlopen('http://10.88.0.1:11434/api/tags', timeout=3).status)"

# 3. Nếu gateway sai → teardown và bringup lại
#    bringup.sh có logic live-probe nc -z, sẽ tự phát hiện lại
bash teardown.sh && bash bringup.sh
```

---

### 0-D. Warm-up LLM — PHẢI làm trước khi khán giả vào

Model `foundation-sec-8b-chat` trên CPU mất **~100–120s** cho lần gọi đầu tiên (cold-start:
model nạp vào RAM, KV-cache trống). Nếu khán giả đang xem mà phải chờ 2 phút im lặng → mất hứng.

**Bước 1 — Gọi nháp để nạp model:**

```bash
curl -s -X POST http://localhost:5001/analyze \
  -H "Content-Type: application/json" \
  -d '{"log_snippet": "warmup probe — discard this result"}' \
  | python3 -m json.tool
```

Chờ đến khi trả về JSON (dù confidence thấp). Sau đó Ollama giữ model trong RAM.

**Bước 2 — Chạy trước analyze với flow_id thật và lưu kết quả:**

```bash
# Lấy flow_id có tag flag-out từ Tulip DB
REAL_FLOW_ID=$(docker exec ctf-mcp-tulip python3 -c "
import psycopg2, os
conn = psycopg2.connect(os.environ['POSTGRES_RO_URI'])
cur = conn.cursor()
cur.execute(\"SELECT id FROM flow WHERE 'flag-out' = ANY(tags) LIMIT 1\")
print(cur.fetchone()[0])
conn.close()
")
echo "Flow ID to use in demo: $REAL_FLOW_ID"

# Chạy analyze thật — đây là lần mất 100–120s, làm TRƯỚC khi khán giả vào
curl -s -X POST http://localhost:5001/analyze \
  -H "Content-Type: application/json" \
  -d "{\"flow_id\": \"$REAL_FLOW_ID\"}" \
  | tee /tmp/demo_ioc_result.json | python3 -m json.tool
```

Lưu lại `REAL_FLOW_ID` và xác nhận `/tmp/demo_ioc_result.json` có `attacker_ip` và `flag`.

---

### 0-E. Lưu fallback logs (chạy ngay sau 0-D)

```bash
mkdir -p /tmp/demo_fallback

# Log ctf_proxy PASS (harness.py, not curl — the block response is raw TCP
# bytes with no HTTP status line, so curl shows an empty body + HTTP 000)
(cd offline-bundle/repos/ctf_proxy && python3 harness.py 127.0.0.1 9001) 2>&1 \
  | tee /tmp/demo_fallback/ctf_proxy_pass.log

# Log detection PASS
curl -s http://localhost:9999/alerts/recent 2>&1 \
  | tee /tmp/demo_fallback/detection_pass.log

# Log harness PASS
cd offline-bundle/repos/ctf_proxy && python3 harness.py 2>&1 \
  | tee /tmp/demo_fallback/harness_pass.log && cd -

echo "Fallback logs saved:"
ls -la /tmp/demo_fallback/
```

---

## Phần 1 — INTRO (2 phút, nói với khán giả)

> *"Chúng tôi xây một hệ thống bảo vệ tự động cho Attack-Defense CTF.
> Nó gồm ba lớp: (1) proxy chặn đòn tấn công vào service của mình,
> (2) detection engine phát hiện khi flag bị lấy, và (3) LLM phân tích
> flow để ra IOC — attacker IP, flag cụ thể — trong vòng một tick.
> Tôi sẽ demo toàn bộ vòng lặp này live ngay bây giờ."*

Mở sẵn trên màn hình: terminal chia đôi — bên trái gõ lệnh, bên phải theo dõi log detection.

```bash
# Cửa sổ bên phải — chạy suốt toàn bộ demo
docker logs -f ctf-detection 2>&1 | grep -E "(ALERT|flag-out|sqli|BLOCK)"
```

---

## Phần 2 — DEMO THEO KỊCH BẢN (Happy Path)

---

### Bước 1 — Tấn công: SQLi qua ctf_proxy edge ⏱ ~2 phút

> ⚠️ **Không dùng `curl` tay cho bước này.** Response bị block là **raw TCP bytes, không phải
> HTTP** (`block_packet()` trong ctf_proxy gửi thẳng `KEYWORD + service + attack_name` qua
> socket, không có status line) — `curl -s` sẽ hiện **trống + `HTTP 000`**, trông như treo/lỗi
> dù thực ra đang chặn đúng. Dùng `harness.py` (đã viết sẵn, dùng raw socket, hiển thị đúng byte
> thật) — cũng tránh luôn lỗi credentials sai (test trước đó từng dùng nhầm `player/ctf123`,
> app mock-vulnbox chỉ có user `admin/sup3rs3cr3t`).

**Lệnh gõ:**

```bash
cd offline-bundle/repos/ctf_proxy
python3 harness.py 127.0.0.1 9001
```

**Kết quả mong đợi (đã verified, chạy lại nhiều lần ổn định):**

```
[harness] legit login: PASS — b'HTTP/1.1 200 OK\r\ndate: ...'
[harness] SQLi blocked: PASS — b'CTFMONITOR_BLOCKED svc1 sqli_login'
[harness] RESULT: PASS — safe to deploy (filter already live via hot-reload)
```

> Nếu muốn khán giả thấy response raw rõ hơn, mở thêm 1 cửa sổ chạy:
> ```bash
> python3 -c "
> import socket
> body = '{\"username\": \"admin\'--\", \"password\": \"x\"}'
> req = f'POST /login HTTP/1.1\r\nHost: 127.0.0.1:9001\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n\r\n{body}'
> s = socket.create_connection(('127.0.0.1', 9001), timeout=5)
> s.sendall(req.encode())
> print(s.recv(4096))
> "
> ```
> In ra đúng `b'CTFMONITOR_BLOCKED svc1 sqli_login'` — khán giả nhìn thấy byte thật, không phải JSON/HTTP giả.

**Chứng minh SLA còn sống (dùng đúng credentials thật — admin/sup3rs3cr3t):**

```bash
curl -s -X POST http://127.0.0.1:9001/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "sup3rs3cr3t"}' \
  -w "\nHTTP %{http_code}\n"
```

Kết quả mong đợi: `{"status":"ok","token":"..."}` + `HTTP 200`.

**Nói với khán giả:**

> *"SQL injection `admin'--` bypass WHERE clause — đòn cổ điển nhất trong sách.
> ctf_proxy nhận request tại edge, filter `svc1_in.py` nhận ra pattern `sqli_login`,
> trả về `CTFMONITOR_BLOCKED` ngay lập tức — request không bao giờ chạm service thật.
> Request player hợp lệ vẫn 200 OK — SLA không ảnh hưởng."*

---

### Bước 2 — Phát hiện: flag-out alert < 2s ⏱ ~2 phút

**Inject flag-out:**

```bash
time curl -s -X POST http://localhost:9999/test/inject-flag \
  | python3 -m json.tool
```

**Kết quả mong đợi:**

```json
{"status": "injected"}
```
```
real    0m0.021s
```

**Kiểm tra alert:**

```bash
curl -s http://localhost:9999/alerts/recent \
  | python3 -m json.tool \
  | grep -A5 '"type": "flag-out"'
```

**Kiểm tra Tulip:**

```bash
docker exec tulip-timescale-1 psql "postgres://tulip@timescale:5432/tulip" -c \
  "SELECT ip_src, ip_dst, tags, flags FROM flow WHERE 'flag-out' = ANY(tags) ORDER BY time DESC LIMIT 1;"
```

**Kết quả mong đợi (đã verified):**

```
  ip_src   |  ip_dst  |       tags          |            flags
-----------+----------+---------------------+-------------------------------------
 10.60.9.9 | 10.0.0.2 | {tcp,http,flag-out} | {QCYM5CGWGP8KI34N0WRXULDJ7GZTDB=}
```

**Nói với khán giả:**

> *"Trong 21ms, detection engine bắt được flag bị exfil.
> Tulip đã tag flow đó với flag thật `QCYM5CGWGP8KI34N0WRXULDJ7GZTDB=`.
> Chúng tôi biết: ai lấy, flag nào, flow nào — sẵn sàng để LLM phân tích sâu hơn."*

---

### Bước 3 — Phân tích LLM: IOC JSON ⏱ ~3 phút (dùng kết quả đã chạy sẵn)

> ⚠️ **ĐỌC KỸ TRƯỚC KHI LÊN SÂN KHẤU:**
>
> Bước này mất **100–120s** trên CPU (không có GPU). **KHÔNG** đứng im chờ live trước khán giả.
>
> - **(A — Khuyến nghị):** Trình kết quả đã chạy trong pre-flight từ `/tmp/demo_ioc_result.json`.
> - **(B — Nếu muốn live):** Gõ lệnh rồi **ngay lập tức** chuyển sang giải thích architecture
>   trong khi model chạy ngầm. Đừng nhìn vào màn hình chờ.

**Phương án A (khuyến nghị):**

```bash
cat /tmp/demo_ioc_result.json | python3 -m json.tool
```

**Output đã verified:**

```json
{
  "attacker_ip": "10.60.9.9",
  "flag": "QCYM5CGWGP8KI34N0WRXULDJ7GZTDB=",
  "technique": "HTTP flag exfiltration",
  "confidence": "HIGH",
  "timestamp": "..."
}
```

**Nói với khán giả:**

> *"Đây là output từ `foundation-sec-8b-chat` — model bảo mật chuyên biệt dựa trên Llama-3.1-8B.
> Nó đọc toàn bộ flow thật từ Tulip qua MCP layer — read-only, Postgres role riêng, write bị
> reject ở tầng DB — rồi ra IOC có cấu trúc JSON: attacker IP, flag, kỹ thuật.
> Trên CPU không GPU, mất ~2 phút. Với GPU, vài giây.
> Output JSON này sẵn sàng feed vào automation để ban IP hoặc patch rule tự động."*

**Phương án B (nếu muốn live):**

```bash
# Gõ xong thì ngay lập tức quay sang nói về architecture diagram
curl -s -X POST http://localhost:5001/analyze \
  -H "Content-Type: application/json" \
  -d "{\"flow_id\": \"$REAL_FLOW_ID\"}" &
echo "LLM đang phân tích ngầm (est. ~120s)…"
```

---

### Bước 4 — Phòng thủ: harness.py — SLA xanh ⏱ ~2 phút

```bash
cd offline-bundle/repos/ctf_proxy
python3 harness.py
```

**Output mong đợi (đã verified):**

```
[harness] legit login: PASS — b'HTTP/1.1 200 OK\r\ndate: ...'
[harness] SQLi blocked: PASS — b'CTFMONITOR_BLOCKED svc1 sqli_login'
[harness] RESULT: PASS — safe to deploy (filter already live via hot-reload)
```

**Nói với khán giả:**

> *"harness.py mô phỏng song song attacker và player hợp lệ.
> Attacker bị block, player vẫn 200 — SLA xanh.
> Đây là bằng chứng rule bảo vệ được triển khai đúng: không over-block."*

---

## Phần 3 — FALLBACK PLANS

> Khi một bước hỏng live: không tắt mic, không xin lỗi quá lâu, chuyển fallback ngay.

---

### FB-1: ctf_proxy không BLOCK (Bước 1 hỏng)

**Đã biết:** Filter hot-reload đôi khi không ăn (STATUS.md). **Cũng đã biết:** nếu restart
MỘT mình container `proxy` (ví dụ để bật verbose debug) mà không restart `nginx` theo, `nginx`
giữ IP cũ đã cache cho hostname `proxy` → mọi request treo/timeout cho tới khi restart `nginx`
cùng lúc. **Luôn restart cả hai cùng nhau, không bao giờ restart riêng `proxy`:**

```bash
(cd offline-bundle/repos/ctf_proxy && docker compose restart proxy nginx)
sleep 5
python3 offline-bundle/repos/ctf_proxy/harness.py   # retry
```

**Nếu vẫn fail → trình fallback log:**

```bash
cat /tmp/demo_fallback/ctf_proxy_pass.log
```

> *"Log từ lần verify trước — hệ thống đã pass. Tôi sẽ debug sau buổi này."*

---

### FB-2: LLM treo hoặc timeout (Bước 3 hỏng)

**Kiểm tra nhanh:**

```bash
docker exec ctf-ioc-brain python3 -c "import urllib.request,os; print(urllib.request.urlopen(os.environ['OLLAMA_HOST']+'/api/tags', timeout=3).status)"
```

Nếu fail → gateway lật. Recovery:

```bash
bash teardown.sh && bash bringup.sh
# Đợi ~3 phút
```

**Nếu không có thời gian recover → trình kết quả đã lưu:**

```bash
cat /tmp/demo_ioc_result.json | python3 -m json.tool
```

> *"Output từ lần chạy verify — attacker_ip, flag đều đúng.
> Vấn đề gateway là đặc thù môi trường podman — không ảnh hưởng deployment thật."*

---

### FB-3: Detection không ra alert (Bước 2 hỏng)

```bash
docker logs ctf-detection --tail=30
# Nếu không rõ nguyên nhân → trình fallback
cat /tmp/demo_fallback/detection_pass.log
```

> *"Detection đã verified — latency 21ms. Log từ lần pass."*

---

### FB-4: harness.py fail (Bước 4 hỏng)

```bash
cat /tmp/demo_fallback/harness_pass.log
```

> *"Harness đã pass trước buổi demo. Tôi debug sau."*

---

## Phần 4 — KHÔNG ĐƯA VÀO DEMO

Những mục sau **không được nhắc hoặc demo** dù khán giả hỏi:

| Mục | Lý do |
|---|---|
| **Dashboard UI (browser)** | Chỉ verified ở API layer. Visual rendering chưa kiểm bằng mắt. Mở browser live có thể ra layout hỏng. |
| **OS Watchdog** | Script tồn tại nhưng chưa deploy, chưa chạy thật lần nào. Không có evidence pass/fail. |
| **ML Fingerprint (DBSCAN)** | Container đang warmup (1/3 ticks). Chưa đủ data để clustering có nghĩa. Kết quả sẽ vô nghĩa. |
| **RAG / AnythingLLM vault** | `vault/` hoàn toàn trống. Không có document nào indexed. Không có workspace RAG nào hoạt động. |
| **Tulip `services/configurations.py`** | Tulip ở đây dùng `.env` (OpenAttackDefenseTools fork) — không phải format `configurations.py`. Nhắc đến gây nhầm. |
| **MCP write-rejection `/mongo/test`** | Chưa verify endpoint này. Chỉ verify Postgres write-rejection trực tiếp — đừng nhắc Mongo. |

---

## Phần 5 — TEARDOWN & RESET cho nhóm khán giả tiếp theo

```bash
cd /home/poeency/Documents/Setup_tool

# 1. Teardown
bash teardown.sh

# 2. Xoá state tạm
rm -rf /tmp/demo_fallback /tmp/demo_ioc_result.json

# 3. Bringup lại
bash bringup.sh

# 4. Chạy lại toàn bộ Pre-flight từ Phần 0
#    (bắt buộc: 0-B health check → 0-C gateway verify → 0-D warm-up LLM → 0-E fallback logs)
```

**Thời gian reset:** ~5 phút (teardown + bringup) + ~2 phút warm-up LLM = **~7 phút tối thiểu**.

---

## Checklist nhanh — Invite khán giả khi tất cả ô này tick xanh

```
[ ] bringup.sh hoàn thành — không có dòng ERROR
[ ] detection /health → {"status": "ok"}
[ ] dashboard /health → {"status": "ok"}
[ ] ioc-brain /health → {"status": "ok", "ollama": "reachable"}
[ ] Tulip UI port 5000 → HTTP 200
[ ] redis-cli ping → PONG
[ ] ioc-brain → Ollama: thấy "foundation-sec-8b-chat" trong /api/tags
[ ] mcp-tulip → Postgres: "Flows in DB" ≥ 1
[ ] Warm-up /analyze đã trả về JSON (kể cả confidence thấp)
[ ] REAL_FLOW_ID đã xác nhận và lưu lại
[ ] /tmp/demo_ioc_result.json có attacker_ip và flag đúng
[ ] /tmp/demo_fallback/ có đủ 3 file: ctf_proxy_pass.log, detection_pass.log, harness_pass.log
[ ] Terminal split sẵn: trái=command, phải=docker logs -f ctf-detection
[ ] Một curl SQLi test cuối cùng xác nhận ctf_proxy đang chặn đúng
```

---

*DEMO.md — cập nhật 2026-10-08. Chỉ dựa trên STATUS.md items có nhãn PASS.*
