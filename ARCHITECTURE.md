# ARCHITECTURE.md — Kiến trúc hệ thống CTF Monitor

> Tài liệu này giải thích **hệ thống hoạt động như thế nào** — dành cho người chưa biết gì về codebase.
> Đọc từ trên xuống, theo đúng luồng dữ liệu.

---

## Bức tranh toàn cảnh — hệ thống làm gì?

Trong một cuộc thi **Attack-Defense CTF**, mỗi đội có một "vulnbox" — máy chủ chạy các service **cố tình có lỗ hổng**. Đội khác sẽ tấn công vào vulnbox của bạn để lấy "flag" (token điểm). Nhiệm vụ của bạn:

1. **Chặn** đòn tấn công của đội khác (Defense)
2. **Biết ngay** khi flag của mình bị lấy (Detection)
3. **Hiểu** kẻ tấn công dùng kỹ thuật gì (Analysis)
4. **Tự động cập nhật** rule phòng thủ (Automation)

Hệ thống này làm tất cả 4 việc đó, **tự động**, trong thời gian thực.

---

## Sơ đồ kiến trúc tổng thể

```
                        ┌─────────────────────────────────────────┐
                        │           INTERNET / CTF NETWORK         │
                        │         (teams CIDR: 10.60.0.0/16)      │
                        └──────────────────┬──────────────────────┘
                                           │ HTTP/TCP requests
                                           ▼
┌──────────────────────────────────────────────────────────────────────────┐
│                          MONITOR HOST (10.0.0.50)                        │
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐     │
│  │                   ctf-net (Docker bridge 10.0.0.0/24)           │     │
│  │                                                                  │     │
│  │  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐   │     │
│  │  │  ctf_proxy   │───▶│ mock-vulnbox │    │    detection     │   │     │
│  │  │ (nginx edge) │    │  svc1 :9001  │    │  (flag scanner)  │   │     │
│  │  │ IP:10.0.0.2  │    │  svc2 :9002  │    └───────┬──────────┘   │     │
│  │  └──────┬───────┘    └──────────────┘            │              │     │
│  │         │ BLOCK/PASS                              │ alerts       │     │
│  │         │                              ┌──────────▼──────────┐   │     │
│  │  ┌──────▼──────────────────────────┐  │       Redis          │   │     │
│  │  │   harness.py (SLA validator)    │  │   (alert queue)     │   │     │
│  │  └─────────────────────────────────┘  └──────────┬──────────┘   │     │
│  │                                                   │              │     │
│  │  ┌────────────┐   ┌────────────┐   ┌─────────────▼──────────┐   │     │
│  │  │ mcp-tulip  │◀──│  ioc-brain │◀──│      dashboard         │   │     │
│  │  │ (MCP/RO)   │   │ (LLM API)  │   │   (unified UI/API)    │   │     │
│  │  └─────┬──────┘   └────────────┘   └────────────────────────┘   │     │
│  │        │                                                          │     │
│  └────────┼──────────────────────────────────────────────────────────     │
│           │                                                          │     │
│  ┌────────▼──────────────────────────┐   ┌───────────────────────┐ │     │
│  │     Tulip (Postgres/TimescaleDB)  │   │  Ollama (LLM host)    │ │     │
│  │       flow forensics DB           │   │ foundation-sec-8b-chat │ │     │
│  │       port :5433 (host)           │   │       port :11434     │ │     │
│  └───────────────────────────────────┘   └───────────────────────┘ │     │
│                                                                      │     │
└──────────────────────────────────────────────────────────────────────────┘
```

---

## Các thành phần — giải thích từng cái

### 🛡️ 1. ctf_proxy — "Người gác cổng"

**Là gì:** Một nginx reverse proxy ngồi trước vulnbox. Mọi traffic từ đội khác đều đi qua đây **trước** khi chạm service thật.

**Làm gì:**
- Nhận request từ attacker tại IP `10.0.0.2` (địa chỉ mà đội khác biết)
- Chạy từng request qua **filter module** Python (ví dụ `svc1_in.py`)
- Nếu filter phát hiện tấn công → trả về `CTFMONITOR_BLOCKED svc1 sqli_login` (HTTP 403)
- Nếu request sạch → forward vào mock-vulnbox bên trong

**Tại sao cần nó:** Không sửa vulnbox gốc (tránh mất điểm SLA), chỉ chặn ở lớp proxy.

```
Attacker ──▶ ctf_proxy (10.0.0.2:8080)
                │
                ├── filter khớp → 403 CTFMONITOR_BLOCKED
                │
                └── filter OK   → mock-vulnbox:9001 → 200 OK
```

---

### 🎯 2. mock-vulnbox — "Mục tiêu giả lập"

**Là gì:** Một FastAPI app giả lập vulnbox thật, dùng cho demo/test trên một máy duy nhất.

**Gồm 2 service:**
- `svc1` (HTTP :9001) — có lỗ hổng SQLi cố ý ở endpoint `/login`
- `svc2` (TCP :9002) — raw TCP echo

**Tại sao cần nó:** Trong competition thật, vulnbox là máy riêng. Khi demo/test một mình, mock-vulnbox thay thế hoàn toàn — ctf_proxy không biết sự khác biệt.

---

### 🔍 3. detection — "Cảm biến cờ"

**Là gì:** Service Python chạy liên tục, quét traffic và sinh alert.

**Phát hiện 3 loại sự kiện:**

| Loại | Cách phát hiện | Ý nghĩa |
|---|---|---|
| `flag-out` | Regex `[A-Z0-9]{31}=` trong pcap outbound | Flag của mình đang bị lấy đi |
| `honeytoken` | Endpoint `/honeytoken` bị hit | Kẻ tấn công đã vào được vulnbox (honeytoken là bẫy) |
| `suricata` | Đọc `eve.json` từ Suricata IDS | Rule-based network signature match |

**Khi phát hiện:** Đẩy alert vào **Redis queue** (< 1 giây).

---

### 🗄️ 4. Redis — "Bưu điện nội bộ"

**Là gì:** In-memory message queue. Không lưu dữ liệu lâu dài — chỉ chuyển alert giữa các service.

**Ai ghi vào:** `detection`, `ml-fingerprint`, `watchdog`

**Ai đọc ra:** `dashboard` (để hiện UI), `ioc-brain` (để kích phân tích)

---

### 📊 5. Tulip — "Sổ ghi lưu lượng"

**Là gì:** Tool forensics mã nguồn mở (OpenAttackDefenseTools/tulip). Lưu **toàn bộ flow TCP** vào Postgres/TimescaleDB.

**Làm gì:**
- Assembler đọc file `.pcap` từ thư mục `traffic/`
- Parse thành flows (ip_src, ip_dst, payload, timestamp)
- Tag tự động: `tcp`, `http`, `flag-out` (nếu có flag trong payload)
- Lưu cả **flag thật** vào cột `flags`

**Tại sao quan trọng:** Đây là nguồn dữ liệu thật để LLM phân tích. Không phải log text — là flow đầy đủ.

---

### 🔌 6. mcp-tulip — "Thủ thư an toàn"

**Là gì:** MCP (Model Context Protocol) server — lớp trung gian giữa `ioc-brain` và Postgres.

**Làm gì:**
- Expose hai hàm: `get_flow(flow_id)` và `search_flows(query)`
- Kết nối Postgres bằng role **chỉ đọc** (`tulip_ro` — `GRANT SELECT` only)
- Nếu ai cố `DELETE`/`UPDATE` → Postgres tự từ chối (không phải app convention, là DB enforcement)

**Tại sao cần lớp MCP thay vì kết nối thẳng:** Tách biệt quyền hạn. LLM không thể vô tình (hay cố ý) xóa dữ liệu forensics.

```
ioc-brain ──▶ mcp-tulip (port 8765) ──▶ Postgres (tulip_ro) ──▶ flow table
                                              ✗ DELETE rejected
```

---

### 🧠 7. ioc-brain — "Thám tử AI"

**Là gì:** FastAPI service gọi LLM để phân tích flow và ra IOC (Indicators of Compromise).

**Luồng hoạt động:**

```
POST /analyze {"flow_id": "abc123"}
        │
        ▼
1. Gọi mcp-tulip → lấy flow đầy đủ từ Postgres
        │
        ▼
2. Build prompt → gửi sang Ollama (foundation-sec-8b-chat)
        │
        ▼
3. LLM trả về JSON có cấu trúc
        │
        ▼
Response: {
  "attacker_ip": "10.60.9.9",
  "flag": "QCYM5CGWGP8KI34N0WRXULDJ7GZTDB=",
  "technique": "HTTP flag exfiltration",
  "confidence": "HIGH"
}
```

**Model:** `foundation-sec-8b-chat` — Foundation-Sec-8B (Llama-3.1 base, fine-tune bảo mật) với chat template Llama-3 được thêm thủ công vì GGUF gốc không có template.

**Lưu ý latency:** CPU-only → ~100–120s/call. GPU → vài giây.

---

### 🖥️ 8. dashboard — "Bảng điều khiển"

**Là gì:** Web app tổng hợp mọi alert từ Redis và hiển thị.

**Dữ liệu hiển thị:**
- Alert `flag-out`, `honeytoken`, `suricata` theo thứ tự ưu tiên
- SLA status từ watchdog
- Link sang Tulip để xem chi tiết flow

---

### ⏱️ 9. watchdog — "Nhân viên kiểm tra SLA"

**Là gì:** Service poll TCP/HTTP đến các port của vulnbox mỗi vài giây.

**Logic:**
- Kết nối được → `SERVICE UP` → đẩy `sla-ok` vào Redis
- Timeout → `SERVICE DOWN` → đẩy `sla-down` vào Redis → dashboard báo đỏ

**Tại sao quan trọng:** Trong A/D CTF, nếu service của bạn down → đội khác không lấy được flag từ bạn → bạn mất điểm defense **dù không bị tấn công**.

---

### 🤖 10. Ollama — "Hạ tầng LLM"

**Là gì:** Chạy **trên host** (không phải container) — local LLM inference engine.

**Lý do chạy trên host không phải container:** GPU access. Container không truy cập GPU trực tiếp dễ dàng; Ollama trên host đã có CUDA/ROCm sẵn.

**Model đang dùng:** `foundation-sec-8b-chat` — wrapper tự tạo từ `Foundation-Sec-8B-GGUF` + Llama-3 chat template.

---

## Luồng dữ liệu — một vụ tấn công từ đầu đến cuối

```
① Attacker gửi SQLi → ctf_proxy
         │
         ├── [BLOCKED] → 403 response → log vào ctf_proxy
         │
         └── [PASS through] (nếu qua được)
                   │
② Vulnbox gửi flag trong response → pcap capture
                   │
③ Tulip assembler đọc pcap → lưu flow vào Postgres
   Detection đọc pcap → tìm regex flag → alert "flag-out"
                   │
④ Detection đẩy alert vào Redis
                   │
⑤ Dashboard đọc Redis → hiển thị alert (< 1s)
   ioc-brain (optionally) nhận trigger → gọi mcp-tulip
                   │
⑥ mcp-tulip lấy flow từ Postgres (read-only)
                   │
⑦ ioc-brain gửi flow cho Ollama LLM → nhận IOC JSON
                   │
⑧ IOC JSON: attacker_ip + flag + technique → lưu/hiển thị
```

---

## Cấu hình tập trung — `services.json`

Tất cả component đọc từ **một file duy nhất**: `services.json`.
Không hardcode IP, port, hay keyword ở bất cứ đâu khác.

```json
{
  "vulnbox":     { "ip": "10.0.0.2", ... },
  "ctf_proxy":   { "keyword": "CTFMONITOR_BLOCKED", ... },
  "flag":        { "regex": "[A-Z0-9]{31}=", ... },
  "mcp":         { "postgres_role": "tulip_ro", ... },
  "ollama":      { "llm_model": "foundation-sec-8b-chat", ... }
}
```

`bringup.sh` đọc `services.json` → sinh config cho ctf_proxy → khởi động tất cả theo đúng thứ tự.
`validate-config.sh` kiểm tra consistency (ví dụ: keyword trong `services.json` phải khớp với file config được gen ra).

---

## Vấn đề đặc thù: Podman thay Docker

Máy này dùng **podman** (giả Docker). Điều này gây ra một vấn đề mạng:

- Docker thật: container dùng `host.docker.internal` để gọi về host → luôn hoạt động
- Podman: `host.docker.internal` resolve sai → ioc-brain không gọi được Ollama

**Giải pháp đã triển khai trong `bringup.sh`:**
```bash
# Thử kết nối thật đến từng candidate gateway
nc -z 172.17.0.1 11434 → hoạt động → dùng 172.17.0.1
nc -z 10.88.0.1  11434 → thử tiếp nếu cái trên fail
```

Container nhận `DOCKER_HOST_GATEWAY=172.17.0.1` qua env var và gọi Ollama qua IP thật thay vì hostname.

---

## Những gì CHƯA hoạt động (không demo)

| Thành phần | Trạng thái |
|---|---|
| Dashboard UI (browser visual) | API OK, visual chưa kiểm tra |
| OS Watchdog agent | Code có, chưa deploy lần nào |
| ML Fingerprint (DBSCAN) | Container chạy, đang warmup, chưa có kết quả |
| RAG / vault / AnythingLLM | `vault/` trống, chưa index document nào |

---

## Tóm tắt một dòng cho từng component

| Component | Một câu mô tả |
|---|---|
| **ctf_proxy** | Chặn đòn tấn công trước khi vào service |
| **mock-vulnbox** | Service thật giả lập cho demo/test |
| **detection** | Phát hiện flag bị lấy trong < 1 giây |
| **Redis** | Chuyển alert giữa các service |
| **Tulip** | Lưu toàn bộ flow TCP để forensics |
| **mcp-tulip** | Cho LLM đọc Tulip — read-only, an toàn |
| **ioc-brain** | Gọi LLM phân tích flow → ra IOC JSON |
| **dashboard** | Tổng hợp alert hiển thị một chỗ |
| **watchdog** | Kiểm tra service còn sống (SLA) |
| **Ollama** | Chạy LLM local trên host |

---

*ARCHITECTURE.md — 2026-10-08. Dựa trên STATUS.md (PASS items) và docker-compose.yml thực tế.*
