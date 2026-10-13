# ARCHITECTURE.md — Kiến trúc hệ thống CTF Monitor Hub

> Tài liệu này giải thích **hệ thống hoạt động như thế nào** — dành cho người chưa biết gì về codebase.
> Đọc từ trên xuống, theo đúng luồng dữ liệu.
>
> **Không có LLM / generative-AI nào trong repo này** (đã bị gỡ bỏ hoàn toàn theo quyết định của
> người dùng — xem lịch sử trong `docs/STATUS.md`). Mọi phân tích là do con người đọc flow/log,
> không có bước "AI gợi ý" nào.

---

## Bức tranh toàn cảnh — hệ thống làm gì?

Trong một cuộc thi **Attack-Defense CTF**, mỗi đội có một "vulnbox" — máy chủ chạy các service **cố tình có lỗ hổng**. Đội khác sẽ tấn công vào vulnbox của bạn để lấy "flag" (token điểm). Nhiệm vụ của bạn:

1. **Biết ngay** khi flag của mình bị lấy, hoặc có traffic lạ (Detection)
2. **Hiểu** kẻ tấn công dùng kỹ thuật gì, bằng cách tự đọc flow (Analysis — con người, không AI)
3. **Chặn** đòn tấn công đó (Defense) — luôn là một hành động **con người bấm**, không có gì tự động chặn
4. **Theo dõi SLA** để service không bị rớt điểm vì chính rule phòng thủ của mình (Watchdog)

Hệ thống này gồm hai "zone" tách biệt theo `MODE`:

| | `MODE=contest` | `MODE=prep` |
|---|---|---|
| Khi nào dùng | Ngày thi thật, 8 tiếng thi | Luyện tập, demo, phát triển |
| Compose file | `docker-compose.contest.yml` | `docker-compose.contest.yml` **+** `docker-compose.prep.yml` |
| Vulnbox | Thật, do ban tổ chức cấp (qua `services.json`) | `mock-vulnbox` (toy app giả, chạy local) |
| Thành phần thêm | — | `mock-vulnbox`, và `ml-fingerprint` (chỉ nếu `ml_classifier.enabled=true` trong `services.json`) |

`bringup.sh`/`teardown.sh`/`deploy-all.sh` đều đọc biến môi trường `MODE` và **từ chối chạy** nếu
phát hiện container prep-only còn sống trong lúc `MODE=contest` (an toàn ngày thi: không bao giờ
vô tình mang theo fixture luyện tập vào trận thật).

---

## Sơ đồ kiến trúc (MODE=contest, tối giản)

```
                    ┌───────────────────────────────────────┐
                    │     MẠNG THI (teams_cidr, scoreboard)  │
                    └──────────────────┬──────────────────────┘
                                        │ traffic thật đến vulnbox
                                        ▼
┌───────────────────────────────────────────────────────────────────────┐
│                          VULNBOX (do BTC cấp)                          │
│                                                                        │
│   attacker/checker ──▶ ctf_proxy (nếu đã deploy)  ──▶  service thật   │
│                         │  filter_modules/<svc>/<svc>_in.py            │
│                         │  (mỗi service TCP trong services.json        │
│                         │   có 1 cặp filter riêng; UDP KHÔNG được      │
│                         │   ctf_proxy hỗ trợ — xem phần Defense dưới)  │
│                         ▼                                              │
│                   block → trả "<keyword> <service> <rule>"            │
│                   pass  → forward vào service thật                    │
└───────────────────────────────────────────┬───────────────────────────┘
                                             │ tcpdump trên vulnbox-host
                                             │ (capture TẤT CẢ port trong
                                             │  services[], mọi proto)
                                             ▼
┌───────────────────────────────────────────────────────────────────────┐
│                           MONITOR HOST                                 │
│                                                                        │
│  pcap kéo về traffic/  ──┬──▶ Suricata (đọc lại pcap, chỉ ALERT,       │
│                          │     không chặn — xem "Suricata" dưới)       │
│                          │                                             │
│                          └──▶ Tulip assembler (TimescaleDB/Postgres)   │
│                                     │ flows đầy đủ, tag flag-out/...   │
│                                     ▼                                  │
│                          detection_service.py (quét pcap: flag regex,  │
│                          honeytoken, proxy-blocked keyword)            │
│                                     │                                  │
│                                     ▼                                  │
│                              Redis "alerts" list/pubsub                │
│                                     │                                  │
│         ┌───────────────────────────┼───────────────────────┐          │
│         ▼                           ▼                       ▼          │
│    dashboard (FastAPI,         watchdog_service.py     host_agent.py  │
│    web UI, đọc Redis/Tulip)    (SLA poll vulnbox mỗi    (daemon trên   │
│         │                      vài giây → alert         host, KHÔNG   │
│         │  không có docker     sla-down/slow/restored)  trong         │
│         │  socket / SSH key    │                         container —  │
│         │  trong container →   │                         có SSH key + │
│         │  queue action qua ───┼─────────────────────────▶ docker     │
│         │  Redis "ops_requests"│                         socket để    │
│         │                      │                         làm việc    │
│         ▼                      ▼                         thật)       │
│   người dùng bấm nút trên dashboard: tạo rule, upload lên ctf_proxy,  │
│   pause/resume filtering, chặn IP/content qua iptables, v.v.          │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Các thành phần — giải thích từng cái

### 🛡️ 1. ctf_proxy — "Người gác cổng" trên vulnbox (chặn thật, TCP/HTTP, KHÔNG UDP)

**Là gì:** Dự án mã nguồn mở `ctf_proxy` (vendored trong `offline-bundle/repos/ctf_proxy`), chạy
ngay trên vulnbox-host (không phải trên monitor host). Mọi traffic vào một service **đã được
deploy ctf_proxy phía trước** đều đi qua đây trước khi chạm service thật.

**Deploy bằng `contest-runtime/defense/deploy-ctfproxy.sh`:**
- Đọc **toàn bộ** `services[]` có `proto: "tcp"` trong `services.json` (bỏ qua `"proto": "udp"` —
  ctf_proxy chỉ hỗ trợ TCP/HTTP, không có cách nào proxy UDP).
- Với mỗi service: gỡ port đang bind của service gốc, chuyển port đó cho ctf_proxy, sinh
  `proxy/config/config.json` một entry cho mỗi service (tên, `target_ip`/`target_port` = service
  gốc, `listen_port` = port public, `http: true/false` theo field `layer` trong `services.json`:
  `l7-http`/`l7-https` → `http: true`, `l4-raw` → `http: false`).
- ctf_proxy tự sinh `nginx.conf` từ `config.json` lúc container khởi động (có cơ chế failover: nếu
  container `proxy` chết, nginx tự chuyển traffic thẳng vào service gốc — không mất SLA).
- Mỗi service có một cặp filter riêng: `filter_modules/<tên-đã-sanitize>/<tên>_in.py` (và `_out.py`,
  ít dùng hơn). `class Module` trong đó — mỗi method là **một rule**; method nào trả `True` thì
  **chặn** (đóng kết nối, trả về `"<keyword> <service> <rule>"` để detection nhận diện).
- **Service HTTP** (`http: true`): filter nhận `HTTPStream`, đọc được `url/path/method/parameters/
  headers/raw_body` đã parse sẵn.
- **Service raw TCP** (`http: false`, ví dụ binary service / pwn-style): filter nhận `TCPStream`,
  chỉ có bytes thô (`stream.current_message`) — không có url/path/param để đọc, Dashboard's rule
  builder tự chuyển sang chế độ chỉ cho chọn `target: raw` khi bạn chọn service này.

**Quan trọng:** không có gì tự động upload/chặn — mọi rule phải qua tab RULES và người dùng bấm
"Check & Upload".

---

### 🔍 2. Suricata — "Cảm biến cảnh báo" (chỉ ALERT, không bao giờ chặn)

**Là gì:** Suricata chạy **trên monitor host**, đọc lại các file `.pcap` đã kéo về từ vulnbox
(`-r <traffic_dir> --pcap-file-continuous`) — tức là nó phân tích **offline, sau khi traffic đã
xảy ra**, không ngồi giữa đường truyền. Vì vậy **Suricata không thể chặn bất cứ thứ gì**, dù rule
viết `alert` hay `drop` — cấu hình pcap-replay không có khả năng drop packet thật.

**Dùng để:** quan sát an toàn trước khi quyết định chặn thật ở ctf_proxy, hoặc cảnh báo những thứ
không cần chặn (ví dụ scanner/recon).

**Rule sống ở:** `contest-runtime/detection/suricata/lib/rules/suricata.rules` — một dòng = một
rule. RULES tab (3a) hiện bảng có cấu trúc (#, SID, Message, Added, Edit/Delete) phía trên khung
raw-text để sửa tay khi cần.

---

### 🚧 3. Fallback firewall (iptables trên vulnbox) — khi không cài được ctf_proxy, hoặc cho UDP

Hai kiểu chặn độc lập với ctf_proxy, cả hai chạy qua `host_agent.py` (SSH vào vulnbox, `iptables`):
- **Chặn theo IP** (chain `CTFBLOCK`) — thô, chặn nguyên 1 địa chỉ. Rủi ro: attacker và checker có
  thể share IP (NAT) — chặn nhầm checker mất SLA.
- **Chặn theo nội dung** (chain `CTFBLOCK_CONTENT`, `iptables --string` match, hex-encode trước khi
  gửi qua SSH) — vẫn hoạt động khi attacker/checker share IP, vì khớp theo **payload**, không theo
  địa chỉ. Đây cũng là lựa chọn cho **UDP** (ctf_proxy không proxy được UDP; iptables content-match
  hoạt động ở tầng packet, không quan tâm TCP hay UDP).

---

### 🗄️ 4. Redis — "Bưu điện nội bộ" + hàng đợi lệnh

Hai vai trò khác nhau, cùng một Redis instance:
- **`alerts` list + `alerts_channel` pubsub:** mọi alert (`flag-out`, `honeytoken-out`, `suricata`,
  `proxy-blocked`, `sla-down`/`slow`/`restored`, ...) được `lpush` vào đây và publish để dashboard
  nhận qua WebSocket gần như ngay lập tức.
- **`ops_requests` list + `ops_result:<id>` keys:** cơ chế bridge giữa dashboard (chạy trong
  container, **không có** docker socket hay SSH key) và `host_agent.py` (daemon chạy **trực tiếp
  trên monitor host**, có SSH key + docker socket thật). Dashboard `rpush` một action có tên
  (`ctfproxy_apply`, `firewall_content_block`, `suricata_delete_rule`, ...) kèm payload; host_agent
  lấy ra, kiểm tra với whitelist (`hostagent/actions/__init__.py`), thực thi, rồi ghi kết quả vào
  `ops_result:<id>` cho dashboard đọc lại. Không có whitelist → action bị từ chối thẳng, không chạy.

---

### 📊 5. Tulip — "Sổ ghi lưu lượng"

Tool forensics mã nguồn mở (OpenAttackDefenseTools/tulip fork), lưu **toàn bộ flow TCP** vào
TimescaleDB/Postgres. Assembler đọc `.pcap` từ `traffic/`, parse thành flow (ip_src, ip_dst,
payload, timestamp), tự tag `flag-out`/`flag-planted`/`flag-echo`/`honeytoken-out` nếu khớp regex
flag thật. Dùng để **con người** mở flow lên đọc request/response thật khi quyết định viết rule
hoặc phân biệt checker vs kẻ trộm — không có bước AI đọc hộ.

---

### 🖥️ 6. dashboard — "Bảng điều khiển"

FastAPI app (container riêng), tổng hợp mọi alert từ Redis, hiển thị qua các tab: **MONITOR,
EVENTS, HUNT, RULES, APPLIED, SERVICES, CONFIG**. Mọi hành động có tác dụng thật (sửa rule, upload
ctf_proxy, bật/tắt service, chặn IP/content) đều đi qua `host_agent.py` qua Redis `ops_requests`
(xem mục 4) — container dashboard tự nó không có quyền chạm vào vulnbox hay docker trên host.

---

### ⏱️ 7. watchdog (SLA) — poll TCP/HTTP tới từng service

`contest-runtime/watchdog/watchdog_service.py`, chạy trên monitor host. Poll từng service trong
`services.json` mỗi vài giây (`POLL_INTERVAL_SEC`), đẩy `sla-down`/`sla-slow`/`sla-restored` vào
Redis khi trạng thái đổi. **Khác với OS-watchdog** (mục 8) — đây chỉ kiểm tra "service còn trả lời
không", không vào bên trong vulnbox.

---

### 🕵️ 8. OS-watchdog agent — chạy trên chính vulnbox

Script shell cài đặt trên vulnbox (`contest-runtime/watchdog/deploy-os-watchdog.sh`), theo dõi
tiến trình/cron/file lạ xuất hiện **trên chính máy vulnbox** — dấu hiệu RCE đã thành công (không
chỉ là traffic lạ, mà attacker đã thực thi được lệnh). Báo về qua cùng hàng đợi Redis `alerts`.

---

### 🤖 9. ml-fingerprint (chỉ `MODE=prep`, tùy chọn) — không phải generative AI

Bộ phân loại `sklearn` (DBSCAN clustering trên hành vi client: timing, path pattern...) để gợi ý
"client này có giống checker bot không". **Không bao giờ chạy khi `MODE=contest`** dù
`services.json.ml_classifier.enabled=true` — `bringup.sh` không bao giờ nạp
`docker-compose.prep.yml` trong contest mode, bất kể giá trị field đó. Chỉ bật khi ban tổ chức xác
nhận bằng văn bản (ghi chú ngay trong `services.json`).

---

## Luồng dữ liệu — một vụ tấn công từ đầu đến cuối

```
① Attacker gửi request tới service (có thể qua ctf_proxy nếu đã deploy)
         │
         ├── [ctf_proxy BLOCKED] → trả "<keyword> <service> <rule>" → log vào ctf_proxy
         │
         └── [PASS/chưa có ctf_proxy] → chạm service thật
                   │
② tcpdump trên vulnbox-host bắt mọi packet (mọi port trong services[])
                   │   → rsync kéo .pcap về monitor host mỗi ~15s
                   │
③ Suricata đọc lại pcap → match rule → alert (KHÔNG chặn, xem mục 2)
   Tulip assembler đọc pcap → lưu flow đầy đủ vào Postgres, tự tag flag-out/...
   detection_service.py quét pcap → regex flag / honeytoken / proxy-blocked keyword → alert
                   │
④ Mọi alert lpush vào Redis "alerts" + publish "alerts_channel"
                   │
⑤ Dashboard nhận qua WebSocket gần real-time → hiện ở EVENTS/MONITOR
   flag-out/honeytoken-out được nhấn mạnh hơn (toast dính màn hình, beep không throttle,
   browser notification requireInteraction) — vẫn KHÔNG tự tạo rule, chỉ đảm bảo người không bỏ lỡ.
                   │
⑥ NGƯỜI DÙNG mở flow trong Tulip (qua EVENTS → Make rule, hoặc HUNT), tự đọc, tự quyết định
                   │
⑦ Sinh rule trong tab RULES (Suricata alert-only, hoặc ctf_proxy block-thật — chọn đúng service
   nếu có nhiều service) → Test on recent traffic → Apply/Upload (một cú bấm, không tự động)
                   │
⑧ Rule mới xuất hiện ngay trong tab APPLIED (tự refresh mỗi lần mở tab) → theo dõi hit count,
   nếu khớp cả IP/traffic của checker → Pause filtering, sửa lại.
```

---

## Cấu hình tập trung — `services.json`

Tất cả component đọc từ **một file duy nhất**: `contest-runtime/config/services.json`. Không
hardcode IP/port/keyword ở bất cứ đâu khác trong code — mọi nơi cần port/tên service đều đọc động
từ file này lúc chạy (deploy-ctfproxy.sh, host_agent, dashboard, watchdog, capture BPF filter đều
vậy — xem field `services[]` có thể khai nhiều service với `proto`/`layer`/`compose_service` khác
nhau, port thay đổi được bất cứ lúc nào chỉ bằng sửa file này + redeploy, không cần sửa code).

```json
{
  "vulnbox":      { "ip": "...", "ssh_user": "...", "capture_ssh_alias": "..." },
  "monitor_host":  { "ip": "...", "dashboard_port": 8080 },
  "flag":          { "regex": "[A-Z0-9]{31}=", "submit_url": "..." },
  "ctf_proxy":     { "keyword": "CTFMONITOR_BLOCKED", "insertion": { "mode": "docker-compose", ... } },
  "services": [
    { "name": "web", "port": 8003, "proto": "tcp", "layer": "l7-http", "compose_service": "public-proxy" }
  ],
  "retention":     { "pcap_max_gb": 5, "min_free_gb": 10, "tulip_flow_retention_hours": 0 }
}
```

`proto` ∈ `tcp`/`udp`. `layer` ∈ `l7-http`/`l7-https`/`l4-raw`/`l4-udp` — quyết định ctf_proxy có
eligible cho service này không (`proto: tcp` only) và filter dùng `HTTPStream` hay `TCPStream`.
`compose_service` = tên service trong docker-compose của vulnbox đang bind port đó (để
`deploy-ctfproxy.sh` biết gỡ port ở đâu); nếu bỏ trống, rơi về field cũ
`ctf_proxy.insertion.remote_compose_service` (tương thích config viết trước khi field này có).

`bash contest-runtime/config/validate-config.sh` kiểm tra consistency trước khi `bringup.sh` chạy
bất cứ thứ gì.

---

## Những gì KHÔNG có trong repo này (đã gỡ bỏ, đừng tìm lại)

| Thành phần cũ | Trạng thái |
|---|---|
| `ioc-brain` (FastAPI gọi LLM phân tích flow) | Đã xóa hoàn toàn khỏi repo |
| `mcp-tulip` (MCP layer cho LLM đọc Tulip) | Đã xóa hoàn toàn |
| Ollama / `llm-host` / model `foundation-sec-8b-chat` | Đã xóa, không còn service nào gọi LLM |
| `vault/` (RAG/AnythingLLM workspace) | Đã xóa |
| Nút "Ask LLM" trên Dashboard | Đã gỡ khỏi UI |

Lý do: người dùng yêu cầu gỡ hoàn toàn mọi đường dẫn generative-AI khỏi repo (không còn dùng được
LLM trong môi trường thi). `ml-fingerprint` được **giữ lại** vì là bộ phân loại non-generative
(sklearn DBSCAN), không phải LLM.

---

## Tóm tắt một dòng cho từng component còn lại

| Component | Một câu mô tả |
|---|---|
| **ctf_proxy** | Chặn thật trước MỌI service TCP khai trong services.json (trừ UDP) |
| **Suricata** | Đọc lại pcap, chỉ cảnh báo, không chặn được gì |
| **Fallback firewall (iptables)** | Chặn theo IP hoặc theo nội dung packet — dùng khi ctf_proxy không áp được, hoặc cho UDP |
| **Redis** | Chuyển alert real-time + làm hàng đợi lệnh dashboard→host_agent |
| **Tulip** | Lưu toàn bộ flow TCP để người dùng tự đọc forensics |
| **dashboard** | Tổng hợp alert + giao diện tạo/áp rule, một chỗ |
| **host_agent.py** | Daemon trên host thật thi hành mọi lệnh có quyền (SSH/docker) theo whitelist |
| **watchdog (SLA)** | Service của mình còn sống không |
| **OS-watchdog** | Trên chính vulnbox — phát hiện RCE đã thành công |
| **mock-vulnbox** | Target giả cho luyện tập/demo (chỉ MODE=prep) |
| **ml-fingerprint** | Phân loại client (sklearn, không generative) — chỉ MODE=prep, cần xác nhận bằng văn bản mới dùng thi thật |

---

*ARCHITECTURE.md — cập nhật 2026-10-14. Dựa trên code thực tế trong `contest-runtime/` và lịch sử
trong `docs/STATUS.md` (không phải suy diễn).*
