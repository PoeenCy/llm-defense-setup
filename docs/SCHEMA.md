# Tham chiếu Schema của services.json

> **Mọi** thành phần trong CTF monitoring hub chỉ đọc duy nhất từ
> `contest-runtime/config/services.json`.
> **Không bao giờ** hardcode IP, port, hay định dạng flag ở bất kỳ nơi khác — mọi port dùng ở bất
> cứ đâu trong repo (BPF filter của capture, ctf_proxy, polling của watchdog, các rule builder
> trên dashboard) đều được đọc từ file này lúc runtime, không nằm cứng trong code.
>
> Không có field LLM/generative-AI nào trong schema này — repo này không có thành phần đó.

---

## Field cấp cao nhất

| Field | Kiểu | Bắt buộc | Mô tả |
|-------|------|----------|-------------|
| `_comment` | string | không | Ghi chú cho người đọc; parser bỏ qua |
| `team_id` | string | **có** | Mã định danh team, dùng trong nhãn log và tên thư mục remote của ctf_proxy (`~/ctf-proxy-<team_id>`) |
| `vulnbox` | object | **có** | Config kết nối & capture tới vulnbox |
| `monitor_host` | object | **có** | IP và các port service của máy này |
| `flag` | object | **có** | Định dạng flag & config nộp flag lên gameserver |
| `teams_cidr` | string | **có** | CIDR của toàn bộ các team (dùng để lọc traffic) |
| `gameserver_hint` | object | không | Gợi ý IP gameserver (tùy chọn) |
| `honeytoken` | object | **có** | Config flag giả dùng làm bẫy phát hiện |
| `tulip` | object | **có** | Config port của service Tulip |
| `mock_vulnbox` | object | **có** | Config target giả chỉ dùng để luyện tập, vẫn được đọc cả khi `MODE=contest` để quyết định `bringup.sh` có cần khẳng định nó KHÔNG đang chạy hay không |
| `ctf_proxy` | object | **có** | Config proxy chặn ở edge: keyword, tinh chỉnh nginx failover, và cách/có nên chèn nó vào vulnbox thật hay không |
| `ml_classifier` | object | **có** | Cổng tuân thủ (compliance gate) cho bộ phân loại ml-fingerprint tùy chọn |
| `services` | array | **có** | Danh sách service trên vulnbox cần theo dõi — một hoặc nhiều, trộn tự do TCP/UDP/HTTP/raw |
| `capture` | object | không | Tinh chỉnh phiên capture (xem dưới); mọi field đều tùy chọn, giá trị mặc định an toàn |
| `flagtrace` | object | không | Tính năng tùy chọn dò chuỗi exfil-flag (xem dưới); không khai = tắt hoàn toàn, không gì chạy |
| `retention` | object | không | Các mức bảo vệ dung lượng đĩa (xem dưới); mọi field đều tùy chọn, giá trị mặc định an toàn |

---

## Object `vulnbox`

| Field | Kiểu | Bắt buộc | Mô tả |
|-------|------|----------|-------------|
| `ip` | string (IPv4) | **có** | IP vulnbox trên LAN của ban tổ chức |
| `ssh_user` | string | **có** | User SSH cho các script deploy — thường là "team patch key" hạn chế quyền, chỉ vào được container public-proxy của chính mình, không có full root |
| `ssh_port` | integer | **có** | Port SSH |
| `capture_iface` | string | **có** | Interface mạng dùng để capture, hoặc `"auto"` để `deploy-capture-pull.sh` tự dò interface external qua `ip route` |
| `pcap_broker_port` | integer | **có** | Port mà server pcap-broker nghe trên vulnbox, nếu có (hiếm — hầu hết setup dùng SSH+tcpdump thay vào, xem `capture_ssh_alias`) |
| `capture_ssh_alias` | string | không | Alias SSH (từ `~/.ssh/config`, có thể gồm `ProxyJump`) có ĐỦ quyền chạy `tcpdump -Z root` — dùng bởi `deploy-capture-pull.sh` khi user SSH riêng của team (ở trên) không đủ quyền. Cần khi quyền capture và quyền "SSH service riêng của team" là 2 mức khác nhau (phổ biến: SSH admin vào vulnbox-host khác với key riêng từng team) |
| `docker_bridge` | string hoặc null | không | Ghi đè: tên chính xác interface docker bridge cần capture, chỉ dùng khi `capture_iface: "auto"` dò nhầm qua `ip route` (hiếm) |
| `note` | string | không | Ghi chú tự do |

---

## Object `monitor_host`

| Field | Kiểu | Bắt buộc | Mô tả |
|-------|------|----------|-------------|
| `ip` | string (IPv4) | **có** | IP LAN của máy này trên mạng thi |
| `dashboard_port` | integer | **có** | Port HTTP của Dashboard |
| `alert_queue_port` | integer | **có** | Port Redis cho hàng đợi alert/lệnh chung |
| `bind_ip` | string (IPv4) | không | Địa chỉ mà Dashboard (8080) và Tulip web UI (3000) lắng nghe. `127.0.0.1` (mặc định/an toàn) = chỉ máy này. Đặt thành IP LAN để đồng đội trên mạng tin cậy mở được. Redis (`alert_queue_port`), API quản trị/test của detection, và Postgres của Tulip **luôn luôn** chỉ loopback bất kể giá trị này (đã sửa 2026-10-16 — trước đó cả 3 cũng theo `bind_ip`, nghĩa là mở dashboard cho LAN cũng vô tình mở luôn hàng đợi alert không mật khẩu và các endpoint test/inject-flag). Port thu thập honeytoken luôn luôn nghe trên mọi interface bất kể gì, theo thiết kế (nó phải được vulnbox gọi tới được) |
| `bind_ip_note` | string | không | Ghi chú nhắc lại điều trên |

Không có field `ioc_api_port` hay bất kỳ field liên quan LLM nào ở đây — thành phần đó đã bị gỡ
hoàn toàn khỏi repo.

---

## Object `flag`

| Field | Kiểu | Bắt buộc | Mô tả |
|-------|------|----------|-------------|
| `regex` | string | **có** | Regex (tương thích Python) khớp một flag hợp lệ |
| `submit_url` | string | không | URL nộp flag lên gameserver (PUT kèm header `X-Team-Token`, token được giữ NGOÀI file này) |
| `note` | string | không | Nhắc xác nhận lại với ban tổ chức |

---

## String `teams_cidr`

- Ký pháp CIDR (ví dụ `"10.13.2.0/24"`)
- Dùng bởi rule Suricata và bộ phát hiện flag-out để biết traffic nào là giữa các team

---

## Object `gameserver_hint`

| Field | Kiểu | Bắt buộc | Mô tả |
|-------|------|----------|-------------|
| `ip` | string (IPv4) | không | IP nghi là của gameserver |
| `note` | string | không | Cảnh báo cho người đọc về khả năng bị NAT |

---

## Object `honeytoken`

| Field | Kiểu | Bắt buộc | Mô tả |
|-------|------|----------|-------------|
| `flag` | string | **có** | Giá trị flag giả làm mồi (KHÔNG được là flag thật, nhưng vẫn phải khớp `flag.regex`) |
| `endpoint_port` | integer | **có** | Port mà bộ thu thập honeytoken lắng nghe trên máy monitor |
| `note` | string | không | Nhắc về vị trí đặt mồi |

---

## Object `tulip`

| Field | Kiểu | Bắt buộc | Mô tả |
|-------|------|----------|-------------|
| `web_port` | integer | **có** | Port web UI của Tulip |
| `ingestor_port` | integer | **có** | Port API ingestor của Tulip |
| `note` | string | không | Tulip lưu flow trong TimescaleDB/Postgres, không phải Mongo — không có field `mongo_port` |

---

## Object `mock_vulnbox`

Target giả chỉ dùng để luyện tập (`prep-only/training/mock-vulnbox/`), không bao giờ là phòng thủ thật.

| Field | Kiểu | Bắt buộc | Mô tả |
|-------|------|----------|-------------|
| `enabled` | boolean | **có** | `false` = chế độ vulnbox thật. Chỉ thực sự được bật khi `enabled: true` VÀ `MODE=prep` cùng đúng — `MODE=contest` không bao giờ bật nó bất kể cờ này, và luôn khẳng định nó chưa chạy |
| `hostname` | string | **có** | Tên DNS docker mà container trả lời trên `ctf-net` (mặc định `"mock-vulnbox"`) |
| `note` | string | không | Ghi chú |

---

## Object `ctf_proxy`

Config cho proxy chặn ở edge ([ctf_proxy](https://github.com/ByteLeMani/ctf_proxy),
vendor hoá tại `offline-bundle/repos/ctf_proxy`).

| Field | Kiểu | Bắt buộc | Mô tả |
|-------|------|----------|-------------|
| `keyword` | string | **có** | Chuỗi ctf_proxy gửi lại khi chặn một kết nối (`"<keyword> <service> <rule>"`, bytes thô, không có status line HTTP). `PROXY_BLOCK_RE` của detection parse chuỗi này — phải luôn là nguồn duy nhất mà các tool khác đọc theo, không bao giờ hardcode ở nơi khác |
| `listen_ip` | string | **có** | IP ctf_proxy lắng nghe (trong docker network riêng của vulnbox) |
| `nginx` | object | **có** | Tinh chỉnh failover: `connect_timeout`, `max_fails`, `fail_timeout` (giây) — truyền thẳng vào `generate_nginx_conf.py` của chính ctf_proxy |
| `dos` | object | **có** | `{"enabled": bool, "duration": int, "interval": int}` — tính năng tùy chọn của ctf_proxy làm chậm kẻ tấn công (giữ socket bị chặn mở, gửi byte định kỳ) |
| `insertion` | object | **có** | Chèn ctf_proxy vào đâu/cách nào đối với vulnbox THẬT — xem dưới |
| `note` | string | không | Nhắc `keyword` phải luôn đồng bộ |

### Object `ctf_proxy.insertion`

| Field | Kiểu | Bắt buộc | Mô tả |
|-------|------|----------|-------------|
| `mode` | string | **có** | `"disabled"` (mặc định, chỉ giám sát — không thử làm gì) hoặc `"docker-compose"` (chèn thật qua `deploy-ctfproxy.sh`) |
| `remote_ssh_alias` | string | nếu mode là `docker-compose` | Alias SSH có quyền vào docker/compose của vulnbox-host |
| `remote_compose_file` | string | nếu mode là `docker-compose` | Đường dẫn (trên vulnbox-host) tới compose file sở hữu (các) service mục tiêu |
| `remote_compose_service` | string | không | Tên compose service dùng **chung làm fallback**, áp dụng cho bất kỳ entry `services[]` nào không tự khai `compose_service` riêng (xem dưới) — giữ cho config viết từ trước khi field `compose_service` theo-từng-service tồn tại vẫn chạy được không cần đổi |
| `remote_network_name` | string | nếu mode là `docker-compose` | Docker network mà 2 container `nginx`+`proxy` của ctf_proxy phải join vào (thường dạng `<project>_<network-key>`, tìm bằng `docker network ls` trên vulnbox-host) |

---

## Object `ml_classifier`

Cổng tuân thủ cho service `ml-fingerprint` tùy chọn (`prep-only/ml-classifier/`), model
non-generative duy nhất còn lại trong repo (sklearn DBSCAN clustering).

| Field | Kiểu | Bắt buộc | Mô tả |
|-------|------|----------|-------------|
| `enabled` | boolean | **có** | Mặc định `false`. **Không có tác dụng gì** khi `MODE=contest` bất kể giá trị — `bringup.sh` không bao giờ gộp `docker-compose.prep.yml` vào ở chế độ contest, dừng ở đó. Chỉ bật service này ở `MODE=prep`, và chỉ khi BTC đã xác nhận bằng văn bản. |
| `note` | string | không | Nhắc lại điều trên |

---

## Array `services`

Mỗi phần tử mô tả MỘT service cần theo dõi — mảng này chứa bao nhiêu phần tử cũng được, trộn tự
do protocol/layer. Capture (BPF filter của tcpdump) và Suricata đã đọc **mọi** entry ở đây, không
giới hạn; việc chèn ctf_proxy (`deploy-ctfproxy.sh`) cũng lặp qua tất cả, nhưng chỉ thực sự front
cho những entry có `proto: "tcp"` (xem `layer`/`compose_service` dưới).

| Field | Kiểu | Bắt buộc | Mô tả |
|-------|------|----------|-------------|
| `name` | string | **có** | Mã định danh ngắn cho service (dùng trong tag Tulip, rule Suricata, và — sau khi làm sạch thành identifier Python hợp lệ — làm tên module/filter riêng của ctf_proxy nếu service này đủ điều kiện dùng ctf_proxy) |
| `port` | integer | **có** | Port TCP/UDP public trên vulnbox. Đổi được bất cứ lúc nào chỉ bằng sửa field này + deploy lại — không có gì trong code hardcode số port |
| `proto` | string | **có** | `"tcp"` hoặc `"udp"`. Service `"udp"` vẫn được capture và cảnh báo giống hệt TCP, nhưng **không bao giờ** đủ điều kiện dùng ctf_proxy (nó không proxy được UDP) — dùng chặn-theo-nội-dung của Dashboard cho các service này |
| `layer` | string | **có** | `"l7-http"` / `"l7-https"` (ctf_proxy parse như HTTP, filter nhận được `url`/`path`/`method`/`parameters`/`headers`/`raw_body`) hoặc `"l4-raw"` (TCP thô, filter chỉ nhận bytes thô của message hiện tại) hoặc `"l4-udp"` (chỉ mang tính thông tin — hiệu lực giống `proto: "udp"` với điều kiện dùng ctf_proxy) |
| `compose_service` | string | không | Tên compose service trên vulnbox-host hiện đang bind `port` của service này — cần cho `deploy-ctfproxy.sh` để biết gỡ dòng port nào và recreate container nào. Nếu bỏ trống sẽ dùng lại `ctf_proxy.insertion.remote_compose_service` (config 1-service viết từ trước khi có field này vẫn chạy đúng, không cần sửa) |
| `description` | string | không | Mô tả service cho người đọc |
| `note` | string | không | Ghi chú tự do riêng từng service |

---

## Object `capture`

Tinh chỉnh vòng lặp capture tự quản (`contest-runtime/monitor/capture_pull.py`). Mọi field đều
tùy chọn; BPF filter luôn được dựng từ mọi port trong `services[]` (không phân biệt protocol —
khớp cả TCP và UDP), không bao giờ lấy từ object này.

| Field | Kiểu | Bắt buộc | Mô tả |
|-------|------|----------|-------------|
| `rotate_seconds` | integer | không | Bao lâu tcpdump rotate sang file pcap mới trên vulnbox-host (mặc định `30`). Một file chỉ được kéo về monitor sau khi đã rotate xong và đóng lại — không bao giờ kéo khi còn đang được ghi |
| `remote_max_mb` | integer | không | Giới hạn dung lượng spool trên vulnbox-host (mặc định `512`). Nếu thư mục của chính phiên capture vượt ngưỡng này, hoặc dung lượng trống của vulnbox tụt dưới 256MB, tcpdump remote tự dừng một cách an toàn (đóng file đang ghi trước, không mất gì) thay vì làm đầy đĩa vulnbox |
| `pull_seconds` | integer | không | Bao lâu monitor kiểm tra lại để kéo các file vừa đóng xong (mặc định `5`) |

Riêng `retention.min_free_gb` (xem dưới) cũng chặn ở phía MONITOR: việc kéo file sẽ tạm dừng nếu
dung lượng trống của chính monitor tụt dưới ngưỡng đó, độc lập với giới hạn phía vulnbox ở trên.

---

## Object `flagtrace`

Tùy chọn. Không khai hoặc `enabled: false` = không gì chạy. Tham chiếu đầy đủ, lệnh và cách triển
khai: `contest-runtime/flagtrace/README.md`.

| Field | Kiểu | Bắt buộc | Mô tả |
|-------|------|----------|-------------|
| `enabled` | boolean | không | Bật `ctf-flagtrace` (ingest + API đọc). Cần có `game.id`, `game.start_time`, `game.tick_seconds`, `game.checker_ips` và `teams[].ips` |
| `trace.enabled` | boolean | không | Bật `ctf-flagtrace-worker` (hồ sơ trace Phase 2). Yêu cầu `enabled: true`. Tắt chỉ dừng worker; hồ sơ/kết quả đã lưu vẫn giữ nguyên |
| `trace.*` (giới hạn) | number | không | `algorithm_budget_ms`, `max_depth`, `max_nodes`, `max_edges`, `max_tokens_per_node`, `max_candidates_per_token`, `max_query_rows`, `token_max_df`, `df_min_samples` (`max_context`, `context_window_seconds`, `burst_gap_seconds` đã bị gỡ cùng với context ở engine p2.3.2 và bị từ chối nếu khai); vận hành: `poll_seconds`, `lease_seconds`, `max_attempts`. Đây là giá trị khởi điểm, chưa được benchmark |
| `trace.same_service_only` | boolean | không | Phải luôn là `true` ở bản này; `false` sẽ bị từ chối |
| `decoder_mode` | string | không | `full` (mặc định) decode mọi body; `gated` chỉ decode body trông như đã mã hóa (giống cách detection làm); `off` không decode gì, nên sẽ bỏ lọt các flag chỉ hiện ra sau khi decode. Dashboard (tab FLAG TRACE) có thể ghi đè lúc runtime; ghi đè đó được giữ qua các lần restart cho tới khi reset |
| `flag_ids_url` | string | không | URL HTTP(S) được hỏi 1 lần mỗi tick để lấy flag ID. Phải trả về JSON list dạng `{"tick", "service", "owner_team_id", "value"}` (tên service giống `services[].name`); API của một giải khác định dạng cần viết adapter riêng. Nếu không khai, flag ID vẫn lấy được từ chính các phiên putflag của checker, hoặc từ `import-flagids <file>` |
| `game.flag_validity_ticks` | integer | không | Flag còn hợp lệ bao nhiêu tick, theo luật của giải. Dùng để chấp nhận một flag ID là value role `target`; không khai = chấp nhận mọi tick trước đó, và kết quả sẽ ghi rõ điều này |

Value role (`target`) khớp với flag ID thuộc về `team_id` ở cấp cao nhất: capture được lấy trên
vulnbox của chính team này, nên mọi flag-out đều làm lộ một flag mà team này sở hữu.

Cũng được dùng bởi `contest-runtime/hostagent/retention.py`: một pcap không bao giờ bị xóa khi
ingest của Flag-trace còn có thể cần tới nó (xem object `retention` dưới) — không cần field mới,
chỗ này chỉ kiểm tra `flagtrace.enabled` và việc database của Flag-trace đã tồn tại hay chưa.

---

## Object `retention`

Bộ bảo vệ dung lượng đĩa, chạy mỗi 60s bởi `contest-runtime/hostagent/retention.py`. Ba mức leo
thang: (1) xóa pcap đã capture cũ, (2) dọn image/build-cache dangling của chính Docker (luôn an
toàn — không bao giờ đụng vào thứ đang chạy), (3) chỉ khi tự chọn (opt-in) — xóa dữ liệu flow cũ
của Tulip.

| Field | Kiểu | Bắt buộc | Mô tả |
|-------|------|----------|-------------|
| `pcap_keep_minutes` | integer | không | Xóa pcap cũ hơn mốc này sau khi detection đã quét xong; `0` (mặc định) = tắt |
| `pcap_max_gb` | number | không | Giữ `traffic/` dưới dung lượng này, xóa file cũ nhất trước (mặc định `5`) |
| `min_free_gb` | number | không | Giữ tối thiểu dung lượng trống này; kích hoạt xóa pcap, rồi tới dọn Docker (mặc định `10`) |
| `tulip_flow_retention_hours` | number | không | **Phương án cuối, chỉ khi tự chọn (opt-in).** `0` (mặc định) = không bao giờ đụng vào dữ liệu flow của Tulip. Nếu đĩa vẫn dưới `min_free_gb` sau cả dọn pcap *và* dọn Docker, host_agent sẽ xóa các chunk TimescaleDB trong bảng `flow`/`flow_item` của Tulip cũ hơn số giờ này. Việc này xóa flow thi thật đã capture — chỉ để `0` trừ khi bạn hiểu rõ đánh đổi này. |
| `note` | string | không | Nhắc lại điều trên |

---

## Kiểm tra (Validation)

Chạy `bash contest-runtime/config/validate-config.sh` sau mỗi lần sửa `services.json`.
Nó sẽ `exit 1` ngay và báo rõ nếu thiếu field bắt buộc hoặc sai kiểu dữ liệu, và cảnh báo riêng
nếu file `offline-bundle/repos/ctf_proxy/proxy/config/config.json` CỤC BỘ (được ghi bởi
generator `gen-ctfproxy.py` đã orphan, nhưng vẫn được `bringup.sh` gọi — xem mục File Structure
trong `docs/RUNBOOK.md`) có `keyword` lệch so với file này. Kiểm tra này không liên quan tới
việc deploy remote THẬT (`deploy-ctfproxy.sh` tự ghi `config.json` riêng trực tiếp trên
vulnbox-host, không bao giờ đọc hoặc ghi vào file cục bộ này).
