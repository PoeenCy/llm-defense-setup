**Flag-trace — Kế hoạch triển khai Phase 1 vào framework hiện tại**

> **Ghi chú đối chiếu 2026-10-14:** giữ nguyên kế hoạch tại thời điểm lập bên dưới. Phase 1 đã có implementation; xem [báo cáo kiểm chứng](PHASE1_REPORT.md) và [nền tích hợp hiện tại](INTEGRATION_BASELINE.md), gồm cả các yêu cầu trong kế hoạch chưa được thực hiện đầy đủ.

Ngày lập: 2026-10-14. Trạng thái: kế hoạch dựa trên việc đọc code, chưa triển khai hoặc kiểm chứng runtime.

Tài liệu gốc: [PHASE1_INGEST.md](PHASE1_INGEST.md), [hợp đồng Phase 2](PHASE2_TRACE.md). Những khác biệt bên dưới là phương án tích hợp đề xuất; cần cập nhật đồng bộ hợp đồng khi bắt đầu triển khai.

**1. Đầu ra và phạm vi nghiệm thu**

Phase 1 hoàn tất khi một bộ PCAP đi qua pipeline và tạo được:

- Transaction request/response có chiều truyền, connection, thứ tự, timestamp, đội, service và tick.
- Bytes nguyên gốc cùng bản parse/giải mã; phân biệt rõ dữ liệu đầy đủ, thiếu, bị cắt hoặc không hỗ trợ.
- Token consumed/produced có vị trí, quan hệ token cha/con và thông tin phép giải mã.
- Flag sighting, phân loại checker/nguồn chưa biết và một job trace bền vững cho transaction đủ điều kiện.
- Bảng flag IDs khi có nguồn dữ liệu, baseline từ checker, trạng thái ingest và API đọc tối thiểu.
- Restart hoặc ingest lại cùng dữ liệu không tạo thêm transaction/job trùng.

Trace chain, signature exploit, sinh script replay, tab chain và tự động áp rule thuộc giai đoạn sau. Phase 1 tạo queue nhưng chưa chạy trace worker.

**2. Những gì đã xác nhận từ repo**

| Điểm hiện có | Bằng chứng trong code | Hệ quả cho Phase 1 |
|---|---|---|
| Capture xoay 30s, kéo mỗi 15s | `contest-runtime/monitor/deploy-capture-pull.sh` | Tận dụng pipeline; thay kiểm tra tuổi file bằng xác nhận file đã đóng |
| Detection quét từng packet, gộp flag trong phạm vi PCAP | `contest-runtime/detection/service/detection_service.py` | Không dùng alert hiện tại làm transaction hoặc queue đầu vào trace |
| Tulip ghép TCP và lưu flow/flow_item | `offline-bundle/repos/tulip/services/go-importer/cmd/assembler/` | Tận dụng thư viện/kinh nghiệm reassembly; cần lớp ingest riêng bảo toàn raw và ranh giới transaction |
| Tulip có thể thay response raw bằng bản giải nén | `assembler/http.go` | Không coi dữ liệu API Tulip là bản sao bytes trên dây |
| Hai bản decoder hiện giống nhau | `detection/service/decoders.py`, `dashboard/app/decoders.py` | Có thể hợp nhất vào module dùng chung, với kiểm thử hồi quy |
| Redis giới hạn RAM, dùng eviction; compose chưa cấu hình lưu queue bền vững | `docker-compose.contest.yml` | Queue trace và tiến độ ingest đặt trong SQLite |
| Retention có thể xóa PCAP chưa scan khi thiếu đĩa/quá dung lượng | `contest-runtime/hostagent/retention.py` | Phải tích hợp trạng thái ingest trước khi bật Flag-trace với retention |
| Config dùng `team_id` dạng chuỗi, `proto=tcp`, `layer=l7-http` | `contest-runtime/config/services.json` | Giữ định dạng này; không ép team thành số hoặc đổi `proto` sang HTTP |
| Tick start được sinh bằng giờ hiện tại, tick length hardcode | `config/generators/gen-tulip-env.py` | Bổ sung thời gian giải cố định để các thành phần thống nhất |
| Config Save & apply dựng đường dẫn bringup từ ROOT là contest-runtime | `hostagent/actions/config.py`, `hostagent/common.py` | Sửa đường dẫn repo và truyền MODE khi tích hợp redeploy Flag-trace |

Config đang có `port=8003`, `capture_port=8090`, trong khi ghi chú mô tả capture pre-NAT. Đây là điểm cần kiểm chứng bằng metadata PCAP trước khi bật live; chưa kết luận giá trị nào sai và không tự sửa cấu hình hiện tại.

**3. Kiến trúc triển khai được chọn**

```text
Vulnbox: tcpdump → file đã đóng
                   ↓ ship + công bố file hoàn tất
Monitor: traffic/*.pcap ───────→ Tulip / Suricata / detection hiện tại
                   ↓
          ctf-flagtrace
          ├─ Go helper: đọc PCAP, ghép TCP, tách HTTP message
          ├─ Python: tagger, structured parse, decoder, token, flag
          ├─ DB writer: transaction + token + job trace
          ├─ công việc phụ: flag IDs và baseline
          └─ API đọc + trạng thái
                   ↓
          SQLite trên volume bền vững
```

- Một service Compose `flagtrace`, container `ctf-flagtrace`, chạy trên monitor.
- Go helper dùng `github.com/gopacket/gopacket/reassembly`; bản 1.3.0 đã có trong Tulip và module cache local. Pin dependency và kiểm chứng bằng fixture trước khi mở rộng.
- Python 3.11 để khớp container hiện tại; host đang có Python khác phiên bản, nên nghiệm thu bằng môi trường/container cố định.
- Go giữ phần transport/HTTP framing; Python giữ logic nghiệp vụ, decoder và SQLite. Giao tiếp bằng record có version, giới hạn kích thước, raw bytes biểu diễn base64. Log đi riêng khỏi kênh dữ liệu.
- Không sửa source trong `offline-bundle/`: đây là artifact bị gitignore. Module Go mới nằm trong source Flag-trace; ghi nhận nguồn khi tái sử dụng code.
- Không ghép thêm một stack Tulip hay database cho từng đội.

**4. Cấu trúc source dự kiến**

```text
contest-runtime/
├── flagtrace/
│   ├── Dockerfile                 # Go builder + Python runtime
│   ├── requirements.txt
│   ├── transport/                 # go.mod, cmd/, internal/, Go tests
│   ├── app/
│   │   ├── main.py                # lifecycle, supervisor, shutdown
│   │   ├── config.py              # snapshot + validation + config version
│   │   ├── contracts.py           # dataclasses và record version
│   │   ├── ingest/                # discovery, helper adapter, recovery
│   │   ├── parsing/               # bodies, locations, representations
│   │   ├── tagging.py
│   │   ├── tokens.py
│   │   ├── flags.py
│   │   ├── baseline.py
│   │   ├── flagids.py
│   │   ├── store/                 # migrations, writer, repositories
│   │   └── api.py                 # read-only endpoints
│   └── tests/                     # unit, integration, PCAP fixtures
└── common/
    └── flag_decoders.py           # engine dùng chung sau refactor

data/flagtrace/                     # DB/WAL và runtime metadata; gitignore
traffic/.incoming/                 # file ship chưa được công bố
```

**5. Database và hợp đồng dữ liệu**

Một SQLite cho toàn bộ đội, trên filesystem local, bật WAL, foreign keys, busy timeout. Bắt đầu với `synchronous=FULL`; benchmark trước khi cân nhắc giảm mức đồng bộ. Một DB writer xử lý ingest và các cập nhật nền; API dùng connection đọc riêng. Batch tối đa khoảng 200 transaction hoặc flush theo thời gian để traffic ít không bị chờ vô hạn.

| Bảng | Nội dung và ràng buộc chính |
|---|---|
| `games`, `config_versions` | Game ID, thời gian giải, cấu hình dùng để phân tích |
| `teams`, `team_networks` | Team ID dạng TEXT, IP/CIDR; không suy luận đội từ octet IP |
| `pcap_files`, `pcap_paths` | Identity theo game/source/content hash; đường dẫn, thứ tự capture, trạng thái và lỗi |
| `connections` | Hai endpoint, transport, capture source, thời điểm bắt đầu/kết thúc, SYN/gap/close reason |
| `transactions` | ID riêng, connection, thứ tự, request/response raw, parse result, timestamps, team/service/tick, quality |
| `transaction_pcaps` | Quan hệ nhiều file cho một transaction; packet/stream spans phục vụ tra cứu |
| `representations` | Bản raw/decoded, kiểu encoding, parent, transform và mức đầy đủ |
| `tokens` | Giá trị gốc/chuẩn hóa, role, location, representation, parent token, source key và observation time |
| `token_df`, `service_stats` | Đếm số transaction chứa token và tổng transaction tương ứng |
| `flag_sightings`, `flags_in` | Flag, hướng, transaction, representation, vị trí và ngữ cảnh checker |
| `trace_queue` | Một job duy nhất cho transaction/version; pending/leased/done/error, attempts và lease |
| `flag_ids` | Game, tick/validity, service, đội sở hữu flag ID, value và nguồn |
| `baseline` | Thống kê checker theo service/path template/field; sample count và version |
| `ingest_checkpoints` | Tiến độ đã commit, mốc PCAP phải replay khi restart |

Quy ước bắt buộc:

- Đổi tên `flows` trong spec Flag-trace thành `transactions`. `conn_id`, `transaction_id`, ID flow Tulip là ba khái niệm riêng.
- `team_id` của transaction là đội nguồn request; đội sở hữu `flag_id` được đặt tên rõ là `owner_team_id`.
- IP chưa biết: `team_id=NULL`, có `source_key=ip:<địa chỉ>`. SQL không dùng `team_id=NULL` để nối tất cả nguồn lạ.
- Timestamps lưu dạng integer microseconds UTC, có request start/response start/end và token observation time. Tick tính từ packet time; queue time là thời gian xử lý riêng.
- ID connection/transaction phải ổn định khi replay cùng capture source. Unique trên `(game_id, conn_id, seq_in_conn)`; queue unique theo transaction và analysis version.
- Index chính: transaction `(game_id, source_key, service, ts_request)`, `(conn_id, seq_in_conn)`; token `(game_id, source_key, service, normalized_value, observed_ts)`.
- `token_df` tăng một lần cho mỗi giá trị trong một transaction, dù token xuất hiện nhiều vị trí; ingest trùng không tăng lại.
- Thay cấu hình tạo version mới; không âm thầm thay nghĩa các dòng cũ. Reclassify/reindex phải là thao tác rõ ràng.

Sự kiện Phase 2 sẽ nhận: `{"schema_version":1,"game_id":"…","transaction_id":"…"}`. Cập nhật PHASE2_TRACE.md từ `flow_id` sang hợp đồng mới trước khi viết trace worker.

**6. Capture, ingest và phục hồi sau restart — A1 đến A4**

Capture/ship:

1. Dùng session ID cho capture, tên file không đụng giữa các lần deploy. Xác định capture point và port thấy được tại đó.
2. tcpdump ghi đầy đủ packet; callback sau rotation đánh dấu file đóng. Duy trì thứ tự file; callback hoàn tất muộn không được làm worker xử lý vượt một file còn thiếu.
3. Ship vào `.incoming`, kiểm tra hoàn tất, công bố `.pcap` ở `traffic/` bằng rename cùng filesystem. Chỉ xác nhận/xóa bản remote sau khi local đã được công bố và ghi nhận.
4. Stop capture phải đóng và bàn giao cả file cuối; quản lý PID/session của chính framework, không kill mọi tcpdump trên máy.
5. Không chuyển PCAP đã ingest sang archive khác vì Tulip/detection vẫn dùng `traffic/`. Trạng thái archive nằm trong DB.

Ingest/reassembly:

- Xử lý file theo thứ tự capture cho từng source; một source là một điểm capture chuẩn, tránh ghép lẫn cùng traffic ở hai hop NAT.
- PCAP Ethernet/VLAN và Linux cooked cần fixture; hỗ trợ IPv4/IPv6 TCP trong phạm vi link types đã kiểm chứng. Link type/protocol không hỗ trợ phải có counter và lý do, không lặng lẽ bỏ.
- Retransmission, out-of-order, sequence wrap, port reuse, half-close, RST và missing SYN có test riêng. IP fragmentation phải reassemble hoặc đánh dấu chưa hỗ trợ/không đầy đủ rõ ràng.
- Dùng mapping byte offset → packet timestamp/provenance; không lấy thời điểm callback reassembly làm timestamp cho mọi byte. API `ScatterGather.CaptureInfo(offset)` đã có ở dependency local.
- HTTP transaction được phát khi response đủ dữ liệu; không đợi connection keep-alive đóng. Raw TCP giữ turns và hoàn tất khi close/timeout.
- Replay PCAP cũ dùng packet time để tính timeout; không dùng trực tiếp giờ máy hiện tại để flush tất cả connection cũ.
- Giới hạn open connections, buffer, thời gian chờ và kích thước record. Khi chạm giới hạn, lưu quality reason và metrics; không khẳng định dữ liệu đầy đủ.

Recovery:

- Mốc đã đọc file không đồng nghĩa trạng thái TCP đã an toàn để bỏ. Giữ mốc replay từ file sớm nhất còn chứa đầu connection đang mở.
- Persist checkpoint bảo thủ trước khi tiến sang phần dữ liệu mới; chỉ nâng mốc sau khi output liên quan đã commit.
- Sau crash, replay từ mốc này để dựng lại transport/parser state. ID ổn định và unique constraint ngăn tăng transaction/token/job lần nữa.
- Pin PCAP cần replay; job trace đã commit vẫn pending sau restart.
- Dữ liệu đến quá muộn, thiếu file hoặc vượt giới hạn recovery phải được đánh dấu; giữ khả năng reimport một capture vào dataset mới, không vá âm thầm vào connection đã chốt.
- Với connection sống quá lâu, phải có giới hạn tài nguyên và chính sách đóng partial có lý do; không để cơ chế pin giữ đĩa vô hạn.

**7. Tag, parse, flag và token — A5 đến A9**

Tagger xác định server bằng capture endpoint/service config và SYN khi có, không suy luận từ port nhỏ hơn. Cho phép địa chỉ service sau NAT trong cấu hình khi cần. Trường hợp chiều truyền mơ hồ được lưu riêng và không tự kết luận flag-out. Mapping checker do người vận hành cấp, không suy từ IP scoreboard.

HTTP framing phải kiểm chứng Content-Length, chunked/trailers, keep-alive, pipelining, HEAD, 1xx/100 Continue, 204/304 và body kết thúc bằng close. Informational response không được làm lệch cặp request/response. Framing mâu thuẫn hoặc mất byte được đánh dấu và giữ phần còn lại ở dạng raw.

Giữ nguyên raw request/response; parse headers, query, form theo danh sách giữ thứ tự và phần tử trùng. JSON/multipart giữ đường dẫn trường, occurrence, filename, content type và dữ liệu binary. Location cần vừa đọc được vừa có cấu trúc để tên key chứa dấu chấm/ngoặc không gây nhầm.

Giải transfer encoding trước content encoding. Mọi bước giải nén/decoder có hạn mức đầu ra, số lớp và thời gian; giữ `decode_error`, `decode_truncated` hoặc `decode_budget_exhausted`. Có `max_body_stored` và `max_scan_bytes` riêng: không cắt bản lưu rồi coi vùng chưa scan là sạch. Raw/decoded bị cắt luôn giữ provenance và chỉ báo mức phủ.

TLS giữ metadata, đánh dấu encrypted; Phase 1 không tự chèn TLS proxy. HTTP/2 và WebSocket nâng cấp được giữ raw/turns với nhãn protocol; chưa tuyên bố hỗ trợ token/flag trong payload cho đến khi có parser riêng.

Flag rules:

- Ghi sighting ở cả request và response, kể cả checker; checker response không tạo job trace.
- Response của nguồn chưa map đội vẫn có thể tạo job với source key IP; sửa điều kiện `team_id IS NOT NULL` trong spec gốc.
- Phân biệt request chứa flag rồi response echo trong cùng transaction; không dùng việc flag xuất hiện ở bất kỳ request nào trong cùng PCAP để hạ toàn bộ cảnh báo.
- Regex match là bằng chứng thấy flag-format, chưa phải xác nhận exploit. Giữ thông tin flag-in đã biết và lý do phân loại.
- Một response nhiều flag có một job, nhiều sightings. Match dùng whole match ngay cả khi regex có capture groups.

Token rules:

- Consumed từ request; produced từ response; timestamp theo byte/message nguồn để Phase 2 không tạo cạnh đi ngược nhân quả.
- Giữ raw value, normalized value và transform chain. URL decode đúng ngữ cảnh; không trim/decode mất thông tin ở trường binary hay password.
- Subtoken có offset trong parent và ngưỡng riêng (`sub_min_len=3`); giữ được flag ID `7731` dù `min_len=6`.
- JWT claims/base64 tạo representation con; không coi claim JWT là đã được xác thực hoặc có thể sửa và ký lại.
- Chỉ lọc min length/stoplist lúc ghi. DF được lưu để Phase 2 lọc động; định nghĩa rõ mẫu số là số transaction của service trong phạm vi thống kê.

**8. DB commit, công việc phụ và API — A10 đến A13**

- Ghi transaction, representations, token, DF, sightings và queue trong cùng commit. Không enqueue Redis trước commit.
- Job queue bền vững nằm trong SQLite. Redis chỉ đưa trạng thái tới dashboard; Phase 1 chưa phát thêm bộ alert flag-out trùng detection mặc định.
- Baseline cập nhật từ checker theo tick, có số mẫu và cửa sổ thống kê; dùng cùng module chuẩn hóa path mà Phase 2 sẽ dùng. Chưa có baseline phải thể hiện là thiếu dữ liệu.
- Flag IDs: hỗ trợ import JSON chuẩn hóa và adapter nguồn BTC tùy chọn. Schema chuẩn chứa game, tick/validity, service, owner_team_id, value. Thiếu API thực tế không chặn ingest; endpoint submit flag không phải nguồn flag IDs.
- Token/flag vị trí trong decoded data phải chỉ về đúng representation, không giả làm offset raw.
- API nội bộ tối thiểu: `/health`, `/status`, `/transactions`, `/transactions/{id}`, `/flagouts`. Có phân trang, lọc team/IP/service/tick và giới hạn payload. Queue kiểm tra qua CLI/status; không có endpoint chạy exploit.
- Dashboard thêm route proxy đọc `/api/flagtrace/...`; System Status/Services hiện trạng thái và điều khiển container. Tab phân tích chain để sau.

**9. Config, retention và vòng đời triển khai**

Mở rộng `services.json`, không tạo config YAML thứ hai:

- `game`: `id`, `start_time`, `tick_seconds`, `checker_ips`.
- `teams`: danh sách ID dạng chuỗi, tên và IP/CIDR; kiểm tra mapping chồng lấn giữa đội.
- `flagtrace`: `enabled`, giới hạn ingest/decode/body, token options, baseline window và flag-ID source.
- Cấu hình capture thêm rotation/pull interval, capture identity và hạn mức spool. Giữ `services[].proto/layer/port/capture_port` tương thích.
- Cấu hình đang dùng không có block Flag-trace vẫn chạy stack cũ; khi bật Flag-trace phải validate trường bắt buộc. Không tự điền IP checker hoặc thời gian giải bằng phỏng đoán.
- Tulip generator dùng game start/tick khi có, giữ fallback cho cấu hình cũ. Validate cả thay đổi Save & apply và restart worker bằng config snapshot mới.

Retention là điều kiện bắt buộc trước live:

- Bổ sung trạng thái durable để host agent biết PCAP chưa ingest, cần replay hoặc cần giữ làm bằng chứng. Quyền xóa phải có điều phối với ingest/reimport, tránh race giữa kiểm tra và unlink.
- Theo dõi riêng DB, WAL, traffic và staging. Checkpoint WAL định kỳ; không vacuum lớn trong đường ingest.
- Khi vượt hạn mức: dọn phần đủ điều kiện trước; nếu vẫn thiếu chỗ thì báo degraded và dừng nhận thêm ở ngưỡng đã cấu hình. Remote spool cũng có quota và dừng capture của framework trước khi làm đầy đĩa vulnbox; ghi nhận khoảng trống capture.
- Không âm thầm xóa file chưa xử lý để rồi đánh dấu pipeline khỏe. Dừng capture vẫn phải bàn giao được file cuối theo cơ chế đóng file.
- Bản raw lưu bị cắt phải thể hiện nếu PCAP đầy đủ về sau hết retention; không hứa có thể tải lại dữ liệu đã bị xóa.

**10. File cần thêm hoặc sửa**

| File/khu vực | Thay đổi |
|---|---|
| `contest-runtime/flagtrace/` | Toàn bộ module mới, schema, API, CLI, fixture và tests |
| `contest-runtime/common/flag_decoders.py` | Hợp nhất decoder; bổ sung metadata/giới hạn khi cần |
| Hai `decoders.py` hiện tại + Dockerfile tương ứng | Wrapper/import tương thích; sửa build context/COPY để dùng common, không thêm bản copy thứ ba |
| `docker-compose.contest.yml` | Service, volume DB, traffic/config read-only, healthcheck, stop grace period |
| `bringup.sh`, `teardown.sh` | Enable/disable, khởi động và shutdown đúng, giữ DB; offline dùng image đã build |
| `contest-runtime/config/services.json`, validator, `docs/SCHEMA.md` | Schema bổ sung, tương thích config cũ; giữ thay đổi người dùng đang có |
| `config/generators/gen-tulip-env.py` | Đồng bộ game start/tick; giữ thay đổi decoder đang có |
| `monitor/deploy-capture-pull.sh` + helper capture/ship | Closed-file protocol, staging, session identity và shutdown |
| `hostagent/registry.py`, `actions/services.py` | Đăng ký service; quản lý đúng capture session/PID |
| `hostagent/actions/config.py` | Restart Flag-trace; sửa repo path, MODE và báo kết quả redeploy chính xác |
| `hostagent/retention.py`, `health_check.py` | Ingest-aware retention, backlog/lag/recovery/disk status |
| `dashboard/app/routes/flagtrace.py`, main/core config | Proxy API đọc và trạng thái; chưa dựng chain UI |
| `pull-and-save.sh`, `offline-restore.sh` | Build/save/load image Flag-trace rõ ràng; không dựa vào image vô tình có trên máy |
| `.gitignore`, `.dockerignore` phù hợp | Không đưa DB/WAL/traffic/secrets vào Git hoặc Docker build context |
| `flag-trace/PHASE1_INGEST.md`, `PHASE2_TRACE.md` | Đồng bộ transaction IDs, unknown IP, timestamps, quality, queue và locations |

**11. Các mốc triển khai và điều kiện qua mốc**

| Mốc | Công việc | Đầu ra kiểm chứng |
|---|---|---|
| P1.0 | Chốt contracts/schema, config fixture và PCAP chuẩn | Mô tả bytes/timestamps/token/flag kỳ vọng độc lập với implementation |
| P1.1 | Skeleton, migrations, DB writer, CLI import | DB mở lại được; rollback commit lỗi; import lặp không tăng dữ liệu |
| P1.2 | Go reassembly + HTTP framing và Python adapter | Đúng raw request/response trên retransmit, pipelining và nhiều PCAP |
| P1.3 | Tagger, structured parse, token, decoder, flag | Bảng token đúng location; checker tách đúng; unknown IP vẫn được giữ |
| P1.4 | Durable queue + recovery/checkpoints | Kill/restart ở các điểm commit không mất/nhân đôi transaction hoặc job |
| P1.5 | Baseline, flag IDs, API/status | API lọc đúng đội/service; baseline có sample count; không có flag-ID source vẫn ingest |
| P1.6 | Capture handoff + retention + Compose/host agent | File đang ghi không bị đọc; file cần replay không bị dọn; bật/tắt giữ DB |
| P1.7 | End-to-end, hiệu năng, offline bundle, docs | Bộ acceptance bên dưới đạt, có số đo và giới hạn được ghi lại |

P1.0–P1.4 chạy với PCAP local và DB tạm trước. Chỉ chuyển sang capture live khi P1.6 đạt; việc viết code không tự kéo theo deploy lên vulnbox hiện tại.

**12. Bộ kiểm thử nghiệm thu**

1. Fixture `notes`: checker put/get flag, Team 5 register/login/upload/read; đúng thứ tự transaction, token session/file ID, subtoken `7731`, và job cho response cuối. Không phụ thuộc numeric ID 105 của ví dụ.
2. Chia header/body/flag qua nhiều packet; retransmit và out-of-order không lặp bytes/token/flag.
3. Một connection qua ít nhất hai PCAP; restart giữa hai file cho kết quả tương đương chạy liền.
4. Hai connection xen kẽ cùng đội, hai đội dùng cùng token, một đội nhiều IP, hai IP chưa map: source identity và lookup không bị trộn.
5. HTTP framing: pipelining, HEAD, 100 Continue, chunked/trailers, gzip/deflate/br, JSON/form/multipart và header/query trùng.
6. Raw TCP nhiều lượt, missing SYN/FIN, packet gap, port reuse, binary và encrypted traffic: quality phản ánh đúng dữ liệu thiếu/không hỗ trợ.
7. Flag plain/base64/nén, nhiều flag trong một response, regex có groups, checker response, echo cùng transaction, flag sau vùng lưu bị cắt.
8. Location/representation: ký tự đặc biệt trong tên JSON key, query/form lặp, JWT/base64 token và phép biến đổi không đảo ngược.
9. Fault injection: chết trước/sau commit, Go helper chết, SQLite busy, Redis mất, PCAP lỗi, file ship dở, decoder vượt budget. Lỗi một file không âm thầm làm mất cả queue.
10. Retention: pin/release qua restart, thiếu đĩa và staging backlog, PCAP hết hạn nhưng record DB còn; trạng thái degraded phải nhìn thấy.
11. Regression: rule-generator tests hiện có; decoder parity; config cũ không có Flag-trace; MODE=contest không kéo fixture prep vào runtime.
12. End-to-end Compose bằng fixture, restart container, đọc API; offline start từ image đã save với network fetch bị tắt.

Số đo phải ghi: packet/s, transaction/s, CPU/RAM, DB/WAL/traffic growth, ingest backlog, thời gian phục hồi và độ trễ từ packet tới commit. Mục tiêu `<10s cho PCAP 60s` chỉ có ý nghĩa khi nêu kích thước, packet/connection count và máy đo. Tách capture delay, ship delay, ingest delay; chưa cam kết latency sub-second cho luồng xoay file.

Thông tin còn cần khi bật live: game start/tick thật, IP checker, mapping đội, capture point/port thực tế và định dạng API flag IDs nếu có. Dùng fixture để phát triển trước; các thông tin này không chặn việc triển khai và kiểm thử offline.
