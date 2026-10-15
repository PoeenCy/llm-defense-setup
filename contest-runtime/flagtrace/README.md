# Flag-trace runtime

Tài liệu thiết kế và nghiệm thu nằm ở [`flag-trace/`](../../flag-trace/). File này chỉ mô tả cách chạy.

## Hai service, một image, một file SQLite

| Service (container) | Lệnh | Việc làm | Ghi DB |
|---|---|---|---|
| `flagtrace` (`ctf-flagtrace`) | `run` | Ingest PCAP đã đóng trong `traffic/`, phục vụ API nội bộ `:8095` | transactions, tokens, `trace_queue`; sở hữu schema |
| `flagtrace-worker` (`ctf-flagtrace-worker`) | `trace` | Dispatch flag-out → hồ sơ + job, claim/lease, chạy engine, commit run | `trace_*` |

Image: `ctf-flagtrace:phase2`. DB: `data/flagtrace/flagtrace.sqlite3`. Worker không mount PCAP, Docker socket hay SSH.

## Config (`services.json`)

```json
"flagtrace": {
  "enabled": true,
  "trace": { "enabled": true }
}
```

- `flagtrace.enabled` cần `game.id`, `game.start_time` (có timezone), `game.tick_seconds`, `game.checker_ips` và `teams[].ips`.
- `flagtrace.trace.enabled` yêu cầu `flagtrace.enabled`. Các giới hạn thuật toán và giá trị mặc định nằm trong `TRACE_DEFAULTS` ở [`app/config.py`](app/config.py); chúng là **giá trị khởi đầu để tune**, chưa benchmark.
- `same_service_only` phải là `true` — trace chéo service chưa được nghiệm thu nên bị từ chối.
- **Flag ID** (để gán vai trò `target`) có ba nguồn, đều ghi vào bảng `flag_ids`:
  - Tự động, không cần config: lấy từ phiên putflag của checker vào box mình (`game.checker_ips` phải đúng). Chỉ giữ vị trí có giá trị đổi qua các tick, cập nhật mỗi tick.
  - `flagtrace.flag_ids_url`: poll mỗi tick, endpoint phải trả danh sách `{"tick","service","owner_team_id","value"}`. API của giải có format khác thì cần adapter.
  - `import-flagids <file.json>`: nạp tay cùng format.
- Chỉ so với flag ID của đội mình (`team_id` ở đầu `services.json`). `game.flag_validity_ticks` (tùy chọn) là số tick một flag còn hiệu lực theo luật giải; không có thì flag ID của mọi tick trước đều được chấp nhận và kết quả ghi rõ điều đó.
- Mỗi job lưu snapshot cấu hình thuật toán lúc được tạo. Đổi `poll_seconds`/`lease_seconds`/`max_attempts` không đổi `algorithm_hash`, nên không làm kết quả cũ bị coi là lỗi thời.
- `flagtrace.decoder_mode` (mặc định `full`) là chế độ decoder khi ingest; xem mục [Decoder khi bị tải nặng](#decoder-khi-bị-tải-nặng).

Kiểm tra: `bash contest-runtime/config/validate-config.sh`.

## Mở flow trong Tulip

Mỗi bước trên Timeline là một flow của Tulip; cột **Tulip** link thẳng tới nó để xem byte thô, tag và traffic xung quanh. Khớp được làm **lúc hiển thị** qua `/api/tulip/resolve` (cửa sổ thời gian + IP/port, cộng chuỗi flag ở anchor), **không lưu flow ID vào kết quả** — ingest lại capture không để lại ID cũ sai. `✓` là khớp đúng IP, `~` là flow gần nhất theo thời gian (tooltip ghi lý do). Tulip không tới được thì cột ghi lý do sau 20 s chứ không treo.

## Gom nhóm chain và bước đáng ngờ (P2.4b)

Mục đích là phòng thủ: biết **bug nào đang bị khai thác nhiều** để ưu tiên vá hoặc viết rule, và **bước nào trong chain là bất thường**.

- **Nhóm** = các chain cùng *cấu trúc*: cùng dãy bước, mỗi bước cùng method, cùng path đã chuẩn hóa (`path_template`, dùng chung với baseline) và cùng *tên* các field. Giá trị không tham gia, nên đổi session/username/file ID mỗi lần vẫn chung nhóm, và cùng một khai thác do đội khác dùng cũng vào chung nhóm. Vai trò giá trị (B6) cũng không tham gia, để nhóm không phụ thuộc vào suy luận có thể dùng chính nhóm làm căn cứ.
- **Đếm theo hồ sơ, qua run mới nhất**: phân tích lại không làm tăng số đếm, và hồ sơ có chain đổi sẽ chuyển sang nhóm tương ứng. Nhóm chỉ có nghĩa là các chain *giống nhau*, không khẳng định chúng khai thác cùng một bug.
- **Bảng biến thiên field** là thứ một chain đơn lẻ không nói được: field nào mọi chain đều gửi y hệt (hằng do attacker chọn, script giữ nguyên) và field nào mỗi lần một khác (phải lấy từ response hoặc tự sinh). Bảng này đọc thẳng request của từng chain, không đọc vai trò giá trị, vì giá trị mà mọi chain đều gửi giống nhau bị xếp `constant` nên không được lưu.
- **Bước đáng ngờ** = so với baseline dựng từ chính request của checker (`game.checker_ips` phải đúng): endpoint checker không gọi, field checker không gửi, giá trị dài bất thường, hoặc **loại ký tự** checker không dùng ở field đó. Chỉ xét loại ký tự, không xét từng ký tự: giá trị của checker cũng ngẫu nhiên nên không phủ hết bảng chữ, và bắt theo từng ký tự sẽ đánh dấu mọi bước.
- **Mức tin cậy**: dưới `MIN_SAMPLES` (20) mẫu thì finding là `weak`; không có baseline thì **không bước nào bị đánh dấu** và kết quả ghi rõ lý do. Mỗi finding lưu kèm số mẫu đã đối chiếu, nên dựng lại baseline sau đó không làm đổi kết quả cũ.
- Run cũ (trước `p2.5.1`) không có nhóm; worker tự xin phân tích lại một lần cho mỗi hồ sơ, theo trigger có version (`auto:grouping:<normalizer>`).

## Decoder khi bị tải nặng

Decoder (base64, gzip, xor…) chiếm phần lớn CPU của ingest nhưng bắt được những flag-out mà body thô không lộ ra (43/95 flag-out của dataset A). Có ba chế độ:

| Chế độ | Làm gì | Dataset A (713 transaction) | Dataset B (4100 transaction) |
|---|---|---|---|
| `full` (mặc định) | Decode mọi body | 16,0 s · 95 flag-out | 73,4 s · 2000 flag-out |
| `gated` | Chỉ decode body mà `looks_encoded()` coi là đã mã hóa (cùng bộ lọc với detection) | 12,8 s · 95 flag-out | 16,0 s · 2000 flag-out |
| `off` | Không decode | 7,7 s · **52** flag-out | 13,1 s · 2000 flag-out |

- **Đổi trên dashboard**, tab FLAG TRACE, ô *Ingest decoder*. Không cần restart: ingest đọc chế độ trước mỗi file PCAP, nên chế độ mới áp từ file kế tiếp. Chọn `off` phải xác nhận.
- **Chế độ đặt từ dashboard được giữ qua restart** (bảng `runtime_settings`) cho tới khi đổi lại hoặc bấm *Back to config default*. Khi khác `full`, System Status có mục *Flag-trace decoder* màu vàng, nên không bị quên.
- `gated` có thể sót kiểu mã hóa ra chữ đọc được (ví dụ XOR làm đổi hoa/thường), nên nó là bước hạ đầu tiên khi tải nặng, không phải mặc định.
- **Không coi "không có flag" là kết luận** ở chỗ decoder bị hạ: transaction ghi quality `req:`/`resp:decoder_gated` hoặc `decoder_off`, run có cảnh báo, và mỗi file PCAP ghi chế độ của lần đọc gần nhất (`pcap_files.decoder_mode`).
- **Body giống hệt nhau chỉ decode một lần:** kết quả được cache theo hash nội dung, trong RAM, có giới hạn (4096 entry, 64 MB). Mỗi transaction vẫn lưu bằng chứng riêng. Kết quả hết `decode_budget` không được cache.
- **Replay sau restart không tốn CPU:** transaction đã có trong DB bị bỏ trước khi parse/decode (`duplicates_skipped` trong `/status`). Replay toàn bộ dataset A: 12,7 s → 0,3 s.

## Lệnh

Chạy trong container (`docker compose run --rm --no-deps flagtrace python -m flagtrace.app.main <lệnh>`) hoặc local với `PYTHONPATH=contest-runtime`.

| Lệnh | Dùng khi |
|---|---|
| `migrate --check` | In version trên đĩa/của image; exit `3` nếu cần nâng schema |
| `migrate` | Nâng schema khi **cả hai writer đã dừng**; backup nhất quán vào `/data/backups/` trước khi nâng |
| `trace` | Vòng lặp worker (entrypoint của `flagtrace-worker`) |
| `trace-once [--mode seed]` | Một lượt dispatch/claim/phân tích, cùng engine và đường persist với worker |
| `worker-health` | Healthcheck của worker: heartbeat của chính nó còn mới |
| `status` | Trạng thái ingest + trace |
| `ingest --traffic DIR --db FILE --finalize` | Ingest offline một thư mục PCAP |
| `import-flagids FILE` | Nạp flag ID từ file JSON (danh sách `{"tick","service","owner_team_id","value"}`) |
| `verify-script ARTIFACT --fixture NAME --target 127.0.0.1 [--port N] [--flag-id ID] [--expect FLAG]` | Chạy **chain supported** trên fixture loopback và ghi verification gắn với artifact hash; không nhận target từ xa |

## Triển khai và đường lui

`bringup.sh` làm đúng thứ tự sau:

1. Build image mới (hoặc dùng image đã load khi `--offline`).
2. `migrate --check` bằng image mới. Nếu cần nâng: dừng `flagtrace` và `flagtrace-worker` → `migrate` (tự backup) → khởi động lại.
3. Bật `flagtrace`; bật `flagtrace-worker` chỉ khi `trace.enabled=true`, ngược lại dừng worker (ingest vẫn chạy, hồ sơ/job/lịch sử giữ nguyên).

Đường lui vận hành là **tắt `flagtrace.trace.enabled`**. Image cũ không đọc được DB đã nâng version: Phase 1 cần backup `data/flagtrace/backups/flagtrace-v2-*.sqlite3`, image Phase 2 trước P2.4 (schema v3) cần `flagtrace-v3-*.sqlite3`, image trước chế độ decoder (schema v4) cần `flagtrace-v4-*.sqlite3`, image trước exporter P2.5 (schema v5) cần `flagtrace-v5-*.sqlite3`.

## API (proxy qua dashboard dưới `/api/flagtrace/...`)

| Route | Nội dung |
|---|---|
| `GET /traces?source_key=&service=&team_id=&tick=&state=&limit=&cursor=` | Danh sách hồ sơ, mới nhất trước; cursor `<ts_request>:<trace_id>` |
| `GET /traces/{id}` | Anchor, kết quả mới nhất, các yêu cầu phân tích gần đây |
| `GET /traces/{id}/runs` | Lịch sử kết quả |
| `GET /traces/{id}/runs/{run_id}` | Steps, edges, coverage, warnings, metrics, `value_roles` và metadata `scripts`; run cũ hơn mốc tương ứng trả `not_computed` |
| `GET /traces/{id}/runs/{run_id}/scripts/{artifact_id}` | Nội dung một artifact đã scope theo game/trace/run; route riêng để run detail không tải toàn bộ script |
| `GET /transactions/{id}/evidence[?run_id=]` | Parsed fields, representations (base64, có cờ cắt), tokens, flag sightings |
| `GET /trace-status` | Heartbeat worker và backlog (chờ dispatch / pending / running / failed) |
| `POST /traces/{id}/retrace` `{"idempotency_key": "..."}` | Tạo job phân tích mới (202). Gửi lại cùng key trả cùng job; worker tắt → 409 |
| `GET /decoder` | Chế độ decoder đang áp dụng, nguồn (`config`/`dashboard`), mặc định trong config, chế độ của file gần nhất, thống kê decoder/cache từ lúc ingest khởi động |
| `POST /decoder` `{"mode": "full"\|"gated"\|"off"\|"default"}` | Đặt chế độ (giữ qua restart); `default` xóa giá trị đặt tay và quay về config |
| `GET /trace-groups?source_key=&service=&team_id=&state=&limit=&offset=` | Flag-out giống hệt nhau gộp một dòng: cùng nguồn, service, flag và request (method + path, không tính query). Mỗi nhóm có số hồ sơ, lần đầu/lần cuối, tick, đếm trạng thái, các kiểu kết quả và hồ sơ đại diện (chain nối nhiều bước nhất, hòa thì mới nhất) |
| `GET /trace-groups/{trace_id}/members?limit=&offset=` | Các hồ sơ cùng nhóm với `trace_id`, mới nhất trước |
| `GET /chain-groups?service=&source_key=&limit=&offset=` | Nhóm chain cùng cấu trúc (P2.4b): mô tả, số hồ sơ, số nguồn, số hồ sơ có bước lệch baseline |
| `GET /chain-groups/{group_id}?limit=&offset=` | Chi tiết nhóm: cấu trúc từng bước, nguồn, bảng biến thiên field, danh sách hồ sơ |

Dashboard chỉ chuyển tiếp các route trên; mỗi POST chỉ mang `idempotency_key` hoặc `mode`.

### Script artifact (`scripts`, P2.5)

- Mỗi run mới từ engine `p2.5.0` lưu một Python artifact cho từng request và một artifact cho HTTP chain. Exporter hiện tại là `p2.5.1` (có fallback raw-DEFLATE); artifact gắn `run_id`, exporter version và SHA-256; nâng exporter không sửa run cũ.
- Worker tự tìm latest run `linked` chưa có chain artifact và enqueue một run mới bằng trigger versioned `auto:scripts:<exporter_version>`. Việc tải bù chạy theo batch, idempotent qua poll/restart và không sửa run cũ; vì vậy một run lịch sử vẫn có thể trả `not_computed` trong khi latest run đã có Copy.
- Request đơn gửi raw HTTP/1 bytes đã capture nên giữ body binary, multipart boundary, duplicate header/query/form và encoding. Raw bị storage-truncated thì `unsupported`.
- Chain patch đúng byte range đã xác định, giữ phần còn lại nguyên văn và sửa `Content-Length`; host là tham số, port mặc định là `dst_port` của từng transaction. `linked` được bóc từ response, `generated` chỉ sinh khi suy được format, `target` là `flag_id`.
- `supported` chỉ nói exporter không thấy giới hạn đã biết. `needs_edit` dùng cho unknown/ambiguous/JWT, span/encoding không chắc, trace partial hoặc dữ liệu ingest ở decoder `gated/off`. `unsupported` dùng khi thiếu raw bytes hoặc raw TCP chưa có turn/span mapping.
- `reproduced` chỉ xuất hiện sau lệnh `verify-script` chạy đúng artifact hash trên fixture loopback. Dashboard chỉ copy/download; không có đường chạy script vào service thi đấu.

## Đọc kết quả

- `linked` = engine chạy hết trên dữ liệu có lúc đó, **không** có nghĩa đã tìm đủ hay tái hiện được exploit. `partial` = dừng vì giới hạn (xem `coverage.limits_hit`). `seed_only` = chỉ lưu anchor.
- Kết quả chỉ gồm **flow**: bước `anchor` (flag-out) và các bước `data_linked` (có cạnh giá trị nối tới flow). Traffic chỉ gần về thời gian hoặc chung connection không phải bằng chứng nên không được đưa vào; flag-out một request (không cần đăng nhập) là kết quả 1 bước. Run của engine trước `p2.3.2` có lưu thêm bước `context`; API và UI bỏ qua các bước đó. Vai trò không khẳng định request đó khai thác bug.
- Cạnh `response_to_request`: response trước đó mang giá trị. Cạnh `request_reuse`: suy nguồn từ lần đầu giá trị xuất hiện trong request ở trường cùng loại (ví dụ register → login). Lặp lại cùng trường của cùng endpoint (payload hằng của exploit) không tạo cạnh mà ghi `repeated_in_same_step`.
- Giá trị không giải thích được nằm trong `coverage.unexplained` kèm lý do; file capture bị reject/lỗi/late của game nằm trong `coverage.ingest_gaps` và cảnh báo.
- Traffic đến muộn không tự kích hoạt phân tích lại trong bản này: dùng **Re-analyse**; kết quả cũ vẫn xem được. Auto-backfill script chỉ áp dụng cho latest run đã `linked` nhưng thiếu artifact, không phải cơ chế retrace mọi thay đổi dữ liệu.

### Vai trò giá trị (`value_roles`, B6)

Mỗi field trong request của các bước được gán một vai trò, tức là cách một script lấy được giá trị đó:

| Vai trò | Khi nào | Script làm gì |
|---|---|---|
| `linked` | Có cạnh `response_to_request` (hoặc chuỗi `request_reuse` bắt đầu từ một response) | Bóc từ response nguồn (`evidence.from`); cookie thì có cờ `session_cookie` |
| `generated` | Không có nguồn, attacker gửi trước rồi dùng lại ở bước sau (register → login) | Tự sinh giá trị mới, cùng biến (`var`) ở mọi chỗ dùng |
| `target` | Không có nguồn và khớp flag ID của đội mình | Tham số `flag_id` |
| `unknown` | Trông như ID (số/hex/chuỗi ngẫu nhiên), không có nguồn, không khớp flag ID | Cần người xem |
| `constant` | Còn lại | Gửi nguyên văn; chỉ đếm, **không liệt kê** |

- Một phần của giá trị có thể là biến: `../../notes/7731.txt` thành `template` `../../notes/{flag_id}.txt` (cú pháp `str.format`), `parts` ghi vị trí từng biến. Trong base64 thì template là của chuỗi đã decode và `transform: ["base64"]`; trong claim JWT thì `unresolved: "jwt_unverified"` (không ký lại được).
- Căn cứ khớp flag ID (`evidence.basis`), mạnh nhất trước: `same_put_session` (đúng phiên putflag đã đặt flag bị lấy), `put_tick` (flag ID của tick đặt flag đó), `validity_window`, `earlier_tick` (không có cửa sổ hiệu lực).
- `flag_ids.status`: `available`, `none_for_scope` (có flag ID nhưng không cho service/đội này) hoặc `none`. Khi không có nguồn flag ID nào, **không giá trị nào được gọi là `target`**; giá trị lẽ ra là target sẽ thành `unknown`. Flag ID bị từ chối vì thời gian (ngoài cửa sổ, công bố sau request) nằm trong `flag_ids.refused`.
- Flag ID ngắn (dưới 4 ký tự) vẫn được so trên field đã parse nhưng gắn `ambiguous`.
- Bước mà engine chưa mở (giới hạn depth/budget) nằm trong `steps_not_classified`; khi đó `state` là `partial`.
- Flag ID từ checker được dựng lại mỗi tick. Flag-out phân tích trước lần dựng đó (đặc biệt ở 1–2 tick đầu giải) có thể chưa thấy flag ID: dùng **Re-analyse** sau.

## Mức hỗ trợ hiện tại

- Nối tự động: HTTP với dữ liệu có cấu trúc (cookie, header chọn lọc, path, query, form, JSON, multipart) và body tự do.
- Raw TCP: có hồ sơ, anchor và evidence; token lấy từ body gộp mỗi chiều nên liên kết thô hơn.
- Vai trò giá trị: field có cấu trúc của HTTP, body tự do và payload raw TCP (flag ID tìm theo chuỗi con có biên).
- Gom nhóm chain và bước lệch baseline: HTTP. Chain raw TCP vào nhóm theo số bước (không có dòng request để so), và không được so với baseline.
- Chưa có: raw-TCP replay, sự kiện realtime và retention cho trace (phần còn lại của P2.6).

## Test

```bash
cd contest-runtime/flagtrace/transport && GOPROXY=off go build -o /tmp/flagtrace-transport .
cd ../.. && FLAGTRACE_TRANSPORT=/tmp/flagtrace-transport python3 -m unittest discover -s flagtrace/tests
```
