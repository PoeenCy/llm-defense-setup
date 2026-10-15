# Flag-trace — Báo cáo Phase 2 đợt đầu (P2.0–P2.3)

Ngày: **2026-10-14**. Kế hoạch: [PHASE2_IMPLEMENTATION_PLAN.md](PHASE2_IMPLEMENTATION_PLAN.md). Cách chạy: [contest-runtime/flagtrace/README.md](../contest-runtime/flagtrace/README.md).

**Kết luận ngắn:** P2.0–P2.3 đã được triển khai và nghiệm thu: 63 unit/integration test (22 Phase 1 + 41 Phase 2) và 27 kiểm tra trên browser thật đều pass, phủ đủ A1–A12. **Đã kiểm chứng thêm trên môi trường thật (2026-10-14):** build full framework end-to-end bằng `MODE=contest bash deploy-all.sh` (Docker thật), nâng schema v2→v3 trong container, và chạy engine trên capture thật — cả **dataset A** (DB Phase 1 có sẵn, 95 flag-out) lẫn **dataset B** (bắt live trên `lo:8090` của target DTFC2023 local, hai/ba nguồn). Chi tiết ở mục 9–10. Sáu sửa đổi phát sinh từ dữ liệu thật (mục 9.3), gồm việc nối nguyên JWT token qua `Authorization: Bearer`. Còn lại: tối ưu throughput và các điều kiện live đầy đủ thuộc P2.6.

## 1. Phiên bản và input

| Mục | Giá trị |
|---|---|
| Base commit | `d65fa11` + thay đổi chưa commit trên nhánh `feat/decode-dashboard-detection` |
| Engine | `p2.3.1` (`trace/contracts.py`) |
| Schema SQLite | v3 (v1 → v2 → v3; v3 thêm bảng `trace_*`, `pcap_rejects`, cột `pcap_files.attempts`) |
| Image | `ctf-flagtrace:phase2` (hai entrypoint `run` và `trace`) |
| `tests/fixtures.py` | sha256 `8155433cb20346dd92ca73a748e5ea8d3103529aac5da016ff0223430b73ec1f` |
| `tests/test_trace.py` | sha256 `7a3c0a04be50076b008d15431574b3d2a3a6e765c47b21918ebe662f9017bedb` |
| `tests/test_ingest.py` | sha256 `0adacaa969621d3a02cee474d06799ec508eed661b9bd823bab8c05cea4615d5` |
| Môi trường test | Python 3.14.7, Go transport build local, Chromium headless 1243 qua Playwright 1.64 |

## 2. Đã làm theo mốc

| Mốc | Nội dung | File chính |
|---|---|---|
| P2.0 | Contract 3 identity (transaction/trace/run), enum job/run/role/edge, `not_computed` cho P2.4/P2.5; fixture tách connection, noise, request sau anchor, hai script xen kẽ, 4 nguồn chung token, multi-flag, dữ liệu cắt/gzip, checker, HTML/script, tài khoản cũ nhiều tick, response treo | `trace/contracts.py`, `tests/fixtures.py` |
| P2.1 | Migration v3 tách khỏi `Store`; repository (dispatch, claim/lease/fencing, retry/backoff, commit idempotent, latest pointer theo sequence); worker + heartbeat riêng; CLI `migrate [--check]` (tự backup), `trace`, `trace-once`, `worker-health`; cô lập PCAP hỏng; Compose service `flagtrace-worker`; bringup migrate-trước-khi-chạy; registry/config apply/health/save/restore | `migrations.py`, `trace/repository.py`, `trace/worker.py`, `main.py`, `ingest.py`, `docker-compose.contest.yml`, `bringup.sh`, `hostagent/*`, `health_check.py` |
| P2.2 | API `/traces`, `/traces/{id}`, `/runs`, `/runs/{run}`, `/transactions/{id}/evidence`, `/trace-status`; proxy dashboard theo allowlist; tab **FLAG TRACE** (danh sách, timeline, value links, evidence, lịch sử run, deep link `#flagtrace/<trace>[/<run>]`, polling chỉ khi tab mở) | `trace/routes.py`, `api.py`, `dashboard/app/routes/flagtrace.py`, `dashboard/static/js/flagtrace.js`, `main.js` |
| P2.3 | Engine BFS có budget (depth/nodes/edges/tokens/candidates/rows/thời gian), `response_to_request` + `request_reuse`, ambiguity/alternatives, context cùng connection/burst giới hạn trước anchor, coverage + unexplained + capture gaps; `POST /traces/{id}/retrace` có idempotency key | `trace/engine.py`, `trace/routes.py` |

## 3. Lỗi tìm ra trong lúc nghiệm thu và đã sửa

| Lỗi | Hậu quả | Sửa |
|---|---|---|
| `Ingestor.run` gọi `store.status(state=..., **{"state": "degraded"})` | Mọi lượt có file PCAP bị reject/lỗi đều ném `TypeError`: đường "file hỏng không chặn file tốt" của P2.1 chưa từng chạy được | Gộp dict trước khi truyền |
| `request_reuse` nối mọi lần dùng giá trị trong request | Hai script cùng đội gửi cùng payload hằng (`../../notes/7731.txt`) bị nối, BFS kéo cả chain script 1 vào hồ sơ script 2 (vi phạm A3) | Không coi lặp lại cùng trường của cùng endpoint (path đã template) là chuyển giao; ghi `repeated_in_same_step` |
| Path segment trông như chữ bị bỏ (`endpoint_literal`) | File ID như `dgfile`, `hxfile01` mất cạnh `json.id → path` | Literal vẫn được nối khi một **trường response có cấu trúc** tạo ra đúng giá trị đó; không dùng fallback reuse |
| Engine đọc config đang chạy thay vì snapshot của job | Run ghi `algorithm_hash` của job nhưng có thể chạy theo config khác sau restart | Engine nhận `algorithm_config` của job; analysis ghi đúng config đã dùng |
| `release()` báo `failed` khi lease đã mất | Worker đếm sai lỗi | Trả `lost`, không đổi gì |
| UI: Back từ run cũ về `#flagtrace/<trace>` vẫn giữ run cũ | Địa chỉ và nội dung lệch nhau | Route là nguồn sự thật cho run đang xem |
| UI: nhãn "highlighted" cho representation chứa token không có byte span | Gợi ý sai rằng có vùng được tô | Ghi "holds the linked value (see Values)" |

## 4. Ma trận nghiệm thu A1–A12

Tất cả test chạy trên DB tạm với ingest thật (Go transport), không mock đường dữ liệu.

| Mã | Test | Kết quả |
|---|---|---|
| A1 | `test_a1_same_connection`, `test_a1_one_connection_per_step` | Pass — cùng core steps/edges; bản tách connection chứng minh nối bằng dữ liệu (4 connection, không có lý do `same_connection`) |
| A2 | `test_a2_noise_is_context_and_future_is_excluded` | Pass — rác trong burst chỉ là `context`; request sau anchor không vào |
| A3 | `test_a3_interleaved_scripts_stay_apart` | Pass (sau khi sửa lỗi ở mục 3) |
| A4 | `test_a4_sources_do_not_cross`, `test_checker_traffic_never_links` | Pass — 2 đội + 2 IP chưa map, mỗi hồ sơ chỉ chứa nguồn của nó; checker không vào chain |
| A5 | `test_a5_old_account_and_nearest_source`, `test_a5_equal_sources_are_ambiguous_and_stable`, `test_a5_equal_time_across_connections_is_not_ordered` | Pass — nguồn gần nhất, alternatives, ambiguity ổn định qua retrace, timestamp bằng nhau khác connection bị từ chối có lý do |
| A6 | `test_a6_multiple_flags_one_profile_per_anchor` | Pass |
| A7 | `test_a7_replayed_capture_and_retrace_identity`, `test_a7_crash_before_commit`, `test_a7_crash_after_commit` | Pass — crash bằng `os._exit` trong process con thật |
| A8 | `test_a8_stale_lease_cannot_commit`, `test_a8_latest_pointer_never_moves_back`, `test_a8_failing_job_is_bounded_and_others_continue`, `test_a8_busy_database_degrades_then_recovers` | Pass |
| A9 | `test_a9_incomplete_evidence_is_visible`, `ApiTests.test_missing_response_and_storage_cut` | Pass |
| A10 | `test_a10_late_transaction_needs_a_new_run` | Pass — response treo làm transaction đến sau trace; run cũ giữ nguyên, retrace thấy nguồn mới |
| A11 | `test_a11_repeated_fields_and_captured_markup`, `ApiTests.test_captured_markup_is_returned_as_data`, browser `markup rendered as text / no element injected / no alert executed` | Pass |
| A12 | `test_a12_budgets_cut_results_visibly`, `test_a12_deadline`, `test_a12_analysis_holds_no_write_lock` | Pass — 5 giới hạn + deadline cho kết quả `partial` có lý do; trong lúc phân tích, connection khác vẫn lấy được write lock |

Bổ sung: migration Phase 1 → v3 giữ queue pending và chạy lại không nhân đôi; `migrate --check`/backup; `worker-health`; validate config trace; PCAP không đọc được và PCAP có record cắt không chặn file sau và hiện trong `coverage.ingest_gaps`.

## 5. Kiểm tra trên browser thật (P2.2)

Script trong repo: `contest-runtime/dashboard/tests/flagtrace_ui/` (`serve_fixture.py` + `check.py`). Dashboard FastAPI thật + API Flag-trace thật trên DB fixture; 27/27 kiểm tra pass:

- Danh sách 4 hồ sơ, hồ sơ có yêu cầu mới đang `pending` vẫn hiện kết quả cũ; trạng thái worker "no worker".
- Mở hồ sơ → hash `#flagtrace/<id>`; timeline có anchor + data-linked; lịch sử 2 run; chọn run cũ → deep link có run ID, reload giữ đúng run, Back về kết quả mới nhất.
- Bấm value link → hai thẻ evidence nguồn/đích, token được tô ở bảng Values, hai step được chọn trên timeline.
- Payload `<script>`/`onerror` hiện dưới dạng text, không có element bị chèn, không `alert` nào chạy.
- Re-analyse tạo request mới; các tab Events/Rules/Services/Monitor vẫn route đúng; polling dừng khi rời tab; hồ sơ không tồn tại báo rõ; không có lỗi JS.

## 6. Giới hạn còn lại

- **Throughput Phase 1 chưa tối ưu** (P2.6): decoder chiếm phần lớn CPU, DB lớn ~12–15× PCAP. Chưa đo trên tải giải thật; thời gian *engine* trên dữ liệu thật median ~1,4 ms/job (dataset A, mục 9).
- Heuristic `request_reuse` dựa trên "trường cùng loại, khác bước". Giá trị do client tự sinh trùng nhau giữa hai bước khác nhau vẫn có thể nối nhầm; cạnh luôn ghi rõ là suy nguồn.
- Context theo burst có thể chứa bước của script khác cùng đội; chúng chỉ mang vai trò `context`, không có cạnh.
- Token header/cookie/path/JSON không có byte span: UI tô dòng trong bảng Values, không tô vị trí trong bytes.
- Raw TCP: có hồ sơ/evidence, liên kết thô do token gộp theo chiều (đúng như kế hoạch, nghiệm thu riêng).
- Retrace chỉ thủ công; tự retrace khi input đổi thuộc P2.6. `extend_lease` có sẵn nhưng chưa dùng vì budget thuật toán nhỏ hơn lease (validator bắt buộc).

## 7. Cách chạy lại

```bash
cd contest-runtime/flagtrace/transport && GOPROXY=off go build -o /tmp/flagtrace-transport .
cd ../.. && FLAGTRACE_TRANSPORT=/tmp/flagtrace-transport python3 -m unittest discover -s flagtrace/tests
# Browser: xem docstring của contest-runtime/dashboard/tests/flagtrace_ui/serve_fixture.py
```

## 8. Bước tiếp theo

1. Đo và tối ưu throughput Phase 1 trên tải giải thật (P2.6).
2. Mở P2.4 (vai trò giá trị, gom nhóm) và P2.5 (export script), dùng dataset A/B làm mẫu đánh giá.

## 9. Chạy thật end-to-end (2026-10-14)

Môi trường: WSL2, Docker Desktop 29.0.1. Không có SSH tới vulnbox, nên capture/ctf_proxy bị bỏ qua (đúng thiết kế); phần monitor chạy đủ.

**9.1 Build full framework.** `MODE=contest bash deploy-all.sh` → exit 0. Tulip (7 container), detection, dashboard, watchdog, redis đều UP; health check bước 7 báo UP cho Redis/Detection/Dashboard/Tulip. Các bước capture/honeytoken/ctf_proxy tự bỏ qua vì `dfcd-vbox` không reachable, không đụng máy nào. Image `ctf-flagtrace:phase2` build riêng bằng lệnh trong `pull-and-save.sh`.

**9.2 Nâng schema trong container.** Trên bản sao DB Phase 1 thật (713 transaction, v2):
- `migrate --check` → exit 3 (nhận đúng cần nâng).
- `migrate` → backup nhất quán vào `/data/backups/flagtrace-v2-*.sqlite3`, nâng lên v3.
- `migrate --check` lại → exit 0. File gốc không bị đụng.

**9.3 Lỗi phát hiện trên dữ liệu thật và đã sửa** (engine `p2.3.0` → `p2.3.1`):

| Lỗi | Hiện tượng trên dataset A | Sửa |
|---|---|---|
| Fragment chữ bị nối | "image" tách từ `/image-sharing/` nối vào chữ "image" trong HTML và trong `image/png`, kéo mọi lần đọc flag thành chain dài (42/50 `partial`, nhiều edge rác giữa các lần đọc) | Giá trị trông-như-chữ tách ra từ value khác (`literal_fragment`) chỉ nối khi một trường response **có cấu trúc, không phải sub-token** tạo ra đúng giá trị đó; như endpoint literal |
| Context cắt bị coi là partial | Trần `max_nodes` chạm khi gom context (danh sách bước gần) làm run báo `partial` dù liên kết đã đủ (82/95) | Tách `context_limits_hit` khỏi `limits_hit`; state `partial` chỉ do giới hạn khi linking. UI hiện hai dòng riêng |
| Chất lượng context làm "bẩn" chain | Anchor sạch nhưng 67/95 run cảnh báo "incomplete capture" vì các bước **context** không liên quan | Tách `ingest_quality` (anchor + data-linked) khỏi `context_quality`; cảnh báo chỉ theo chain |
| `trace-once` không drain hết | Dispatch giới hạn mỗi poll → chỉ xử lý 50/95 job trong một lần | `run_once(drain=True)` lặp tick tới khi không còn gì mới, như vòng live |
| Context lấn át flow (64 step) | Flag-out một-request (flow 1 bước) hiện **64 step** vì `context` ăn chung ngân sách `max_nodes=64`, bị burst traffic dày một nguồn bơm đầy. Context là traffic gần đó, **không phải flow** (không vào script replay) | Thêm config `max_context` riêng (mặc định 8, `0` = tắt); `max_nodes` chỉ còn là ngân sách cho flow (anchor + data-linked). Dataset A: tối đa 9 step thay vì 64; flow data-linked không đổi |
| Token `Bearer <jwt>` không nối nguyên token | Request lấy flag mang `Authorization: Bearer <access_token>`: engine chỉ nối được các **mảnh** JWT (claim iat/exp/jti, phần base64), còn **nguyên token** rơi vào `no_source_in_scope` vì tiền tố `Bearer ` khác giá trị trần trong login response | `tokens.py` tách scheme (`Bearer`/`Token`/`Basic`...) khi extract header `authorization`, như cách cookie tách lấy value — nguyên token khớp đúng nơi phát hành |

Mỗi lỗi có test regression tương ứng (`test_word_fragments_and_constant_parameters_do_not_link`, `test_capped_context_is_not_a_partial_result`, `test_context_quality_does_not_degrade_the_chain`), đã xác nhận test đỏ trên code cũ.

## 10. Kết quả trên capture thật

**Dataset A — DB Phase 1 có sẵn** (`data/flagtrace/report-2026-10-14`, capture DTFC2023 local trên `lo:8090`, mọi nguồn `127.0.0.1`). Chạy `trace-once` trong container trên bản đã migrate:

| Chỉ số | Giá trị |
|---|---|
| Flag-out xử lý | 95/95, tất cả `done` + `linked` |
| Thời gian engine | median 1,4 ms · p95 1,7 ms · max 1,9 ms/job |
| `limits_hit` khi linking | 0 run (trước sửa: 42 run `partial`) |
| Anchor | 95× `GET /image-sharing/?f=<base64 path>` (file-read trả `DTFC{local_pha1_test}`) |
| Edge | 0 — đúng: tham số `f` là path hằng, đánh dấu `repeated_in_same_step`/literal; không nối các lần đọc độc lập |
| Tham số đọc | `/flag/flag` (×52), `g0.png`/`g1.png`/`g2.png`, `exfil.png` — giải mã base64 đúng |

Flag-out thật của target này là **đọc file một-request**, nên trace đúng là một-bước — khớp bản chất bug, không phải thiếu sót của engine. Mở trên dashboard đang chạy: 95 profile, chọn profile → timeline + evidence (byte thật, flag tô trong representation `decoded (deflate)`), **Re-analyse** tạo run #2 và giữ run #1 trong lịch sử.

**Dataset B — bắt live trong lúc container chạy.** `tcpdump` host-side trên `lo:8090` (dùng `cap_net_raw`, không sudo) trong khi sinh traffic bằng app bình thường (đăng ký→đăng nhập GraphQL lấy `access_token`→truy vấn có `authorization: Bearer`, cộng các lần đọc flag qua image-sharing) từ hai/ba địa chỉ loopback. Hai container `flagtrace` (`run`) + `flagtrace-worker` (`trace`) chạy live, `services.json` riêng bật `flagtrace.trace`.

| Kiểm tra | Kết quả |
|---|---|
| Ingest tự nhặt pcap `.ready` | pcap #1: 11 transaction, 5 profile; worker trace hết trong 2 poll |
| Auto-pickup khi đang chạy | thả pcap #2 (nguồn `127.0.0.3`) vào traffic dir lúc container live → ingest tự xử lý, +3 profile, tất cả `done` |
| Tách nguồn trên dữ liệu thật | 8 profile qua 3 nguồn `127.0.0.1/2/3`; mỗi run `scope.source_key` đúng nguồn của nó, context chỉ cùng nguồn, không nối chéo |
| Liên kết token response→request trên byte thật | `access_token` (JWT) bắt được là token `produced` ở response signIn; không tạo edge vì không flag-out nào mang nó — đúng (flag-out là đọc file, không authed) |
| Dashboard live | tab FLAG TRACE qua proxy allowlist hiển thị 8 profile, anchor cho thấy `GET /image-sharing/?f=L2ZsYWcvZmxhZw==` + header Signature, response flag `DTFC{local_pha1_test}`, coverage phân biệt "limits khi linking" vs "context bị cắt"; không lỗi JS |
| `worker-health` | exit 0 khi heartbeat tươi; healthcheck container PASS |

**Dataset B2 — chuỗi có xác thực, kiểm tra nối token.** Bắn register→login→(request lấy flag mang `Authorization: Bearer <access_token>` từ login) cùng một nguồn, bắt live. Kết quả: flag-out ra **`data_linked` chain** (register/login là data-linked, không phải context), và engine nối `access_token` (login response JSON) → `authorization` header của request lấy flag bằng **một edge nguyên token** (JWT 710 ký tự) cộng các edge claim phụ. Trước khi sửa `tokens.py`, nguyên token không nối được (chỉ nối mảnh); sau khi sửa, `Bearer` không còn trong `unexplained`. Đây là bằng chứng engine nối được pattern login→token→flag phổ biến của A/D trên capture thật — khi request lấy flag thật sự mang token. (Trên DTFC, đường lấy flag mặc định không cần token; token ở đây được gắn vào để kiểm tra khả năng nối.)

Hạn chế của phép đo live: target chỉ có **một** cleartext flag-out (đọc `/flag/flag`), không có chuỗi token→flag cleartext (flag trong DB là chuỗi XOR), nên liên kết nhiều bước **đến tận flag-out** không tái hiện được từ target này — phần đó do fixture A1–A5 phủ. Traffic đều từ loopback nên dạng gói đơn giản hơn qua NAT của giải thật.

## 11. Bỏ context — kết quả chỉ còn flow (2026-10-15, engine `p2.3.2`)

**Vì sao.** Đọc file không cần đăng nhập (flow 1 bước) trên dashboard vẫn hiện 64 step (run `p2.3.1` cũ, chưa phân tích lại sau khi thêm `max_context`), rồi 9 step khi chạy lại: toàn là traffic cùng nguồn ngay trước anchor (`context`), không có cạnh giá trị nào. Flag-trace chỉ cần cái gì **nối được bằng giá trị** tới flag-out; gần về thời gian hay chung connection không phải bằng chứng.

**Thay đổi.**
- Engine không thu thập context nữa: kết quả = anchor + các bước `data_linked`. Bỏ `max_context`, `context_window_seconds`, `burst_gap_seconds` (config cũ còn các key này bị từ chối kèm thông báo rõ); bỏ `context_limits_hit`, `context_quality`.
- Cạnh chỉ được giữ khi nguồn của nó là một step của kết quả. Trước đây khi chạm `max_nodes`, cạnh vẫn được lưu còn nguồn thì không: UI hiện `#?` và evidence trả 404.
- `ENGINE_VERSION` `p2.3.1` → `p2.3.2`, để run cũ và run mới phân biệt được.
- Run cũ vẫn trong lịch sử; API (danh sách, chi tiết run, lịch sử, evidence theo run) và UI bỏ qua các bước `context` đã lưu, UI đánh số step theo thứ tự hiển thị.

**Kiểm chứng.** 64 unit/integration test pass (bỏ 4 test riêng của context; thêm `test_one_request_flag_out_is_one_step`, `test_context_rows_of_older_runs_are_hidden`, và kiểm tra "mọi cạnh trỏ tới step có trong kết quả" trong A12); 28/28 kiểm tra browser. Deploy lên Docker và phân tích lại toàn bộ hồ sơ: 95/95 hồ sơ dataset A = **1 step**; chuỗi tổng hợp register → login → upload ảnh → đọc file (pcap thả vào `traffic/`, nguồn `127.0.0.9`) = **4 step, 5 cạnh**, request rác và request sau anchor không vào.

## 12. Worker im lặng khi có backlog (2026-10-15)

**Lỗi.** `Worker.tick()` xử lý hết hàng đợi trong một lượt rồi mới gửi heartbeat. Backlog dài hơn 60 s (ví dụ sau khi restart, hoặc job chạy gần hết `algorithm_budget_ms`) làm worker bị coi là chết đúng lúc bận nhất: UI báo `no worker`, `worker-health` fail; flag-out mới và lease hết hạn cũng phải chờ hết lượt.

**Sửa.** Mỗi lượt chỉ xử lý job trong tối đa `SLICE_SECONDS` (5 s, luôn ít nhất 1 job), rồi quay về vòng chính để gửi heartbeat, nhận flag-out mới, thu hồi lease; còn việc thì chạy tiếp ngay, không ngủ `poll_seconds`. Ngưỡng stale của `/trace-status` tính thêm `2 × lease_seconds` mà worker công bố, để một job dài hợp lệ không làm worker trông như đã chết. Test `test_backlog_is_worked_in_slices_with_heartbeats` (fail trên logic cũ, pass trên logic mới); 65/65 test pass; đã deploy, worker healthy.

## 13. P2.4a — Vai trò giá trị (2026-10-15, engine `p2.4.0`, schema v4)

**Làm gì.** Mỗi run giờ phân loại từng field trong request của các bước thành `linked` / `generated` / `target` / `unknown` / `constant` (B6), trong cùng snapshot với trace. Code: `contest-runtime/flagtrace/app/trace/values.py`; bảng `trace_values` (schema v4, migration chỉ thêm bảng và index `flag_ids(game_id,service,value)`); summary nằm trong `analysis.value_roles`; API trả `value_roles` trong chi tiết run (run cũ trả `not_computed`); dashboard có bảng "Values". `constant` chỉ được đếm, không lưu.

**Flag ID.** Chỉ so với flag ID của đội mình (`team_id`), cùng service, tick không muộn hơn request. Căn cứ: `same_put_session` (đúng phiên putflag của flag bị lấy, lần qua `flags_in`) > `put_tick` > `validity_window` (key mới tùy chọn `game.flag_validity_ticks`) > `earlier_tick`. Không có nguồn flag ID thì không gán `target` cho giá trị nào, và summary ghi rõ `flag_ids.status = none`. Flag ID bị từ chối vì thời gian được liệt kê trong `flag_ids.refused`. Tìm được flag ID nằm trong chuỗi (template `../../notes/{flag_id}.txt`), trong base64 (template + `transform`), trong claim JWT (`unresolved: jwt_unverified`), trong payload raw TCP, và cả flag ID 1 ký tự (gắn `ambiguous`).

**Lỗi chỉ lộ ra trên dữ liệu thật** (lần chạy đầu trên 100 hồ sơ: 22 `unknown`, đa số sai). Đã sửa, mỗi lỗi có test regression:
- Chuỗi query GraphQL bị coi là ID. Giờ giá trị có khoảng trắng hoặc ngoặc không còn được coi là identifier.
- Register echo lại username, nên login thành `linked` còn username lúc register thì `unknown`. Giờ response chỉ echo giá trị mà chính request đó gửi thì được lần về request: cả hai chỗ là `generated`, cùng một biến.
- Mảnh chữ của path (`image` trong `/image-sharing/`) bị coi là echo, và path của anchor bị biến thành template. Giờ token nhiễu không được tính là đã gửi, và mảnh chữ chỉ làm phần template khi là flag ID.
- Phần `unknown` được đặt tên như biến thật (`{password_2}`). Giờ tên là `{unknown}`; mảnh tách ra từ một giá trị được đặt tên `<field>_part`.

Sau khi sửa, trên 100 hồ sơ: linked 18 · generated 26 · unknown 4 · constant 249 · target 0 (lab không có checker nên không có flag ID). 4 giá trị `unknown` đều đúng là không rõ nguồn: email ngẫu nhiên không dùng lại, tên file ngẫu nhiên, đường dẫn file CV.

**Test.** 77/77 unit/integration (thêm 12 test `ValueRoleTests`), 32/32 kiểm tra trên trình duyệt (thêm 4 cho bảng Values). Đã migrate DB thật v3 → v4 (backup `data/flagtrace/backups/flagtrace-v3-20261014T173841.sqlite3`), deploy và phân tích lại toàn bộ hồ sơ.

**Chưa kiểm chứng / giới hạn.**
- `target` mới được kiểm bằng fixture (checker putflag tổng hợp, `import-flagids`). Chưa có flag ID thật vì lab local không có checker.
- Flag ID từ checker được dựng lại mỗi tick và cần ít nhất 2 tick có giá trị khác nhau. Flag-out ở 1–2 tick đầu giải, hoặc phân tích trước lần dựng lại đó, sẽ chưa thấy flag ID. Hiện phải Re-analyse tay; tự retrace thuộc P2.6.
- Một chain đơn lẻ không phân biệt được hằng do attacker chọn với giá trị tự sinh (ví dụ ID admin `1`): giá trị ngắn được gắn `ambiguous`. P2.4b (gom nhóm) sẽ giải quyết việc này.
- `flagtrace.flag_ids_url` cần endpoint trả đúng format chuẩn hóa; API của giải có format khác thì phải viết adapter.

## 14. P2.6 (một phần) — Dedup trước enrich, cache decoder, chế độ decoder (2026-10-15, schema v5)

**Làm gì.**
- **Dedup trước `enrich()`:** `transaction_id` được tính từ record của transport; transaction đã có trong DB bị bỏ trước khi parse/decode (`duplicates_skipped` trong `/status`). Check cũ trong `Store.insert` vẫn giữ.
- **Cache decoder theo nội dung:** `analysis.Decoder` nhớ kết quả theo hash(regex + body), LRU 4096 entry / 64 MB. Kết quả hết `decode_budget` không được cache. Mỗi transaction vẫn lưu representation `decoded` riêng.
- **Chế độ decoder** `full` / `gated` / `off`: mặc định từ `flagtrace.decoder_mode` (`full`), ghi đè từ dashboard qua `POST /decoder` vào bảng `runtime_settings` và **giữ qua restart**. Ingest đọc chế độ trước mỗi file, ghi vào `pcap_files.decoder_mode`. Body không được decode vì chế độ có quality `<side>:decoder_gated` / `decoder_off`; run có bước như vậy có cảnh báo. System Status có mục *Flag-trace decoder* (vàng khi khác `full`), tab FLAG TRACE có ô chọn chế độ (chọn `off` phải xác nhận).
- Schema v5 chỉ thêm bảng `runtime_settings` và cột `pcap_files.decoder_mode`. Engine không đổi version (chỉ thêm cảnh báo cho dữ liệu mới).

**Đo trên dataset A/B** (ingest offline `--finalize`, cùng máy, chạy tuần tự; replay = đặt lại `replay_from=1` rồi ingest lại):

| | A: ingest | A: replay | A: flag-out | B: ingest | B: replay | B: flag-out |
|---|---|---|---|---|---|---|
| Trước | 18,9 s | 12,7 s | 95 | 78,6 s | 66,6 s | 2000 |
| `full` | 16,0 s | 0,3 s | 95 | 73,4 s | 0,3 s | 2000 |
| `gated` | 12,8 s | 0,2 s | 95 | 16,0 s | 0,3 s | 2000 |
| `off` | 7,7 s | 0,3 s | **52** | 13,1 s | 0,3 s | 2000 |

- Trên data thật (DB lab, 850 body): `looks_encoded()` cho qua 362/850 body và không bỏ sót body nào trong 45 body có flag chỉ thấy sau decode.
- Ở `full`, cache giúp ít trên B vì body ở đó hầu như không trùng (login, flag mỗi đội mỗi tick khác nhau). Phần lớn thời gian `full` trên B là decoder chạy trên body rất nhỏ (~8 ms/body): profiling từng node của decoder là bước tối ưu tiếp theo cho chính `full`.
- Ở `gated`/`off` trên B, CPU chỉ còn ~5 s; phần wall còn lại (~8–11 s) là chờ fsync vì mỗi transaction một commit (`synchronous=FULL`). Commit theo batch chưa làm.

**Test.** 86/86 unit/integration (thêm 8 test `DecoderTests` và 1 test cảnh báo trên run; hai test migration cập nhật cho bước 5), 39/39 kiểm tra trên trình duyệt (thêm 7 cho ô decoder: mặc định, đặt `gated`, hủy `off`, xác nhận `off`, giữ sau reload, về mặc định).

**Deploy.** Build `ctf-flagtrace:phase2`, migrate DB thật v4 → v5 (backup `data/flagtrace/backups/flagtrace-v4-20261014T183717.sqlite3`), rebuild dashboard, restart host agent. Khi khởi động lại, ingest replay phần đuôi đã pin và bỏ 4 transaction trùng mà không decode lại. Đã thử đổi `gated` → về mặc định trên stack thật: tab FLAG TRACE đổi ngay, System Status đổi vàng sau một chu kỳ push của host agent (~30 s). Chế độ hiện tại: `full` từ config.

**Chưa làm / giới hạn.**
- Chế độ không tự hạ/nâng theo backlog; phải đổi tay.
- `pcap_files.decoder_mode` là chế độ của **lần đọc gần nhất**: file được replay sau restart ghi lại chế độ lúc replay, dù transaction cũ trong đó đã được decode trước đó. Quality của từng transaction mới là bản ghi chính xác.
- Flag-out bị bỏ lỡ khi `off` không được decode lại khi bật lại `full`.
- Detection không đổi (đã có bộ lọc `looks_encoded()` riêng theo packet).

## 15. P2.5 — HTTP script artifact và tái hiện local (2026-10-15, engine `p2.5.0`, exporter `p2.5.1`, schema v6)

**Ảnh hưởng của thay đổi Phase 1 mục 14.** Dedup giữ nguyên transaction identity/raw representations và cache decoder vẫn lưu decoded evidence riêng cho mỗi transaction, nên không đổi đầu vào exporter. Schema P2.5 dùng v6 vì v5 đã dành cho decoder mode. Request artifact vẫn `supported` khi raw request đầy đủ; chain bị hạ `needs_edit` nếu bước của run được ingest với `decoder_gated`/`decoder_off`, vì decoded-only step/value có thể đã bị bỏ qua.

**Artifact.** Mỗi run mới lưu Python artifact bất biến cho từng HTTP request và toàn chain trong `trace_script_artifacts`, gắn run, exporter version và SHA-256. Exporter `p2.5.1` bổ sung fallback raw-DEFLATE khi response không khai báo `Content-Encoding`. Run cũ vẫn trả `scripts: not_computed`; worker tự enqueue một **run mới** cho latest run `linked` thiếu artifact phiên bản hiện tại bằng trigger versioned `auto:scripts:p2.5.1`, theo batch và idempotent qua poll/restart. Request đơn gửi đúng raw HTTP bytes. Chain thay đúng byte range của `linked`/`generated`/`target`, sửa Content-Length, giữ duplicate fields/headers, body binary, multipart boundary và phần encoding không đổi. Host là tham số; mặc định dùng đúng `dst_port` của từng bước.

**Giới hạn được nói rõ.** `unknown`, ambiguous, JWT không ký lại được, URL encoding/span không xác định, result partial hoặc decoder bị hạ → `needs_edit`. Raw request thiếu/cắt và raw TCP chưa có turn/span mapping → `unsupported`. `supported` không đồng nghĩa `reproduced`.

**Verification và UI.** CLI `verify-script` chỉ nhận localhost/loopback, chạy artifact trong subprocess có timeout và ghi fixture, target, thời gian, artifact hash cùng kết quả vào `trace_replay_verifications`. Chỉ lần chạy thấy flag mới có `reproduced`. Dashboard hiển thị support/verification, cảnh báo, Copy/Download và source preview; `Copy chain` nằm cạnh badge `linked`, mỗi timeline step có nút Copy request riêng. Không có action chạy script.

**Test.** 97/97 unit/integration pass trên cây code hiện tại. Regression auto-backfill xác nhận linked run thiếu script tạo đúng một job/run mới, giữ nguyên run cũ và không enqueue trùng ở poll sau. Acceptance exporter xác nhận: bốn request notes + chain được lưu/compile; chain chạy với username/password sinh mới, session mới, file ID mới và flag ID mới vẫn lấy `FLAG{fixture_reproduced}`; GraphQL JSON + Bearer chain compile ở trạng thái supported; request có query/form lặp được gửi lại byte-for-byte; non-loopback verification bị từ chối. Chromium live xác nhận 5/5 nút step khớp đúng transaction artifact, Copy thành công và không mở preview/chạy traffic.

**Deploy.** Đã build lại `ctf-flagtrace:phase2` và dashboard, dừng API/worker trong lúc migrate DB thật v5 → v6, tạo backup `data/flagtrace/backups/flagtrace-v5-20261015T002205.sqlite3`, rồi force-recreate API, worker và dashboard; cả ba container healthy. Sau khi bật auto-backfill, DB live có 100 latest run `linked`: 4 đã có chain, worker tự tạo và hoàn tất 96 job còn thiếu; kết quả cuối **100/100 linked profile có chain artifact**, 0 thiếu. Các run cũ vẫn `not_computed` theo chủ đích và còn nguyên trong history.

**Chưa làm / giới hạn.** Raw TCP vẫn unsupported đúng theo kế hoạch. P2.4b grouping/suspect chưa làm; generated value mà một chain chưa phân biệt chắc được giữ ambiguous/needs-edit.

## 16. Gộp flag-out lặp lại trên danh sách (2026-10-15)

**Vấn đề.** Attacker gửi lại cùng một request thì đọc cùng một flag nhiều lần; mỗi lần là một flag-out với hồ sơ riêng, nên tab FLAG TRACE lặp một dòng chỉ khác thời gian. Trên DB lab: 95/100 hồ sơ là cùng flag `DTFC{local_pha1_test}`, cùng nguồn `ip:127.0.0.1`, cùng `GET /image-sharing/`.

**Làm gì.** Chỉ là cách hiển thị, không gộp hay xóa hồ sơ nào: mỗi lần vẫn giữ hồ sơ, job và lịch sử phân tích riêng.
- Nhóm = cùng `source_key`, service, tập flag và dòng request (method + path, không tính query). Khác đội, khác request hoặc khác flag (tick khác) là dòng khác.
- Dòng nhóm hiện hồ sơ có chain nối nhiều bước nhất (hòa thì mới nhất), để một lần có chain dài không bị che sau các lần lặp một bước; có chip "results differ" khi các lần lặp cho kết quả khác nhau, và đếm trạng thái khi lẫn nhau (ví dụ `2 linked · 1 pending`).
- `×N` mở danh sách các lần lặp ngay dưới dòng; bấm một lần lặp mở đúng hồ sơ đó. Nhóm đang mở giữ nguyên qua auto-refresh.
- Ô *group identical flag-outs* (mặc định bật, nhớ theo trình duyệt) để xem lại danh sách từng hồ sơ.
- Code: `flagtrace/app/trace/dedup.py` (route `GET /trace-groups`, `GET /trace-groups/{trace_id}/members`, nối ở `api.py`), `dashboard/static/js/flagtrace-groups.js`; `flagtrace.js` chỉ thêm 3 dòng nối.

**Kết quả.** DB lab: 100 hồ sơ → 6 dòng (×95 cho `DTFC{local_pha1_test}`, t1–t364).

**Test.** 5 test `test_dedup.py` (gộp đúng và tách đúng khi khác đội/request/flag; dòng hiện chain dài nhất; phân trang thành viên; filter; retrace không thành lần lặp). `check_groups.py` 12/12 kiểm tra trên trình duyệt; `check.py` vẫn pass toàn bộ với danh sách gộp mặc định. Toàn bộ 96/96 test Python pass trên cây code hiện tại.

**Deploy.** Đã được đưa lên cùng image Flag-trace/dashboard hiện tại trong lần deploy auto-backfill P2.5.

## 17. P2.4b — Gom nhóm chain và bước đáng ngờ (2026-10-15, engine `p2.5.1`, schema v7)

**Làm gì.**
- **B7 gom nhóm** (`flagtrace/app/trace/grouping.py`): chữ ký của chain = dãy bước, mỗi bước gồm method, path đã chuẩn hóa (`path_template`, dùng chung với baseline) và *tên* các field. Giá trị và vai trò giá trị không tham gia, nên đổi session/username/file ID mỗi lần vẫn chung nhóm, cùng khai thác từ đội khác cũng chung nhóm, và nhóm không phụ thuộc vào suy luận của B6. Bảng `trace_groups`, cột `trace_runs.group_id`.
- **B8 bước đáng ngờ** (`anomalies.py`): so từng bước với baseline dựng từ request của chính checker — endpoint/field checker không dùng, giá trị dài bất thường, loại ký tự checker không gửi ở field đó. Bảng `trace_suspects`.
- **Đếm theo hồ sơ qua run mới nhất**: phân tích lại không tăng số đếm; hồ sơ có chain đổi chuyển sang nhóm tương ứng.
- **API**: `GET /chain-groups`, `GET /chain-groups/{id}` (cấu trúc, nguồn, bảng biến thiên field, danh sách hồ sơ); run detail trả thêm `grouping` và `suspects` (run cũ trả `not_computed`).
- **Dashboard**: dòng "Chain shape ... seen in N flag-out(s) from M source(s)" trên hồ sơ; bảng "Steps that differ from what the checker sends" kèm chip `differs` trên Timeline; mục mở rộng có bảng biến thiên field và danh sách chain cùng nhóm. Code UI trong `flagtrace-chains.js`; `flagtrace.js` chỉ thêm 3 dòng nối.
- Run cũ không có nhóm: worker tự xin phân tích lại một lần cho mỗi hồ sơ (`auto:grouping:<normalizer>`), cùng cơ chế với backfill script của P2.5.

**Hai lỗi tìm ra khi chạy, đã sửa, mỗi lỗi có test hồi quy.**
1. **Bảng biến thiên field đọc sai nguồn.** Bản đầu đọc `trace_values`, nhưng giá trị mà *mọi* chain đều gửi y hệt bị B6 xếp `constant` nên không được lưu — đúng trường hợp bảng này sinh ra để chỉ tên. Hai chain giống hệt nhau cho kết quả khác nhau (`unknown` ở chain đầu, `constant` ở chain lặp, vì `repeated_in_same_step` không nằm trong `OPEN_NOTES`). Giờ bảng đọc thẳng request của từng chain, độc lập với B6. Tên endpoint trong path bị loại vì nhóm đã cố định path template.
2. **So ký tự quá nhạy.** Bản đầu báo mọi ký tự không có trong baseline, nên `/register` bị đánh dấu chỉ vì mật khẩu có chữ `y` mà giá trị ngẫu nhiên của checker tình cờ không dùng: 4/4 bước đều "đáng ngờ", chôn mất lead thật. Giờ chỉ báo **loại** ký tự checker không gửi ở field đó (dấu câu nó không dùng, hoặc cả một lớp nó không dùng); còn 3/4 bước, đúng ba endpoint checker không gọi.

**Kết quả trên dữ liệu thật** (DB lab, 100 hồ sơ): 6 nhóm, lớn nhất **×95** (`GET /image-sharing/`). Nhóm đó cho thấy điều một chain đơn lẻ không nói được: field `query:f` được cả 95 chain gửi và B6 xếp `constant` ở từng chain, nhưng **6 giá trị khác nhau** trên toàn nhóm (`L2ZsYWcvZmxhZw==` = base64 của `/flag/flag`). Lab không có checker nên baseline rỗng: `suspects.state = no_baseline`, không bước nào bị đánh dấu, đúng thiết kế.

**Test.** 110/110 unit/integration (thêm `test_chains.py`: 7 test gom nhóm + 6 test baseline, trong đó 2 test hồi quy cho hai lỗi trên). Browser: `check_chains.py` 10/10 mới; `check.py` 46/46 và `check_groups.py` 12/12 vẫn pass.

**Deploy.** Bạn đã deploy bản có P2.4b lúc 08:12 (101 run `p2.5.1`, 196 job `auto:grouping:n1`, DB lên v7, backup `flagtrace-v5-20261015T002205.sqlite3`). Mình build lại image, khởi động lại `flagtrace`/`flagtrace-worker` và rebuild dashboard để phục vụ `flagtrace-chains.js`.

**Giới hạn.**
- Baseline chỉ dựng được khi có traffic checker; lab không có nên phần B8 mới kiểm bằng fixture (25 phiên checker tổng hợp), chưa kiểm trên giải thật.
- Chain raw TCP vào nhóm theo số bước, không có dòng request để so, và không được so với baseline.
- Bảng biến thiên field đọc tối đa 200 chain mỗi nhóm và 50 giá trị khác nhau mỗi field; vượt thì đánh dấu `distinct_capped`.
- Nhóm chỉ nói các chain *giống nhau*, không khẳng định cùng một bug.

## 18. Script nói rõ lý do hỏng, và cột Tulip trên Timeline (2026-10-15, exporter `p2.5.2`)

**Lỗi báo cáo:** chain script chạy ra `KeyError: ['data', 0, 'signIn', 0, 'access_token', 0]`.

**Nguyên nhân (không phải lỗi đường dẫn).** Response đã bắt được đúng là `{"data":{"signIn":{"access_token":...}}}`, nên đường dẫn exporter sinh ra khớp. Hỏng nằm ở bước signUp của chính chain đó: script chỉ thay `username` và `password`, còn `email` được gửi lại nguyên văn — địa chỉ đã thuộc tài khoản tạo lúc capture. signUp fail vì trùng email → tài khoản không được tạo → signIn trả `null` → `_json_at` đi vào `null`. Artifact đó đã mang `support: needs_edit` và cảnh báo đúng field `['req','json','variables',0,'user',0,'email',0]`.

`email` là `unknown` chứ không phải `generated` vì B6 chỉ gọi một giá trị không nguồn là `generated` khi nó **được dùng lại ở bước sau**; email chỉ xuất hiện một lần. Đây là giới hạn đã ghi ở mục 13. Hướng đóng lại: dùng bảng biến thiên field của P2.4b (field khác nhau ở mọi chain cùng nhóm = giá trị mỗi lần một khác), cộng sinh giá trị **giữ định dạng** trong exporter — hiện exporter báo "no safe format inference" nên để nguyên. Chưa làm.

**Đã sửa.** `_json_at`, `_header`, `_cookie` trong script sinh ra giờ nói rõ dừng ở đâu, gặp gì, và in đầu response thay vì `KeyError(path)`:

```
no ['data', 0, 'signIn', 0, 'access_token', 0] (at ['data', 0, 'signIn', 0]) in this response:
found null there, which is neither an object nor a list. The step meant to produce it
probably failed. Response began: '{"errors":[{"message":"email already exists"}],...'
```

Exporter lên `p2.5.2`; toàn bộ hồ sơ được xuất lại qua backfill `auto:scripts:p2.5.2`. Test `auto:scripts:*` đổi sang dùng hằng `EXPORTER_VERSION` để lần bump sau không phải sửa test.

**Cột Tulip thay cột Quality trên Timeline.** Mỗi bước của trace là một flow trong Tulip; cột mới link thẳng tới flow đó để xem byte thô, tag và traffic xung quanh mà Flag-trace cố tình không lấy.
- Khớp được thực hiện **lúc hiển thị** bằng `/api/tulip/resolve` có sẵn (cửa sổ thời gian + IP/port, cộng chuỗi flag ở anchor) — giống tab Events/Monitor. **Không lưu flow ID nào vào kết quả**, nên ingest lại capture không để lại ID cũ sai.
- Link ghi rõ mức khớp: `✓` khớp đúng IP, `~` chỉ là flow gần nhất theo thời gian, kèm lý do trong tooltip.
- Quality của từng bước không mất: chip chuyển sang cạnh cột Request.
- API: mỗi step trong run detail có thêm `network` (src/dst ip, port, `ts_request`), đọc từ bảng `transactions` lúc truy vấn nên run cũ cũng có.
- Tulip không tới được thì UI bỏ cuộc sau 20 s và ghi lý do, không treo cột: khi DNS không phân giải được, mỗi truy vấn mất 10 s nên một chain 10 bước sẽ treo rất lâu.

**Kiểm chứng.** Trên stack thật: chain 10 bước khớp 10 flow khác nhau, tất cả `✓`, hai bước flag-out khớp "matched IPs + flag text"; link mở được (`/api/tulip/flow/<id>` trả flow có tag `flag-out`). 112/112 test Python (thêm test `network` và 2 test cho helper của script), 72/72 kiểm tra browser (50 + 12 + 10), thêm 4 mục cho cột Tulip gồm trường hợp Tulip không tới được.

**Lưu ý môi trường.** File `/tmp/re.py` (artifact lưu tay, tên gốc `request-01.py`) che mất module `re` chuẩn của Python với mọi script chạy từ `/tmp`, làm hỏng 2 test chạy script sinh ra. Chạy test với `TMPDIR` khác, hoặc đổi tên file đó.
