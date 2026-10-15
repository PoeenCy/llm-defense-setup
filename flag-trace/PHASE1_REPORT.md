**Flag-trace — Báo cáo Phase 1**

Ngày chạy: 2026-10-14. Có hai lần chạy: lần đầu, và lần chạy lại sau khi sửa vấn đề 3 (flag ID ngắn) và vấn đề 5 (response bị cắt). Code: branch `feat/decode-dashboard-detection`, các thay đổi Flag-trace **chưa commit**. Tài liệu đối chiếu: [PHASE1_IMPLEMENTATION_PLAN.md](PHASE1_IMPLEMENTATION_PLAN.md).

Kết quả, config snapshot, script và DB nằm ở `data/flagtrace/report-2026-10-14/` (thư mục này bị gitignore). DB của lần chạy đầu được giữ trong thư mục con `before-fix/`.

**1. Kết luận**

- **Dataset A (PCAP thật, target DTFC local):** pipeline chạy được từ đầu đến cuối.
  - Kết quả: 713 transaction và 95 job trace, cả 95 đều là flag-out qua `GET /image-sharing/`.
  - 43 trong số đó chỉ phát hiện được sau khi decoder giải deflate.
  - Ingest lặp và replay toàn bộ không tạo dòng trùng, kể cả sau khi sửa.
- **Dataset B (20 đội, mỗi đội một IP, flag ID đổi theo tick):**
  - Gán đội đúng, checker được tách riêng, token không bị nối chéo giữa các đội.
  - Flag ID của mỗi tick được ghi thành token ở cả 20 đội.
  - Bảng `flag_ids` thu đúng một ứng viên cho mỗi tick từ lượt putflag của checker.
- **Đã sửa:**
  - Vấn đề 3: token theo vị trí, cộng ứng viên flag ID lấy từ checker.
  - Vấn đề 5: response bị cắt giữ nguyên cặp với request; `dechunk` trả phần đã giải được.
  - `ts_response` ghi NULL khi không có response.
- **Còn chặn trước khi bật live:**
  - Throughput khoảng 26–39 transaction/s.
  - DB lớn gấp 12–15 lần PCAP.
  - Một file PCAP lỗi làm dừng cả lượt ingest.
  - P1.6 (capture handoff, retention khi thiếu đĩa) chưa được kiểm chứng.

**2. Môi trường và dữ liệu**

| Mục | Giá trị |
|---|---|
| Máy | AMD Ryzen 5 6600HS, 4 vCPU, 11 GB RAM, WSL2 (kernel 6.18), ext4. Load average khoảng 2,4 trong lúc đo |
| Image | `ctf-flagtrace:phase1`, đã build lại sau khi sửa: Python 3.11.17 + Go helper (gopacket 1.3.0) |
| Host | Python 3.14.7, dùng để profile và đo thời gian |
| Dataset A (thật) | 7 file trong `traffic/`, 5,0 MB, 7.628 packet, bắt trên `lo:8090` (DTFC2023 local). Mọi nguồn đều là `127.0.0.1` |
| Dataset B (synthetic) | 20 đội, IP `10.60.2–21.1`, 100 tick. Xem mô tả bên dưới |

Trong dataset A có hai file trùng nội dung (`exploit_gzip.pcap` và `exploit_gzip_test.pcap`) và một file rỗng 0 byte (`accept.pcap`).

Dataset B gồm 20.800 packet, 2.100 connection, 2,2 MB. Mỗi tick diễn ra như sau:

- Checker `10.60.0.1` gửi `POST /put` với `id=<flag ID của tick>&flag=…&note=static`.
- Mỗi đội login rồi gọi `GET /notes/<flag ID của tick>` để lấy flag.
- Các connection của cùng một đội chồng thời gian lên nhau.

Config snapshot của A lấy từ `services.json`, bổ sung các giá trị **giả định** sau:

- `game.id = dtfc-local-2026-10-14`
- `start_time = 2026-10-13T15:00:00Z`
- `tick_seconds = 120`
- `teams` và `checker_ips` để trống
- `capture_ips = ["127.0.0.1"]`

Đây không phải thông số của giải thật.

**3. Kết quả dataset A (PCAP thật)**

| Chỉ số | Kết quả |
|---|---|
| File | 6 file `done`. 7 đường dẫn, hai file trùng được gộp thành một `file_id` |
| Transaction / connection | 713 / 713, tất cả là HTTP. Lần đầu là 745, trong đó có 32 transaction TCP bị tách ra (xem 6.5) |
| Phân loại | `no_flag_observed` 618, `flag_out_candidate` 95, `checker` 0 (không có IP checker) |
| Job trace | 95 `pending`, cùng flag `DTFC{local_pha1_test}` |
| Flag chỉ thấy sau decoder | 43/95 (transform `deflate`). Tắt decoder thì chỉ còn 52 job |
| Flag trong request | 10 request `POST /graphql` với body `flag=…`. Không bị tính là flag-out, đúng như mong đợi |
| Token | 104.236 token, trung bình 146/transaction. 91,7% là token `produced/body` lấy từ HTML/JS. 878 token ở vị trí có cấu trúc ngắn hơn 6 ký tự, chủ yếu là `404`, `1000`, `59` |
| Representation / sighting | 2.895 / 167 |
| Quality | 515/713 transaction sạch (72%) |
| Timestamp | 0 bất thường. Không có token `produced` nào trước request của nó; không còn `ts_response=0` |
| Ingest lặp | Mọi bảng giữ nguyên số dòng (bỏ qua nhờ checkpoint) |
| Replay toàn bộ (`replay_from=1`, chạy trên bản sao DB) | Số dòng của mọi bảng và tổng `token_df` (54.134) giữ nguyên, mất 18,0 s |
| API | Xem bảng ngay dưới |
| File rỗng | Chạy trên `traffic/` gốc: `ValueError: accept.pcap: short PCAP header`, **không ingest được file nào**. Chưa sửa |

Kết quả gọi API trên DB của dataset A (lần đầu):

| Lời gọi | Kết quả |
|---|---|
| `/status` | 200 |
| `/health` | 503. Đúng thiết kế: DB do CLI tạo có `state=complete`, còn `/health` chỉ trả 200 khi ở chế độ `run` |
| `/flagouts`, lọc theo `source_key`, phân trang | Hoạt động |
| `/transactions/{id}` | 3 ms, payload 11 KB |
| `tick=abc` | 200 với danh sách rỗng |
| Endpoint lạ | 404 |

Phân rã các vấn đề quality (tính theo số transaction, sau khi sửa):

| Vấn đề | Số lượng | Giải thích |
|---|---|---|
| `resp:decode_budget_exhausted` / `req:…` | 181 / 17 | Chủ yếu do chạm trần `MAX_NODES=600`, không phải do hết thời gian. Đã chạy lại decoder không giới hạn node trên 394 body liên quan (lần đầu): **không sót flag nào** |
| `resp:incomplete_body` | 32 | Response `main.js` khai `Content-Length: 1152017` nhưng capture dừng giữa chừng. Nay vẫn đi cặp với request và vẫn được scan flag |
| `resp:token_limit` | 29 | Response HTML/JS lớn |
| `max_connection_age` | 20 | Ghi sai lý do, xem 6.6 |
| `capture_end` | 12 | Connection còn mở lúc finalize |

**4. Kết quả dataset B (20 đội)**

| Kiểm tra | Kết quả |
|---|---|
| Gán đội | 20 `source_key`, mỗi đội đúng 200 transaction, 0 nguồn chưa map |
| Connection xen kẽ trong cùng đội | Các connection chồng thời gian nhau nhưng vẫn gán đúng đội |
| Checker | 100 transaction `checker`, 100 dòng `flags_in`, không tạo job |
| Job | 2.000 job, mỗi đội 100 |
| Flag ID thành token | Ở mọi tick, flag ID của tick đó là token `consumed` tại `req.path[1]` của cả 20 đội (2.000 token) |
| Ứng viên flag ID từ checker | Trong `flag_ids` có 100 dòng `source=checker_put`, một dòng mỗi tick, đều ở vị trí `req.form.id`. Không dòng nào là `note=static`, `put` hay mảnh của flag |
| DF của một flag ID | 21/4.100 transaction, thấp xa ngưỡng `max_df: 0.3` |
| Token chéo đội (đội A sinh, đội B dùng) | 0 |
| Lookup trong cùng đội (`produced` → `consumed`) | 2.000 cặp |
| Baseline | Có dòng cho `/put` (`id`, `flag`, `note`, path), mỗi dòng 10 mẫu (cửa sổ 10 tick) |
| Quality | Sạch 100% |

**5. Hiệu năng**

| Lần chạy | Wall | CPU user | Transaction/s | Packet/s |
|---|---|---|---|---|
| A, container, mặc định | 28,9 s (lần đầu: 20,8 / 25,7 s) | – | 25–36 | – |
| A, host, mặc định | 24,5–27,1 s (lần đầu: 23,0 s) | 17,9–19,4 s | 26–29 | 281–311 |
| A, host, tắt decoder | 10,0–11,2 s | khoảng 4,0 s | 64–71 | 681–763 |
| B, host, mặc định | 104,1 s | 86,6 s | 39 | 200 |
| B, host, tắt decoder | 14,6 s | 3,6 s | 282 | 1.430 |

- **Chênh lệch giữa các lần đo:** các bản sửa không đụng tới decoder hay cách commit. Chênh lệch giữa lần đầu và lần chạy lại chủ yếu do máy đang tải nặng (load average khoảng 2,4).
- **Max RSS:** khoảng 35–55 MB.
- **Profile (cProfile trên A, lần đầu):**
  - decoder `Engine.search`: 80%
  - `Store.insert`: 15%
  - trích token: 2,6%
  - parse HTTP: 0,2%
  - Go transport: không đáng kể
- **Chi phí decoder:** khoảng 20 ms cho mỗi body (p50), kể cả body chỉ vài chục byte.
- **Thời gian chờ không dùng CPU:** khi tắt decoder, còn khoảng 3–9 s wall không phải CPU. Nhiều khả năng đây là fsync, vì mỗi transaction là một commit với `synchronous=FULL`. Plan yêu cầu gom batch khoảng 200 transaction, code hiện chưa làm.
- **Dung lượng DB:**
  - A: 78,4 MB cho 5,0 MB PCAP (khoảng 15 lần). Bảng `tokens` 38,0 MB, ba index token 24,4 MB, `representations` 9,5 MB, `transactions` 1,4 MB.
  - B: 26,9 MB cho 2,2 MB PCAP (khoảng 12 lần).
  - Sau khi hạ ngưỡng token ở vị trí có cấu trúc, tổng token của A chỉ tăng 0,7% (103.505 → 104.236).
- **So với mục tiêu "<10 s cho PCAP 60 s":** với khoảng 40 transaction/s, lượng xử lý được trong 10 s là khoảng 400 transaction. Tức là traffic chỉ được trung bình dưới 7 transaction/s cho mỗi file 60 s. Chưa có số liệu traffic thật của giải để kết luận đạt hay không.

**6. Vấn đề phát hiện khi chạy**

1. **Throughput thấp (chưa sửa).** Decoder chiếm khoảng 80% CPU, commit từng transaction tốn thêm thời gian chờ I/O. Không thể đơn giản là bỏ decoder, vì nó bắt 43/95 flag-out. Ngoài ra, khi replay, transaction đã có trong DB vẫn bị chạy lại enrich và decoder rồi mới bị loại ở bước insert (replay A mất 18 s). Hướng xử lý:
   - Commit theo batch.
   - Kiểm tra trùng trước `enrich()`.
   - Xem lại chi phí của mỗi node trong decoder.
2. **DB phình 12–15 lần (chưa sửa).** Phần lớn do token từ body HTML/JS và các index đi kèm. Hướng xử lý: hạn chế token hóa body raw theo content-type hoặc kích thước. Retention cũng phải tính phần dung lượng này.
3. **Flag ID ngắn bị bỏ (đã sửa).** Trước đây `min_len=6` áp lên cả path segment và giá trị form/query, nên `7731` trong `/notes/7731` không thành token.
   - **Vai trò của `7731` trong Phase 2:** nó không phải cạnh nối trong chain. B2 chỉ nối token trong cùng một đội, còn giá trị mà checker gửi thuộc nguồn khác. Vai trò thật của nó là ở B6: xếp giá trị vào loại `target`, và biến `../../notes/7731.txt` thành template `../../notes/{flag_id}.txt`.
   - **Cách sửa:** `min_len` (6) giờ chỉ áp cho quét body không có cấu trúc. Các vị trí có cấu trúc (path, query, form, JSON, cookie, header, multipart) dùng `token.struct_min_len`, mặc định 2. Giá trị phổ biến để Phase 2 lọc bằng `token_df` lúc truy vấn.
   - **Ứng viên flag ID từ checker:** `collect_checker_flagids()` chạy sau mỗi lần rebuild baseline, ghi vào `flag_ids` với `source='checker_put'`, `owner_team_id` là đội mình, kèm `location` và `transaction_id` (schema v2, có migration từ v1).
     - Lấy giá trị từ connection của lượt putflag, tính đến chính request putflag. Lấy cả request lẫn response, vì ID do server sinh chỉ xuất hiện trong response.
     - Chỉ giữ những vị trí có giá trị thay đổi giữa các tick.
     - Bỏ cookie, header, chính flag và mọi mảnh tách ra từ flag.
     - Bảng này không ảnh hưởng tới việc tách token lúc ingest, nên ingest vẫn tất định khi replay hay reimport. B6 đối chiếu với bảng lúc truy vấn.
   - **Giới hạn còn lại:**
     - Giá trị 1 ký tự ở vị trí có cấu trúc không thành token; B6 phải tự đối chiếu với `flag_ids`.
     - Trường ngẫu nhiên của checker (ví dụ password) cũng thay đổi theo tick nên vẫn vào danh sách ứng viên. Rủi ro thấp vì B6 chỉ khớp khi giá trị trùng hoàn toàn.
     - Username được tạo trong một connection khác với connection putflag sẽ không được thu.
4. **Một PCAP lỗi chặn cả lượt ingest (chưa sửa).** `discover()` gặp lỗi là raise luôn, các file còn lại không được xử lý. Ở chế độ live, mỗi lượt ingest sẽ raise lại cùng lỗi, nên dừng mãi khi có một file `.ready` hỏng.
5. **Response bị cắt bị tách khỏi request (đã sửa).**
   - **Go helper:** khi connection kết thúc, message dừng giữa header hoặc giữa body được trả về nguyên vẹn và vẫn đi cặp, với quality theo từng transaction: `resp:incomplete_body`, `resp:incomplete_header`, `req:incomplete_body` hoặc `req:incomplete_header`. Phần byte còn lại không còn bị tách thành transaction TCP riêng. `missing_response` giờ gắn cho từng transaction thay vì cho cả connection.
   - **`dechunk`:** trước đây raise lỗi khi chunk bị cắt, nên response chunked + gzip bị cắt thì không tìm được flag. Nay hàm trả về phần đã giải được kèm `decode_incomplete`. Chunk sai định dạng vẫn báo lỗi.
   - **Chưa làm:** đồng bộ lại sau khi mất packet giữa chừng. Một `tcp_gap` vẫn chuyển phần còn lại của connection sang raw.
6. **Lý do đóng connection sai (chưa sửa).** Connection rảnh trong khoảng giữa hai file cách nhau hàng giờ lại bị ghi `max_connection_age` thay vì `idle_timeout` (20 transaction). Thêm nữa, mỗi packet đều duyệt toàn bộ stream để kiểm tra tuổi connection, chi phí sẽ tăng nhanh khi có nhiều connection mở.
7. **`ts_response=0` (đã sửa).** Giờ ghi NULL khi không có response.
8. **Nhãn `decode_budget_exhausted` dễ hiểu sai (chưa sửa).** Nó được gắn cho khoảng 25% transaction, nhưng nguyên nhân là trần số node, không phải hết thời gian. Dataset này không sót flag, nhưng nhãn nên tách rõ hai trường hợp.

**7. Test**

- 22/22 test của Flagtrace pass, cả trên host (Python 3.14) lẫn trong image (Python 3.11.17).
  - Chạy song song 12 lần: không có test flaky.
  - `-X dev`: không có warning.
- 8 test mới:
  - Giá trị ngắn ở vị trí có cấu trúc thành token; body không có cấu trúc vẫn giữ ngưỡng 6.
  - Ứng viên flag ID từ checker: username do checker gửi, ID do server sinh, loại bỏ hằng số, cookie, flag và mảnh của flag; rebuild không đổi kết quả; dòng import từ API không bị xóa.
  - Response bị cắt giữa body vẫn đi cặp.
  - Response chunked + gzip bị cắt vẫn tìm được flag.
  - Header response bị cắt, và request bị cắt không có response (`ts_response` NULL).
  - Migration schema v1 → v2, mở lại DB lần hai không lỗi.
  - `dechunk` khi bị cắt và khi sai định dạng.
  - Kiểm tra giá trị `struct_min_len` hợp lệ.
- `dashboard/tests/test_rulegen.py` pass. `validate-config.sh` pass. `docker compose --profile flagtrace config` hợp lệ.
- Chạy container ở chế độ `run` với PCAP mẫu có marker `.ready`: `/health` trả 200, `state=running`.
- Nhóm 4 (nguồn) đã chỉnh theo thực tế giải: 20 đội, mỗi đội một IP, bỏ trường hợp một đội nhiều IP. Dataset B đã phủ các ý còn lại: connection xen kẽ trong cùng đội, nhiều đội dùng chung flag ID, không nối chéo giữa các đội.
- Còn thiếu so với mục 12 của plan:
  - Không có test Go nào.
  - Fault injection: Go helper chết, SQLite busy, Redis mất, PCAP hỏng, file ship dở.
  - Retention khi thiếu đĩa.
  - Capture handoff với vulnbox thật.
  - E2E bằng Compose.
  - Khởi động offline từ image đã save.
  - Một phần nhóm 6–8: port reuse, IPv6/VLAN, JWT.

**8. Đối chiếu các mốc**

| Mốc | Trạng thái | Bằng chứng |
|---|---|---|
| P1.0 | Một phần | Có schema (v2) và PCAP mẫu. Chưa có `contracts.py`. PHASE1_INGEST/PHASE2_TRACE chưa đồng bộ |
| P1.1 | Đạt | Rollback, ingest lặp, replay trên dữ liệu thật, migration schema |
| P1.2 | Đạt | Ghép đúng trên dữ liệu thật, message bị cắt vẫn đi cặp. Chưa đồng bộ lại sau gap |
| P1.3 | Đạt | Tách checker, nguồn chưa map, flag mã hóa, flag ID ngắn đều đúng |
| P1.4 | Phần lớn | Replay giữ ID ổn định. Thiếu test kill process ở từng điểm commit |
| P1.5 | Đạt | API, baseline từ checker, flag ID từ checker hoặc import, không có nguồn flag ID vẫn ingest được |
| P1.6 | Chưa kiểm chứng | Có code. Chưa chạy với vulnbox, chưa thử thiếu đĩa |
| P1.7 | Một phần | Đã có số đo trong báo cáo này. Chưa đạt hoặc chưa xác định được mục tiêu hiệu năng. Docs và kiểm tra offline chưa làm |

Ngoài ra còn tồn đọng:

- `PHASE2_TRACE.md` cần cập nhật theo các quy ước mới:
  - `is_noise` và `token.min_len` của Phase 2 phải theo vị trí như Phase 1, nếu không B6 lại bỏ mất flag ID ngắn.
  - `flag_ids` giờ có `owner_team_id`, `source`, `location`, `transaction_id`.
  - B6 cần đọc cả nguồn `checker_put`.
- `docs/SCHEMA.md` chưa có các block `game`, `teams`, `flagtrace`, `capture`, và chưa có `token.struct_min_len`.
- `contest-runtime/flagtrace/README.md` được tham chiếu trong `services.json` nhưng file không tồn tại.
- Ba ghi chú trong `services.json` bị đổi ký tự `—` thành `\u2014`.

**9. Việc tiếp theo, theo thứ tự ưu tiên**

1. Đồng bộ `PHASE2_TRACE.md` (B2/B6, `flag_ids`, ngưỡng token) và SCHEMA.md trước khi viết trace worker.
2. Tăng throughput: commit theo batch, kiểm tra trùng trước `enrich()`, giảm chi phí decoder. Sau đó đo lại bằng dataset A và B.
3. Giảm dung lượng token. Sửa vấn đề 4: một file lỗi không được chặn các file khác.
4. Kiểm chứng P1.6: capture handoff với vulnbox, retention khi thiếu đĩa, E2E bằng Compose, khởi động offline.
5. Đồng bộ lại sau `tcp_gap`; sửa nhãn `max_connection_age` và `decode_budget_exhausted`.

**10. Cách chạy lại**

```bash
# Build Go helper (offline) và chạy test
cd contest-runtime/flagtrace/transport && GOPROXY=off go build -o /tmp/flagtrace-transport .
cd ../.. && FLAGTRACE_TRANSPORT=/tmp/flagtrace-transport python3 -m unittest discover -s flagtrace/tests

# Dataset A bằng image (build lại: docker compose -f docker-compose.contest.yml --profile flagtrace build flagtrace)
R=$PWD/../data/flagtrace/report-2026-10-14
docker run --rm --network none --user $(id -u):$(id -g) \
  -v $R/traffic:/traffic:ro -v $R:/data -v $R/services.json:/runtime/config/services.json:ro \
  ctf-flagtrace:phase1 python -m flagtrace.app.main ingest --db /data/flagtrace.sqlite3 --finalize

# Phân tích DB; sinh lại dataset B (100 tick) rồi ingest
python3 $R/scripts/analyze.py $R/flagtrace.sqlite3
python3 $R/scripts/gen.py $PWD /tmp/synth 100
FLAGTRACE_TRANSPORT=/tmp/flagtrace-transport python3 -m flagtrace.app.main --config /tmp/synth/services.json \
  ingest --traffic /tmp/synth --db /tmp/synth/flagtrace.sqlite3 --finalize
```
