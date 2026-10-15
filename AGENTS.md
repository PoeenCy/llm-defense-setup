# AGENTS.md — hướng dẫn cho agent làm việc trong repo này

Đọc file này trước khi chạy lệnh nào. Nó ghi những thứ **không suy ra được từ code**:
ranh giới phạm vi, thứ tự dựng, và các cái bẫy đã thực sự cắn người trước.

---

## 1. Đây là cái gì, và không phải cái gì

Stack giám sát cho **Attack–Defense CTF**, chạy trên một máy (máy monitor), không phải
trên vulnbox. Trong A/D CTF, mọi đội chạy **cùng một bộ service có lỗi cố ý**; các đội
tấn công nhau để lấy flag, còn checker của BTC liên tục kiểm tra service còn sống.

Repo này làm **nửa phòng thủ** của vòng lặp đó:

| Có | Không có |
|---|---|
| Chặn pattern tấn công ở edge (ctf_proxy, Suricata) | Không chứa service có lỗi để thi (chỉ có `mock-vulnbox` để diễn tập) |
| Biết ngay khi flag rời mạng (detection + Flag-trace) | Không phải CTF platform |
| Dựng lại **chuỗi request** đã lấy flag (Flag-trace) | Không tự tìm lỗ hổng, không sinh exploit mới |
| Xuất chuỗi đã bắt được thành script `requests` (P2.5) | Không tự bắn vào service đang thi |

**Phần "tấn công" của repo chỉ là một việc:** lấy chuỗi tấn công mà đội khác đã dùng để
lấy flag trên **box của chính bạn**, rồi dựng lại thành script chạy được. Vì mọi đội chạy
box giống hệt nhau, script đó dùng lại được với các đội khác. Đó là lối chơi bình thường
của A/D CTF ("steal the exploit"). Nó **không** phải công cụ tìm lỗ hổng.

### Ranh giới — đọc kỹ

- Stack này chỉ được trỏ vào **box của đội bạn** và **mạng game của giải bạn đang thi**,
  hoặc target luyện tập local (`~/ADLabs/dtfc2023`, cổng 8090).
- Capture chạy trên vulnbox **của bạn**. Không bắt traffic của hạ tầng người khác.
- Dashboard **không bao giờ** tự bắn script vào service đang chạy. Nhãn `reproduced` chỉ
  được gắn sau khi replay thành công trên **fixture local**, không phải trên target thật.
- Ngoài phạm vi đó thì đừng dùng. Đây là công cụ cho giải đấu được cấp phép.

---

## 2. Đọc theo thứ tự này

| Khi cần | Đọc |
|---|---|
| Khởi chạy lần đầu | `START.md` |
| Đổi IP/port/config giữa giải | `CONFIG.md` ← vào thẳng đây, đừng đọc README |
| Ý nghĩa từng key trong `services.json` | `docs/SCHEMA.md` |
| Sự cố lúc thi | `docs/RUNBOOK.md` |
| Chuyển từ diễn tập sang thi thật | `docs/GOLIVE.md` |
| Đọc dashboard | `docs/DASHBOARD_GUIDE.md` |
| Flag-trace (phần phức tạp nhất) | `contest-runtime/flagtrace/README.md` |
| Flag-trace đã nghiệm thu tới đâu, còn hổng gì | `flag-trace/PHASE2_REPORT.md` ← **đọc mục "Giới hạn" trước khi tin kết quả** |

`contest-runtime/config/services.json` là **nguồn sự thật duy nhất**. Mọi thành phần đọc
từ đó. Sửa xong luôn chạy `bash contest-runtime/config/validate-config.sh`.

---

## 3. Dựng stack

```bash
MODE=contest bash deploy-all.sh      # 7 bước, chạy lại bao nhiêu lần cũng an toàn
```

`MODE=prep` chỉ dùng khi diễn tập ở nhà. **Không dùng `MODE=prep` lúc thi thật.**

Kiểm tra còn sống:

```bash
curl -s http://127.0.0.1:8080/api/status | python3 -m json.tool | head -40
```

Dashboard ở `http://127.0.0.1:8080`, Tulip ở `:3000`.

### Việc đầu tiên khi thấy System Status trống

`host_agent.py` chạy **trên host, không trong Docker**, nên **không tự khởi động lại** khi
máy/Docker restart. Container lên lại hết nhưng System Status vẫn trống thì gần như chắc
chắn là nó chết:

```bash
nohup python3 contest-runtime/host_agent.py >.host-agent.log 2>&1 &
```

Trạng thái mới xuất hiện sau ~30 s (mỗi chu kỳ push phải chờ SSH tới vulnbox timeout).
Cũng phải chạy lại lệnh này sau khi sửa `contest-runtime/health_check.py`.

---

## 4. Bản đồ dữ liệu

```
vulnbox ──tcpdump──> traffic/*.pcap ──┬──> Tulip (Postgres)      : xem flow thô, :3000
                                      └──> Flag-trace (SQLite)   : hồ sơ + chuỗi tấn công
                                             data/flagtrace/flagtrace.sqlite3  (gitignored)
```

- **Tulip** giữ flow thô. Để **nguyên bản (vanilla)** — mọi thứ của ta nằm ngoài nó.
- **Flag-trace** là SQLite riêng. Chỉ `ctf-flagtrace` được ghi schema; worker và API mở
  cùng file nhưng không chạy DDL.
- Phiên bản hiện tại: schema **v7**, engine **p2.5.1**, exporter **p2.5.2**, normalizer **n1**.
  (Kiểm: `docker exec ctf-flagtrace python -c "from flagtrace.app import migrations; print(migrations.SCHEMA_VERSION)"`)

---

## 5. Luồng phòng thủ: từ flag-out tới chuỗi tấn công

Mở tab **FLAG TRACE** trên dashboard.

1. **Hồ sơ (profile)** = một transaction mà **response có chứa flag**. Mỗi lần như vậy là
   một hồ sơ riêng.
2. **Danh sách gộp**: flag-out giống hệt nhau (cùng nguồn, service, flag, request) gom
   thành một dòng, bấm `×N` để xem từng lần. Bỏ tick *group identical flag-outs* để xem thô.
3. **Timeline** = chuỗi bước đã dẫn tới flag-out đó, nối bằng **giá trị**, không phải bằng
   thời gian. Cột **Tulip** mở flow thô tương ứng.
4. **Values** = mỗi field trong request là loại gì, tức script phải lấy nó ở đâu:
   `linked` (bóc từ response trước) · `generated` (tự sinh) · `target` (flag ID) ·
   `unknown` (không rõ) · không liệt kê = hằng số, gửi nguyên văn.
5. **Chain shape / nhóm** = các chuỗi cùng cấu trúc, bất kể giá trị. Số hồ sơ trong nhóm
   cho biết **bug nào đang bị khai thác nhiều** → ưu tiên vá hoặc viết rule.
6. **Steps that differ from the checker** = bước lệch khỏi baseline dựng từ request của
   chính checker. Là **manh mối**, không phải kết luận.

### Điều quan trọng nhất phải hiểu

Một **cạnh nối** chỉ nói "cùng một giá trị xuất hiện ở hai nơi", **không** nói cái này gây
ra cái kia. Mọi giới hạn đã cắt ngắn tìm kiếm, và mọi giá trị không giải thích được, đều
được ghi ngay cạnh kết quả. Đừng báo cáo một chain như bằng chứng đã tìm ra bug.

API tương ứng (proxy qua dashboard, đều là GET):

```
/api/flagtrace/traces                      danh sách hồ sơ
/api/flagtrace/traces/{t}/runs/{r}         chi tiết: steps, edges, value_roles, grouping, suspects, scripts
/api/flagtrace/trace-groups                flag-out trùng nhau, gộp dòng
/api/flagtrace/chain-groups                nhóm chuỗi cùng cấu trúc
/api/flagtrace/trace-status                worker còn sống không
/api/flagtrace/decoder                     chế độ decoder hiện tại
```

---

## 6. Luồng tấn công: chuỗi → script

Mỗi run sinh ra artifact bất biến: một script cho từng request, và một script cho cả
chuỗi. Lấy bằng nút Copy/Download trên dashboard, hoặc:

```
GET /api/flagtrace/traces/{trace}/runs/{run}/scripts/{artifact}
```

**Đọc `support` trước khi chạy.** Đây là chỗ mất thời gian nhất nếu bỏ qua:

| `support` | Nghĩa |
|---|---|
| `supported` | Mọi giá trị đều có vai trò rõ ràng. Chạy được như hiện trạng. |
| `needs_edit` | **Có giá trị bị gửi nguyên văn vì không suy được.** Phải sửa tay trước khi chạy. Cảnh báo ghi rõ field nào. |
| `unsupported` | Chưa xuất được (raw TCP — chờ Phase 1 ghi được byte span của từng lượt gửi/nhận). |

### Lỗi thường gặp nhất của `needs_edit`

Giá trị **lần đầu do attacker gửi và không dùng lại ở bước sau** (ví dụ `email` lúc đăng
ký) bị xếp `unknown`, nên script gửi lại **nguyên văn**. Chạy lần hai thì đăng ký trùng →
tài khoản không được tạo → bước đăng nhập trả `null` → bước sau hỏng.

Từ exporter `p2.5.2`, script sẽ nói rõ lý do thay vì ném `KeyError` trống:

```
no ['data', 0, 'signIn', 0, 'access_token', 0] (at ['data', 0, 'signIn', 0]) in this response:
found null there, which is neither an object nor a list. The step meant to produce it
probably failed. Response began: '{"errors":[{"message":"email already exists"}],...'
```

Thấy thông báo kiểu này thì **lỗi nằm ở bước trước**, không phải ở bước báo lỗi. Sửa giá
trị bị gửi nguyên văn mà cảnh báo đã chỉ tên, và giữ đúng định dạng của nó
(`...@local.test` vẫn phải là email hợp lệ).

**Nhãn `reproduced`** chỉ được gắn khi đã replay thành công trên fixture local. Dashboard
không bao giờ tự bắn script vào service đang thi.

---

## 7. Những cái sẽ cắn bạn

Toàn bộ mục này là lỗi thật đã xảy ra, không phải giả định.

- **`host_agent.py` không tự dậy lại.** Xem mục 3.
- **Chế độ decoder được giữ qua restart.** Hạ xuống `gated`/`off` lúc bị bắn nhiều thì nó
  **ở nguyên đó** tới khi có người nâng lại; System Status báo vàng. `off` làm **mất**
  flag-out chỉ lộ ra sau khi decode (trên dataset thật là 43/95). Về mặc định: nút *Back to
  config default*, hoặc `POST /api/flagtrace/decoder {"mode":"default"}`.
- **Lab local không có checker.** Nên không có baseline và không có flag ID:
  `suspects.state = no_baseline`, và không giá trị nào được gọi là `target`. Đúng thiết kế,
  **không phải lỗi**. Phần đó mới chỉ kiểm bằng fixture, chưa kiểm trên giải thật.
- **Đừng để file `.py` lạ trong `/tmp`.** Python nạp module từ thư mục của script, nên một
  file `/tmp/re.py` sẽ **che mất module `re` chuẩn** và làm hỏng mọi script chạy từ `/tmp`
  — kể cả script do exporter sinh ra. Đã xảy ra: artifact lưu tay thành `re.py`. Chạy test
  với `TMPDIR` khác, hoặc đổi tên file.
- **Mỗi bước là một flow Tulip, nhưng flow ID không được lưu.** Khớp được làm lúc hiển thị
  (thời gian + IP/port). Ingest lại capture không để lại ID cũ sai. `✓` là khớp đúng IP,
  `~` là chỉ gần nhất theo thời gian.
- **Đổi engine thì run cũ không tự tính lại.** Worker tự xin phân tích lại theo trigger có
  version (`auto:scripts:*`, `auto:grouping:*`); ngoài ra phải bấm Re-analyse. Run cũ giữ
  nguyên kết luận cũ — đó là chủ ý, không phải bug.
- **Đừng `pkill -f <pattern>` khi pattern đó cũng nằm trong chính dòng lệnh đang chạy** —
  nó tự giết shell gọi nó (exit 144). Lấy PID trước, kill ở lệnh riêng.

---

## 8. Sửa code

### Chạy test (bắt buộc trước khi deploy)

```bash
cd contest-runtime/flagtrace/transport && GOPROXY=off go build -o /tmp/ft-transport .
cd ../.. && TMPDIR=/some/clean/dir FLAGTRACE_TRANSPORT=/tmp/ft-transport \
  python3 -m unittest discover -s flagtrace/tests
```

Hiện có 112 test. Kiểm tra trên trình duyệt (72 mục, cần Playwright) nằm ở
`contest-runtime/dashboard/tests/flagtrace_ui/` — chạy `serve_fixture.py` trước rồi tới
`check.py` / `check_groups.py` / `check_chains.py`.

### Deploy lại Flag-trace

```bash
C="docker compose -f docker-compose.contest.yml --profile flagtrace"
$C build flagtrace
# Chỉ khi schema đổi: dừng cả hai writer rồi mới migrate (tự backup vào data/flagtrace/backups/)
$C stop flagtrace flagtrace-worker
$C run --rm --no-deps flagtrace python -m flagtrace.app.main migrate
$C up -d flagtrace flagtrace-worker
```

**File tĩnh của dashboard được nướng vào image** — sửa `static/` xong phải
`docker compose -f docker-compose.contest.yml build dashboard` rồi `up -d --no-deps dashboard`,
không thì trình duyệt vẫn nhận bản cũ.

### Quy ước trong repo

- Mọi thứ đọc từ `services.json`. Đừng hardcode IP/port/regex ở chỗ khác.
- **Tulip giữ nguyên bản.** Code của ta nằm ngoài; đừng patch Tulip.
- Kết quả phân tích là **bất biến**. Phân tích lại tạo run mới, không sửa run cũ.
- Nói rõ cái gì là bằng chứng, cái gì là suy đoán. Giới hạn và dữ liệu thiếu phải hiển thị
  cạnh kết quả, không giấu đi.
- Không có đường LLM/generative nào trong repo này, và đừng thêm vào.
