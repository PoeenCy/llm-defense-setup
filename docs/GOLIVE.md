# GOLIVE.md — Chuyển từ luyện tập (mock-vulnbox) sang thi thật

> Viết ban đầu trong lúc diễn tập (2026-10-10), cập nhật lại sau khi ctf_proxy thật đã deploy và
> test thành công trên vulnbox thật (DFCD practice arena) — 2026-10-14, cập nhật lại lần nữa sau
> khi sửa và test thật cơ chế capture + honeytoken/OS-watchdog — 2026-10-16. Đọc từ trên xuống,
> làm theo đúng thứ tự. Đừng nhảy cóc.
>
> Không có LLM/AI nào trong hệ thống này — mọi quyết định chặn là người tự đọc flow rồi bấm.

## Đã test thật tới đâu (2026-10-16, DFCD practice arena, team-03) — đọc trước khi tin bất cứ dòng nào dưới đây

| Thành phần | Trạng thái | Bằng chứng |
|---|---|---|
| Capture (tcpdump remote + pull về `traffic/`) | **Đã test live** | Chạy nhiều vòng rotate thật, pcap về đúng, không rò rỉ process/đĩa trên vulnbox |
| ctf_proxy nhiều service + multi-condition rule + raw-TCP | **Đã test live** | Build → apply → APPLIED tab → delete, chu trình đầy đủ qua `dfcd-vbox` thật |
| OS-watchdog (báo động + lọc nhiễu) | **Đã test live** | Alert thật đi qua cơ chế pull mới, lọc nhiễu xong vẫn bắt đúng 1 sự kiện thật (mysql query) |
| Honeytoken — HTTP trap (port 7777) | **Đã test live** | Bấm trúng trap qua SSH, xác nhận log + Redis + dashboard khớp |
| Honeytoken — file mồi + inotify | **Chưa test live** | Vulnbox DFCD không có cài `inotify-tools` → nhánh này chưa có cơ hội chạy thật, chỉ sửa đúng cấu trúc (không sudo-fail nữa) nhưng chưa thấy nó tự bắt một lần đọc file thật nào |
| `monitor_host.ip` / hướng vulnbox→monitor | **Hạn chế hạ tầng đã xác nhận** | VPN practice arena này chỉ cho monitor→vulnbox, không cho ngược lại — đã có cơ chế pull bù, nhưng **chưa biết giải thật SVANM 2026 có khác không** |
| Honeytoken đặt trên host (không phải trong container app) | **Hạn chế kiến trúc đã xác nhận, chưa sửa** | Flag thật nằm trong container `node` (`/flag`), file mồi hiện đặt trên host — kẻ tấn công khai thác app thật sẽ không chạm tới. Vẫn có giá trị nếu có container-escape |

Tất cả trên đều là DFCD practice arena, **không phải giải SVANM 2026 thật**. Hạ tầng VPN/mạng của
giải thật có thể khác — làm lại đúng mục "Xác minh `monitor_host.ip`" dưới đây ngay khi vào mạng
thi thật, đừng giả định giống practice arena.

## Tổng quan sự khác biệt

| | Luyện tập (`MODE=prep`) | Thi thật (`MODE=contest`) |
|---|---|---|
| Vulnbox | `mock-vulnbox` container, giả | VM thật của bạn, do ban tổ chức cấp |
| Traffic vào Tulip | Đọc file pcap tĩnh trong `traffic/`, hoặc live qua `PCAP_OVER_IP` nếu vulnbox có pcap-broker | Giống hệt — không phân biệt theo MODE, phân biệt theo cách capture (xem Phase 0, câu 3) |
| ctf_proxy | Front `mock-vulnbox` (nếu bật) | Front TẤT CẢ service `"proto": "tcp"` thật trong `services.json` — **đã code xong, đã test live** (xem Phase 2) |
| `services.json` | IP/port giả | IP/port/flag regex **thật** do ban tổ chức cho — đổi được bất cứ lúc nào, mọi nơi đọc port đều đọc động từ file này |

---

## PHASE 0 — Khung 5 câu hỏi (dùng cho MỌI môi trường thi mới, không riêng gì lần này)

Mỗi giải có hạ tầng khác nhau (VM riêng, container share host, có/không VPN...). Đừng đoán —
trả lời đúng 5 câu này rồi map thẳng vào `contest-runtime/config/services.json`, không cần sửa
code trừ câu 3 nếu rơi vào trường hợp hiếm.

| # | Câu hỏi | Lệnh kiểm tra nhanh | Map vào field nào |
|---|---|---|---|
| 1 | Làm sao vào mạng thi? Đã connect chưa? | `ip addr`, `ping <scoreboard_ip>` | `monitor_host.ip` = IP mình thấy trên mạng đó — **đừng chỉ đoán, xem mục "Xác minh `monitor_host.ip`" ngay dưới đây trước khi qua Bước 1** |
| 2 | Vulnbox của mình: máy riêng hay container share host? | `ssh <key> -p <port> <user>@<ip> hostname` | `vulnbox.ip`, `ssh_user`, `ssh_port` |
| 3 | **Có chỗ nào chạy `tcpdump` với quyền root, thấy traffic thật không?** | xem bảng quyết định dưới | quyết định cách bắt gói tin (xem dưới) |
| 4 | Flag format thật? | hỏi ban tổ chức / đọc rules | `flag.regex` |
| 5 | Port/service thật cần theo dõi — **có thể nhiều hơn 1, protocol khác nhau** | hỏi ban tổ chức / `nmap`/`curl`/`nc` thử | `services[]` — xem format ở Bước 1 dưới |

**Câu 3 — các nhánh có sẵn, không cần code mới, chỉ chọn đúng nhánh:**

| Tình huống | Làm gì |
|---|---|
| Chưa có gì, chỉ muốn test tool | `MODE=prep bash deploy-all.sh` (bật `mock-vulnbox`, container giả, local) |
| Vulnbox tự chạy sẵn pcap-broker (hiếm, ban tổ chức phải set up) | `vulnbox.live_pcap_broker: true` — Tulip nhận live stream qua `PCAP_OVER_IP` |
| Có root+tcpdump ở ĐÂU ĐÓ thấy traffic thật (vulnbox thật, hoặc máy admin khác như trường hợp DFCD) — **nhưng không có broker** | `bash contest-runtime/monitor/deploy-capture-pull.sh` — tcpdump remote + rsync kéo pcap về `traffic/` mỗi 15s, Tulip đọc qua directory-watch (mặc định đã là chế độ này, `deploy-all.sh` tự gọi) |

**Ví dụ thật đã làm (DFCD practice arena, team-03):** team key (`vulnbox.ssh_user/ssh_port`)
chỉ vào được container `public-proxy`, không có `tcpdump`/root thật trong đó. Nhưng có SSH
admin riêng (`~/.ssh/config` alias `dfcd-vbox`, ProxyJump qua gameserver) thấy được tới
`vulnbox-host`. Hai field dùng cho trường hợp này: `vulnbox.capture_ssh_alias` (SSH alias có sẵn,
không cần tự dựng lại ProxyJump trong script), `vulnbox.capture_iface` (để `"auto"` thì script tự
dò interface external qua `ip route`, chỉ set tay nếu `eth0` không phải nơi IP public nằm).

**Lưu ý an toàn:** đừng commit/push `services.json` lên git khi nó đang chứa IP/thông tin hạ
tầng thi thật của một giải chưa kết thúc.

---

## PHASE 1 — Monitor + Detect

### Bước 0 — Thu thập thông tin từ ban tổ chức

Trước khi đổi config, cần có:
- [ ] IP của vulnbox của team mình
- [ ] SSH user + cách auth (key hay password?) vào vulnbox
- [ ] Regex flag thật (ví dụ `ENOFLAG[A-Za-z0-9+/=]{32}` — mỗi giải khác nhau)
- [ ] CIDR của teams network (để phân biệt traffic đồng nghiệp vs đối thủ)
- [ ] URL submit flag (gameserver) — không bắt buộc cho monitor, chỉ cần nếu muốn tự động nộp
- [ ] Danh sách **từng** service + port thật trên vulnbox (tên, port, http hay raw tcp hay udp,
      và tên service trong docker-compose của vulnbox đang bind port đó nếu biết — cần cho Phase 2)
- [ ] IP của máy monitor này trên mạng thi (dùng lệnh `ip addr` hoặc hỏi ban tổ chức)

### Xác minh `monitor_host.ip` — đừng chỉ đoán, test thật

Lỗi thật đã gặp (2026-10-16, DFCD practice arena): `monitor_host.ip` bị gõ sai một lần, và dù
`ssh` tới vulnbox vẫn chạy bình thường (hướng monitor→vulnbox không liên quan gì tới giá trị
này), **honeytoken và OS-watchdog báo về bị mất hoàn toàn, âm thầm, không có lỗi gì hiện ra** —
chỉ phát hiện được nhờ test tay. Lý do: SSH và các report push là 2 hướng kết nối khác nhau.

**3 bước xác minh, làm đúng thứ tự trước khi deploy thật:**

```bash
# 1. IP thật của máy này trên mạng thi (KHÔNG suy luận, đọc trực tiếp)
ip -4 addr show   # tìm interface của VPN/mạng thi, lấy đúng IP đó — không phải IP LAN/wifi

# 2. Tự curl chính mình qua IP đó (sanity check: port 9999 nghe đúng chưa)
curl -s -m 3 http://<IP vừa tìm được>:9999/health

# 3. QUAN TRỌNG NHẤT — từ vulnbox, curl NGƯỢC LẠI về đúng IP/port đó (xem Bước 2
#    ở dưới để có SSH alias trước). Đây là hướng thật honeytoken/OS-watchdog cần,
#    khác hẳn hướng SSH monitor→vulnbox đã quen test:
ssh <vulnbox_ssh_alias> "curl -s -m 5 http://<IP máy monitor>:9999/health"
```

Nếu bước 3 timeout (không phải "connection refused" — refused nghĩa là tới được nhưng không ai
nghe, còn timeout nghĩa là không có đường đi): **mạng VPN của giải không cho chiều
vulnbox→monitor**, không phải lỗi config. Gặp đúng trường hợp này ở DFCD practice arena — hệ
thống đã có cơ chế dự phòng cho ca này (xem khung "Honeytoken/OS-watchdog không tới được
monitor?" ở Bước 2), **không cần làm gì thêm**, chỉ cần biết để không hoang mang khi thấy cảnh
báo "vulnbox can NOT reach..." lúc deploy.

### Bước 1 — Sửa `contest-runtime/config/services.json`

```bash
nano contest-runtime/config/services.json
```

Sửa đúng các field sau (đừng đổi tên field, chỉ đổi giá trị):

```json
"vulnbox": {
  "ip": "<IP vulnbox thật>",
  "ssh_user": "<user SSH thật>",
  "ssh_port": 22,
  "capture_iface": "auto",          // "auto" tự dò; set tay nếu cần
  "pcap_broker_port": 4242
},
"monitor_host": {
  "ip": "<IP máy monitor này trên mạng thi>",
  ...
},
"flag": {
  "regex": "<regex flag thật>",
  "submit_url": "<URL submit thật, nếu có>"
},
"teams_cidr": "<CIDR mạng teams thật>",
"services": [
  {
    "name": "web", "port": 8003, "proto": "tcp", "layer": "l7-http",
    "compose_service": "public-proxy"   // tên service trong compose của vulnbox — cần cho Phase 2
  },
  {
    "name": "pwn1", "port": 9999, "proto": "tcp", "layer": "l4-raw",
    "compose_service": "pwn-service"    // ví dụ: service raw TCP (không phải HTTP) — khai layer "l4-raw"
  },
  {
    "name": "dns1", "port": 5353, "proto": "udp", "layer": "l4-udp"
    // UDP: vẫn capture/alert được, nhưng KHÔNG dùng được ctf_proxy ở Phase 2 — xem lưu ý dưới
  }
]
```

Mỗi service trong mảng được capture/giám sát độc lập — khai **bao nhiêu service cũng được**,
không giới hạn 1. `proto` ∈ `tcp`/`udp`. `layer` quyết định ctf_proxy đọc service đó như HTTP
(`l7-http`/`l7-https`) hay raw TCP (`l4-raw`) ở Phase 2; `l4-udp` nghĩa là Phase 2 sẽ tự bỏ qua
service này (in cảnh báo, không lỗi) — dùng chặn-theo-nội-dung (SERVICES tab) cho UDP.

```bash
bash contest-runtime/config/validate-config.sh     # phải PASS trước khi tiếp tục
```

### Bước 2 — Deploy capture + honeytoken + OS-watchdog lên vulnbox thật (qua SSH)

```bash
# Đảm bảo SSH vào vulnbox được trước (test tay 1 lần):
ssh -p 22 <ssh_user>@<vulnbox_ip> echo ok

# 1. Deploy capture (tcpdump + rsync kéo pcap về) — bắt buộc
bash contest-runtime/monitor/deploy-capture-pull.sh

# 2. Deploy honeytoken (đặt flag giả làm bẫy) — khuyến nghị
bash contest-runtime/detection/deploy-honeytoken.sh

# 3. Deploy OS watchdog (file-integrity + process monitor) — khuyến nghị
bash contest-runtime/watchdog/deploy-os-watchdog.sh
```

Nếu script nào fail: đọc lỗi SSH trước (sai user/key/port là nguyên nhân phổ biến nhất),
đừng đoán.

**Honeytoken/OS-watchdog không tới được monitor? (dòng `[WARN] vulnbox can NOT reach...`)**
Cả hai đều **tự chuyển sang kiểu hỏi-ngược** nếu không gửi được: `host_agent.py` (chạy sẵn trên
máy monitor, trong `MODE=contest bash deploy-all.sh` ở Bước 3) tự SSH sang vulnbox mỗi 20 giây
hỏi "có cảnh báo mới nào chưa báo được không", rồi đẩy vào dashboard giống như nhận được báo
trực tiếp — **không cần làm gì thêm, tự chạy ngay sau khi 2 script trên deploy xong và
`host_agent.py` đang sống**. Dòng `[WARN]` ở trên chỉ là cảnh báo "cách gửi trực tiếp không
dùng được", không phải báo lỗi toàn bộ tính năng. Muốn chắc chắn đang hoạt động: xem
`.host-agent.log` có dòng `os-watchdog alert pull every 20s` + `honeytoken alert pull every 20s`
khi khởi động, hoặc `cat contest-runtime/.oswatchdog-pull-state.json` /
`cat contest-runtime/.honeytoken-pull-state.json` thấy `last_id` tăng dần theo thời gian.

### Bước 3 — Bật hệ thống monitor

```bash
MODE=contest bash deploy-all.sh
```

Kỳ vọng thấy: preflight OK → validate-config PASS → capture start → honeytoken/OS-watchdog deploy
→ ctf_proxy **chỉ nếu** `ctf_proxy.insertion.mode` là `"docker-compose"` trong config (xem Phase 2
— có thể để Phase 1 chạy một mình trước, deploy ctf_proxy sau khi đã quan sát ổn) → health check
tất cả UP.

### Bước 4 — Xác nhận traffic thật đang vào

```bash
# Assembler phải thấy traffic LIVE
docker logs tulip-assembler-1 --tail 20

# Dashboard — mở trình duyệt
xdg-open http://localhost:8080

# Watchdog phải thấy service thật đang sống
docker logs ctf-watchdog --tail 10
```

**Dấu hiệu mọi thứ ổn:** Tulip UI (`localhost:3000`) hiện flow thật đang chạy qua, watchdog
không báo `SERVICE DOWN` liên tục, tab EVENTS trên dashboard có event mới.

---

## PHASE 2 — ctf_proxy thật (ĐÃ CODE XONG, ĐÃ TEST LIVE)

Khác với bản viết lúc diễn tập (lúc đó Phase 2 "chưa làm"), phần này giờ **đã hoạt động thật** —
`contest-runtime/defense/deploy-ctfproxy.sh` tự:
1. Đọc **mọi** service `"proto": "tcp"` trong `services.json` (bỏ qua `"proto": "udp"` — ctf_proxy
   không hỗ trợ UDP, không có nhánh nào để làm được việc này, dùng chặn-theo-nội-dung thay thế).
2. Với mỗi service: xác minh port đang bind đúng `compose_service` khai trong config, gỡ port đó
   khỏi compose file gốc (có backup), nối ctf_proxy vào, build+start.
3. Verify lại traffic thật vẫn chạy qua từng port sau khi xong.

```bash
bash contest-runtime/defense/deploy-ctfproxy.sh
```

An toàn khi chạy lại nhiều lần: service đã có ctf_proxy rồi thì bị skip (không tìm thấy port
binding cũ để gỡ nữa), không làm gì — không có rủi ro double-insert. Rule đang áp trên filter của
một service **không bị mất** khi chạy lại script (đã verify: rsync không đụng tới
`filter_modules/<service>/` đã tồn tại, nó chỉ tạo file mới nếu service đó thật sự chưa từng được
deploy).

**Vẫn đúng với bản cũ — risk thật, vẫn phải cẩn thận:**
- ctf_proxy auto-block traffic sai có thể làm rớt SLA. **Luôn Test on recent traffic** (tab RULES)
  trước khi Check & Upload, dù đã tin filter đúng.
- Downtime ngắn (vài giây) mỗi lần một service được chuyển port qua ctf_proxy lần đầu, hoặc mỗi
  lần `docker compose up` phải recreate service gốc — tránh chạy lúc đang bị tính SLA liên tục nếu
  không bắt buộc; chạy ở giờ nghỉ/tick không quan trọng nếu có thể.
- Có kế hoạch rollback nhanh: SERVICES tab → ctf_proxy → **Uninstall (emergency)** — trả port về
  TẤT CẢ service gốc cùng lúc trong vài giây, dùng khi chính ctf_proxy là vấn đề (không phải 1
  rule cụ thể — nếu chỉ 1 rule gây hại, dùng **Pause filtering** hoặc Rollback rule đó thôi, không
  cần Uninstall).

**Service raw TCP (không phải HTTP):** rule builder trên tab RULES tự biết chỉ cho chọn
`target: raw` (đọc bytes thô, không có url/path/param) khi bạn chọn đúng service đó ở dropdown.

**Service UDP:** không xuất hiện trong dropdown ctf_proxy ở tab RULES (không eligible). Dùng
SERVICES tab → "Fallback block — theo NỘI DUNG" (iptables `--string` match, hoạt động bất kể
TCP/UDP) nếu cần chặn chủ động.

---

## Rollback về chế độ luyện tập

```bash
MODE=contest bash teardown.sh
# services.json: chuyển sang file luyện tập, hoặc đơn giản chạy lại ở MODE=prep
MODE=prep bash deploy-all.sh
```
