# CTF Monitor Hub — Runbook vận hành

> **Vai trò:** Máy monitor chính cho giải Attack-Defense CTF.  
> **Máy này:** Nạp traffic, chạy detection, phục vụ dashboard theo dõi tình huống.  
> **Không có đường LLM/generative-AI nào trong repo này** (đã gỡ bỏ — xem `docs/STATUS.md`).
> Thành phần duy nhất liên quan tới model là bộ phân loại `ml-fingerprint` (tuỳ chọn, sklearn,
> không sinh nội dung, tắt mặc định) — xem ghi chú tuân thủ ở Item D trong `docs/STATUS.md` nếu
> điều lệ giải của bạn quan tâm việc này.

---

## Khởi động nhanh — bật 1 lệnh

```bash
MODE=contest bash deploy-all.sh
```
(Dùng `MODE=prep` khi luyện tập ở nhà — bật thêm bộ phân loại tuỳ chọn `ml-fingerprint` và
target diễn tập `mock-vulnbox` nếu `services.json` cho phép. **Không bao giờ dùng `MODE=prep`
vào ngày thi thật.**)

Chạy theo thứ tự: **preflight** (kiểm tra có docker/docker-compose/python3, module Python
`redis` import được — tự cài qua pip nếu thiếu, và **báo lỗi rõ ràng kèm lệnh sửa chính xác**
nếu vẫn không cài được, thay vì để `host_agent.py` crash âm thầm về sau) → kiểm tra config →
bật stack local (Tulip/detection/dashboard/watchdog) → bắt traffic từ xa (tự dò interface
external, không cần biết tên docker-bridge) → ctf_proxy (chỉ khi `ctf_proxy.insertion` trong
`services.json` đã khai đủ và mọi điều kiện tiên quyết được xác minh lại qua SSH — nếu không thì
tự bỏ qua gọn gàng, vẫn ở chế độ chỉ-giám-sát) → báo cáo `health-check.sh` cuối cùng. **An toàn
khi chạy lại bất cứ lúc nào** — mọi bước đều idempotent, không có gì ở đây xoá dữ liệu.

Nếu không tới được vulnbox, stack local vẫn lên bình thường (bước 4-5 ghi cảnh báo rõ ràng rồi
tiếp tục) — chỉ là chưa có traffic thật cho tới khi sửa xong. Xem mục Troubleshooting của file
này → "Luôn bắt đầu ở đây" (`health-check.sh`) để chẩn đoán đúng cái gì đang hỏng.

### Thiết lập lần đầu (trước khi chạy được deploy-all.sh)

Phần này không tự động hoá được — các giá trị dưới đây đặc thù cho team và mạng thi của bạn,
chỉ con người mới điền đúng được. Mọi thứ SAU bước này đều đã được viết script và tự kiểm tra.

```bash
# 1. Sửa config trung tâm — file DUY NHẤT bạn tự tay sửa
nano contest-runtime/config/services.json
#   Phải điền tối thiểu: team_id, vulnbox.ip, monitor_host.ip, flag.regex,
#   teams_cidr, services[] (port service thật của bạn). Xem docs/SCHEMA.md
#   để biết từng field, và docs/GOLIVE.md cho checklist nhận bàn giao từ BTC.

# 2. Kiểm tra config — bắt lỗi gõ sai/thiếu field TRƯỚC khi chạy gì khác
bash contest-runtime/config/validate-config.sh
#   Mọi dòng [FAIL] ở đây phải sửa xong trước khi tiếp tục — config sai thì
#   không có bước nào sau đó chạy đúng, và các bước sau cũng sẽ báo lại y vậy.

# 3. (khi còn internet) Đóng gói mọi thứ để dùng offline
bash pull-and-save.sh       # ~10-20 phút, tải vài GB image/wheel/repo
```

### Máy air-gapped, ngày thi

```bash
# 1. Copy offline-bundle/ từ máy chuẩn bị (chuyển qua USB/LAN)
rsync -a offline-bundle/ /path/to/Setup_tool/offline-bundle/

# 2. Restore từ bundle (không gọi mạng) — báo [FATAL] và dừng ngay nếu
#    offline-bundle/ thiếu hoặc không đầy đủ, thay vì restore nửa vời
bash offline-restore.sh

# 3. Bật 1 lệnh
MODE=contest bash deploy-all.sh
```

**Nếu bước 1-3 có gì lỗi:** mọi script trong repo này (`validate-config.sh`, `bringup.sh`,
`offline-restore.sh`, `deploy-all.sh`) đều in dòng `[FATAL]`/`[FAIL]` và trả exit code khác 0
khi gặp vấn đề thật — không bao giờ âm thầm tiếp tục trong trạng thái nửa vời. Nếu bạn thấy một
Python traceback trần (không qua định dạng trên), đó chính là một bug đáng báo lại, không phải
thứ để chạy lại mù quáng cho qua.

---

## Tổng quan kiến trúc

```
                    ┌─────────────────────────────────────────┐
                    │          Monitor Machine (this box)      │
                    │                                          │
  vulnbox ──pcap──▶ │  Tulip (TimescaleDB + Assembler)        │
  (pcap-broker)     │    ▲                                     │
                    │    │ flows                               │
                    │  ┌─┴──────────────────────────────────┐  │
                    │  │         Detection Layer (Item 4)   │  │
                    │  │  • flag-out regex scan              │  │
                    │  │  • Suricata alert ingester          │  │
                    │  │  • honeytoken HTTP collector        │  │
                    │  └────────────────┬───────────────────┘  │
                    │                   │ alerts                │
                    │  ┌────────────────▼───────────────────┐  │
                    │  │         Redis (alert queue)         │  │
                    │  └──┬─────────────┬───────────────────┘  │
                    │     │             │                       │
                    │  ┌──▼──┐      ┌──▼──────────────────┐   │
                    │  │ML FP│      │  Dashboard (Item 8)  │   │
                    │  │prep-│      │  WebSocket → browser │   │
                    │  │only │      └─────────────────────┘    │
                    │  └─────┘                                 │
                    │  Watchdog (SLA poller, Item 7)            │
                    └─────────────────────────────────────────┘
```

---

## Service & Port

| Service | Port | Mô tả |
|---------|------|-------------|
| Dashboard | 8080 | Giao diện giám sát tổng hợp |
| Tulip UI | 3000 | Xem chi tiết flow |
| Detection/Honeytoken | 9999 | Thu alert + honeytoken |
| Redis | 6380 | Hàng đợi alert chung |

Chỉ `MODE=prep` (không bao giờ dùng ngày thi thật): `mock-vulnbox` (target giả) và
`ml-fingerprint` (gợi ý lệch chuẩn bot qua Redis, không có port publish) — cả hai tắt mặc định,
xem `services.json`.

---


## Thứ tự bật dịch vụ

Các service **phải** bật đúng thứ tự này (do `bringup.sh` lo):

1. **Redis** — hàng đợi alert chung (mọi service khác đều phụ thuộc vào nó)
2. **Tulip stack** — nạp traffic + TimescaleDB
3. **Detection service** — scanner flag-out, thu honeytoken
4. **Watchdog** — poller SLA
5. **Dashboard** — UI tổng hợp
6. *(chỉ `MODE=prep`)* **ML Fingerprint** — bộ fingerprint bot (khởi động: 3 tick), nếu
   `ml_classifier.enabled` trong `services.json` là true
7. *(chỉ `MODE=prep`)* **mock-vulnbox** — target diễn tập, nếu `mock_vulnbox.enabled` là true

---


## Quy trình Restore Offline

> Dùng trên máy air-gapped sạch. Phải chuyển `offline-bundle/` qua trước.

```bash
# Điều kiện cần
which docker && docker compose version   # Docker 24+ kèm plugin compose v2
which python3                             # Python 3.11+
python3 -c "import redis" || pip3 install --user redis   # host_agent.py cần cái này

# Bước 1: Nạp Docker image (báo lỗi rõ ràng nếu offline-bundle/ thiếu/không đủ)
bash offline-restore.sh

# Bước 2: Xác nhận
docker images | grep tulip           # phải thấy image tulip-*
docker images | grep redis           # phải thấy redis:7-alpine

# Bước 3: Bật
MODE=contest bash bringup.sh --offline
```

### Xác nhận máy thật sự air-gapped (không có mạng)

```bash
# Tất cả các lệnh này phải FAIL (timeout/refused) trên máy air-gapped:
curl --connect-timeout 3 https://docker.io
curl --connect-timeout 3 https://pypi.org
```

---

## Test nghiệm thu (chạy sau khi bật hệ thống)

### Test 1: Phát hiện flag-out trong <2 giây

```bash
# Bắn thử một alert flag-out giả
curl -X POST http://localhost:9998/test/inject-flag
# Kỳ vọng: 200 OK + alert xuất hiện trên dashboard trong vòng 2 giây
```

### Test 2: Alert honeytoken

```bash
# Kích hoạt endpoint honeytoken
curl -X POST http://localhost:9999/honeytoken
# Kỳ vọng: alert type=honeytoken xuất hiện trên dashboard
```

### Test 3: Watchdog SLA báo trong <5 giây

```bash
# Tắt thử một service giả (ví dụ chặn port bằng iptables)
sudo iptables -I INPUT -p tcp --dport 9001 -j REJECT
sleep 5
curl http://localhost:8080/api/alerts | python3 -m json.tool | grep sla-down
# Khôi phục lại
sudo iptables -D INPUT -p tcp --dport 9001 -j REJECT
```

### Test 4: Dashboard hiển thị đủ mọi loại tín hiệu

1. Chạy test 1, 2, 3 ở trên
2. Mở `http://localhost:8080`
3. Xác nhận: flag-out (đỏ), honeytoken (đỏ), sla-down (đỏ) đều hiện ra
4. Xác nhận thứ tự ưu tiên: flag-out/honeytoken ở trên cùng, gợi ý ML ở dưới cùng (chỉ
   `MODE=prep`)

---


## Deploy các thành phần phía Vulnbox

> **Đây là cách thật đang dùng trong thực tế — KHÔNG phải thiết kế pcap-broker được mô tả ở
> những doc cũ khác.** `pcap_broker_port` trong services.json không được dùng; capture thật đi
> qua SSH + tcpdump + rsync pull, vì vulnbox ở đây là một container Docker trên máy Azure chung
> mà mình không quản lý, chỉ tới được qua `ssh dfcd-vbox` (alias trong `~/.ssh/config`,
> ProxyJump qua gameserver).

### Bước 0 — xác nhận có tới được không

```bash
ssh dfcd-vbox "echo OK"
```
Nếu timeout ("Connection timed out during banner exchange"), VM Azure có thể đang bị dừng/giải
phóng. **Bạn (hoặc BTC) phải tự bật lại từ Azure portal/CLI — không có công cụ nào ở đây làm
được việc đó.** Mọi thứ dưới đây sẽ không chạy được cho tới khi bước này thành công.

### Bước 1 — bật capture + pull loop (một script, idempotent)

```bash
bash contest-runtime/monitor/deploy-capture-pull.sh
```
Script này SSH vào, bật `tcpdump -Z root -i <docker_bridge> -w ... -G 30` trên vulnbox-host (ghi
pcap xoay vòng 30s vào `/tmp/ctf-capture-<pid>/` — **không tồn tại qua một lần reboot VM**, phải
làm lại mỗi khi VM khởi động lại), rồi lặp cục bộ kéo file về `./traffic/` mỗi 15s qua rsync.

**Chạy nó như một watch sống lâu** (ví dụ qua tool Monitor, hoặc một terminal để mở sẵn) — nếu
nó dừng, pcap sẽ dồn lại ở phía remote thay vì tới Tulip, và không có gì báo lỗi to để bạn biết.

### Bước 2 — deploy ctf_proxy đứng trước service thật (tuỳ chọn, để chặn)

Xem **"Deploy ctf_proxy nhằm vào Vulnbox thật"** ở dưới — đây là bước riêng, rủi ro hơn (đụng
vào port binding của service đang sống) và không thuộc phần giám sát/capture cơ bản.

### Bước 3 — OS watchdog / honeytoken (cùng cách như trước, nếu bạn có root trên vulnbox)

```bash
bash contest-runtime/watchdog/deploy-os-watchdog.sh
bash contest-runtime/detection/deploy-honeytoken.sh
```

### Xác nhận capture thực sự tạo ra dữ liệu dùng được

Đừng chỉ kiểm tra loop đang chạy — kiểm tra Tulip có đang biến file thành flow không:

```bash
docker exec tulip-timescale-1 psql 'postgres://tulip@timescale:5432/tulip' \
  -c "SELECT count(*), max(time) FROM flow;"
# max(time) phải trong vòng 1-2 phút gần nhất nếu traffic đang sống.
# Nếu count không bao giờ tăng và docker logs tulip-assembler-1 cứ báo
# "Processed 0 packets" trên những file bạn thấy rõ có packet thật
# (kiểm tra bằng: tcpdump -r traffic/<file>.pcap | wc -l) — xem lỗi BPF ở dưới.
```

---

## Deploy ctf_proxy nhằm vào Vulnbox thật

> Việc này chèn một proxy filter vào đúng đường traffic thật cho MỌI service TCP khai trong
> `services.json` (deploy một lần, áp hết). **SẼ gây downtime vài giây** cho mỗi service lúc
> port binding của nó đổi chủ — xác nhận đây là mức rủi ro chấp nhận được trước khi làm giữa
> lúc đang tính điểm. Service UDP không bao giờ bị đụng tới — ctf_proxy bản thân nó không proxy
> được UDP (xem README của chính nó) — dùng chặn-theo-nội-dung của Dashboard cho UDP thay thế.

Phần này chạy theo config, tự động hoá (`contest-runtime/defense/deploy-ctfproxy.sh`, được
`deploy-all.sh` gọi), vì cách duy nhất an toàn để chèn một proxy vào trước một service *đang
sống* là biết chính xác nó nằm trong compose file/service/network nào. Đoán mò trên một layout
lạ có rủi ro sửa sai config của một service thật. Script này mặc định không làm gì cả, chỉ hành
động khi bạn khai rõ nơi cần nhìn vào — và dù vậy nó vẫn xác minh lại mọi giả định qua SSH ngay
trước khi đụng vào bất cứ thứ gì, bỏ qua gọn gàng (theo từng service, không phải tất-cả-hoặc-
không-gì) nếu một điều kiện nào đó của riêng service đó thất bại.

### Chỉ đúng vào target thật

Cấu hình kết nối chung, sửa trong `services.json` → `ctf_proxy.insertion`:
```json
"insertion": {
    "mode": "docker-compose",
    "remote_compose_file": "~/practice-setup/<team>/docker-compose.yml",
    "remote_compose_service": "public-proxy",
    "remote_network_name": "<team>_proxy-public",
    "remote_ssh_alias": "dfcd-vbox"
}
```
`mode` mặc định là `"disabled"` — nghĩa là chỉ giám sát, không thử làm gì. Tìm
`remote_network_name` bằng `ssh <alias> "docker network ls"` trên vulnbox-host (đó là network
mà compose file của chính service target khai, thường tên dạng
`<project>_<network-key-trong-compose-file-đó>`).

Theo từng service: mỗi entry trong `services[]` có thể tự khai `compose_service` riêng (tên
compose service đứng sau CHÍNH port đó, nếu khác với `remote_compose_service` chung ở trên) và
phải khai `layer` (`l7-http`/`l7-https` → ctf_proxy đọc như HTTP; `l4-raw` → raw TCP, filter chỉ
thấy byte thô; `l4-udp` hoặc `proto: "udp"` → bỏ qua hoàn toàn, không đủ điều kiện). Service nào
không khai `compose_service` sẽ dùng lại field `remote_compose_service` chung ở trên — nhờ vậy
config 1-service viết từ trước khi field này tồn tại vẫn chạy được không cần sửa.

### Nó thực sự làm gì (giống nhau dù bạn chạy tay hay để script làm)

```bash
bash contest-runtime/defense/deploy-ctfproxy.sh
```
1. Dựng danh sách service đủ điều kiện (`proto: "tcp"` trong `services[]`); ghi cảnh báo và bỏ
   qua mọi entry `"proto": "udp"`. Với mỗi service đủ điều kiện, xác minh: SSH tới được (kiểm 1
   lần), compose file tồn tại, `compose_service` của nó có khai trong file đó, service đó thực sự
   đang publish đúng port target, network chung tồn tại, `docker compose` có sẵn ở remote. Service
   nào fail điều kiện của chính nó sẽ bị bỏ qua (cảnh báo, không fatal) — không chặn các service
   khác.
2. Copy source `ctf_proxy` lên vulnbox-host (`~/ctf-proxy-<team_id>/`) — một lần, dùng chung cho
   mọi service.
3. Viết DUY NHẤT một `proxy/config/config.json` với một entry cho mỗi service đủ điều kiện:
   `name` = tên service (làm sạch thành một Python identifier hợp lệ — trở thành tên module),
   `target_ip` = tên COMPOSE SERVICE của nó (không phải IP; được resolve qua Docker DNS khi
   ctf_proxy join network), `target_port` = port nội bộ trong container tìm được ở bước 1,
   `listen_port` = port public của nó từ `services.json`, `http` = `true` chỉ khi
   `l7-http`/`l7-https`.
4. Viết `docker-compose.yml` riêng của ctf_proxy — `ports:` của `nginx` liệt kê port public của
   mọi service đủ điều kiện, `nginx`+`proxy` join vào network **đã có sẵn** của vulnbox thay vì
   tự tạo network riêng.
5. Gỡ dòng port public khỏi compose file GỐC của mỗi service đủ điều kiện (toàn bộ file được
   backup một lần, bởi service đầu tiên đụng vào nó, thành `<file>.pre-ctfproxy.bak`) và tạo lại
   mỗi compose service bị ảnh hưởng (dedupe nếu 2 port dùng chung 1 compose service) để nhả port
   ra — đây là khoảnh khắc downtime vài giây, một lần cho mỗi compose service riêng biệt.
6. Build + bật ctf_proxy một lần (container chung, phục vụ mọi service), có cơ chế tự phục hồi
   sẵn cho một race-condition lúc khởi động đã biết (xem dưới), rồi kiểm tra port public của mỗi
   service — curl nếu nó giống HTTP, không thì test connect TCP thô — để xác nhận traffic thật
   vẫn đi qua được trước khi báo thành công.

Chạy lại script này an toàn: service nào đã có ctf_proxy đứng trước rồi (port binding gốc của nó
đã mất) sẽ fail điều kiện tiên quyết của chính nó và bị bỏ qua — không chèn đôi, và nội dung
filter đang sống của những service đã chạy từ trước không bao giờ bị đụng tới (`rsync` không bao
giờ ghi đè `filter_modules/<service>/` một khi nó đã tồn tại ở remote; đã xác nhận bằng
`rsync --dry-run` trước khi tin điều này).

**Lỗi đã biết, script đã tự xử lý — container nginx khởi động vào trạng thái hỏng:**
`docker logs <ctfproxy>-nginx` lặp lại `host not found in upstream "proxy:<port>"` dù hostname
đó resolve bình thường từ mọi container khác trên cùng network, nghĩa là container nginx được
tạo ra mà không gắn network nào (`docker inspect <name> --format
'{{json .NetworkSettings.Networks}}'` in ra `{}`). Restart thường không sửa được — script tự
phát hiện đúng trạng thái này và tự `docker rm -f` + `up -d` lại từ đầu. Nếu bạn tự làm tay thay
vì dùng script, dùng đúng cách sửa này.

`filter_modules/<service>/<service>_in.py` trên remote bắt đầu như một template trống, một file
cho mỗi service — ctf_proxy cho mọi thứ đi qua tới khi bạn viết rule detection thật vào đó (qua
tab RULES 3b của Dashboard, chọn đúng service ở dropdown nếu có nhiều hơn 1 — xem luồng
Tulip/Dashboard ở vài mục trên). Đừng mặc định "ctf_proxy đang chạy" nghĩa là "đang chặn được
tấn công".

---

## Ghi chú về ML Bot Fingerprinter (chỉ `MODE=prep`, tắt mặc định)

> **⚠️ CHỈ LÀ TẦNG GỢI Ý. Không phải cảnh báo. Cần người quyết định trước khi hành động.**
> Không phải generative AI — là clustering sklearn DBSCAN. Chỉ chạy khi cả `ml_classifier.enabled`
> trong `services.json` là `true` VÀ đang ở `MODE=prep`; không có tác dụng gì dưới `MODE=contest`
> dù flag đó là gì.

- Fingerprint dựa theo: khoảng cách thời gian giữa các lần đến, phân bố kích thước packet, thứ tự
  TCP handshake, số flow mỗi tick
- **KHÔNG fingerprint chỉ bằng IP** — BTC có thể NAT toàn bộ traffic của checker
- Sau 3 khung tick (~6 phút): bắt đầu đánh nhãn những cái lệch khỏi cluster của checker
- Nhãn: `bot-like` (khớp pattern checker) vs `deviant` (bất thường về nhịp/kích thước)
- Flow bị đánh dấu deviant hiện trên Dashboard → panel "ML Bot Hints" (màu tím)
- Tham số DBSCAN: eps=1.5, min_samples=3 (chỉnh trong `prep-only/ml-classifier/fingerprint_service.py`)

---

## Đổi Config

**Chỉ sửa `contest-runtime/config/services.json`.** Sau đó:

```bash
bash contest-runtime/config/validate-config.sh
MODE=contest bash teardown.sh
MODE=contest bash bringup.sh
```

Mọi thành phần tự đọc lại services.json ở lần bật tiếp theo. Không cần sửa gì khác.

---

## Cập nhật rule Suricata

Rule Suricata nằm ở `contest-runtime/detection/suricata/lib/rules/`. Thêm file `.rules` vào đó:

```bash
# Ví dụ: thêm một rule flag-out
cat >> contest-runtime/detection/suricata/lib/rules/ctf-flagout.rules << 'EOF'
alert tcp any any -> any any (msg:"CTF Flag Exfiltration"; pcre:"/[A-Z0-9]{31}=/"; sid:9000001; rev:1;)
EOF

# Reload Suricata (nếu dùng container Suricata của Tulip)
docker exec tulip-suricata-1 suricatasc -c reload-rules
```

---


## Cấu trúc file

```
Setup_tool/
├── contest-runtime/              ← mọi thứ được phép chạy trong 8h thi
│   ├── config/
│   │   ├── services.json         ← SỬA FILE NÀY (nguồn sự thật duy nhất)
│   │   ├── validate-config.sh    ← kiểm tra config (gồm cả check keyword bị lệch)
│   │   └── generators/           ← xuất config gốc của từng tool từ services.json
│   │       ├── gen-tulip-env.py  ← → offline-bundle/repos/tulip/.env (đang dùng)
│   │       └── gen-ctfproxy.py   ← viết một config.json LOCAL ở
│   │                                offline-bundle/repos/ctf_proxy/proxy/config/ nhằm vào
│   │                                mock_vulnbox.hostname; vẫn được bringup.sh gọi, nhưng không
│   │                                có gì trong docker-compose.*.yml chạy container ctf_proxy
│   │                                local đọc nó — đường deploy thật (deploy-ctfproxy.sh) tự
│   │                                sinh config.json RIÊNG trực tiếp trên vulnbox-host remote.
│   │                                Mồ côi (orphaned), vô hại.
│   ├── detection/                ← scanner regex flag-out, honeytoken, ruleset Suricata
│   ├── watchdog/                 ← poller SLA + script deploy OS-watchdog
│   ├── monitor/                  ← script deploy capture vulnbox
│   ├── defense/                  ← script deploy ctf_proxy + template rule
│   ├── dashboard/                ← UI giám sát tổng hợp
│   ├── hostagent/ + host_agent.py ← tiến trình thực thi hành động phía host cho Dashboard
│   └── health_check.py           ← chẩn đoán một lượt (cũng nuôi System Status của Dashboard)
│
├── prep-only/                    ← KHÔNG BAO GIỜ bật khi MODE=contest
│   ├── ml-classifier/            ← bộ phân loại lệch-chuẩn-bot sklearn tuỳ chọn (tắt mặc định)
│   └── training/mock-vulnbox/    ← service giả có lỗ hổng, chỉ để diễn tập
│
├── docker-compose.contest.yml    ← compose file DUY NHẤT MODE=contest từng đụng tới
├── docker-compose.prep.yml       ← overlay cho MODE=prep (mock-vulnbox, ml-fingerprint)
├── bringup.sh                    ← bật bằng 1 lệnh (bắt buộc MODE=contest|prep)
├── teardown.sh                   ← dừng gọn gàng (luôn tắt cả 2 compose file)
├── deploy-all.sh                 ← 1 lệnh: preflight → bringup → capture/trap/ctf_proxy trên vulnbox
├── pull-and-save.sh              ← đóng gói bundle offline (chạy khi còn mạng, trước ngày thi)
├── offline-restore.sh            ← restore trên máy air-gapped (không gọi mạng)
│
├── docs/                         ← mọi thứ ngoài file này
│   ├── SCHEMA.md                 ← tham chiếu field của services.json
│   ├── ARCHITECTURE.md           ← hệ thống hoạt động thế nào, theo luồng dữ liệu
│   ├── RUNBOOK.md                ← chính file này
│   ├── STATUS.md                 ← cái gì đã thực sự xác nhận hoạt động, kèm bằng chứng
│   ├── GOLIVE.md                 ← checklist nhận bàn giao từ BTC / chuyển sang ngày thi
│   └── DEMO.md                   ← script trình diễn trực tiếp (kiểm tra trước, phương án lùi)
│
├── traffic/                      ← file pcap (cả Tulip và detection đều theo dõi thư mục này)
│
└── offline-bundle/               ← sản phẩm build (gitignore — chạy pull-and-save.sh để tạo)
    ├── images/                   ← file .tar của Docker image
    ├── wheels/                   ← file .whl của Python
    ├── repos/                    ← repo upstream đã clone: tulip, ctf_proxy, pcap-broker
    └── services.json             ← bản snapshot config
```

---


## Troubleshooting (xử lý sự cố)

### Luôn bắt đầu ở đây

```bash
bash health-check.sh
```
Chẩn đoán một lượt, chỉ đọc, bao phủ mọi kiểu lỗi đã thực sự gặp trong thực tế (dung lượng đĩa,
trạng thái container, SSH tới vulnbox có được không, pull loop, độ mới của flow Tulip). Mỗi
dòng nêu đúng lệnh sửa. Chạy cái này TRƯỚC khi tự debug bằng tay — hầu hết sự cố dưới đây là thứ
script này đã có thể bắt được trong 10 giây, thay vì một hồi điều tra tay dài dòng.

### Bảng tra nhanh

| Triệu chứng | Nguyên nhân khả nghi | Cách sửa |
|---------|-------------|-----|
| Dashboard trắng | Kết nối WebSocket lỗi | Kiểm tra Redis có chạy không: `docker compose -f docker-compose.contest.yml ps redis` |
| Không có flow Tulip nào cả | Pull loop không chạy / không tới được vulnbox | Test `ssh dfcd-vbox "echo OK"` trước, rồi `bash contest-runtime/monitor/deploy-capture-pull.sh` |
| `ssh dfcd-vbox` timeout ngay lúc bắt tay (banner exchange) | VM remote đang dừng/bị giải phóng | Tự bật lại từ cloud portal/CLI của bạn — không sửa được từ máy này |
| Có flow nhưng số lượng kẹt lại, timestamp cũ | Pull loop đã chết âm thầm (ví dụ watch của Monitor hết hạn) | Kiểm tra `ps aux \| grep rsync`; restart pull loop |
| Watchdog báo unknown | Không tới được vulnbox | Kiểm tra IP vulnbox trong `contest-runtime/config/services.json` |
| `deploy-all.sh` chết ở "Preflight checks" | Thiếu docker/docker-compose/python3, hoặc module python `redis` không cài được | Đọc đúng dòng `[FAIL]` — nó nêu rõ cái gì thiếu. Với `redis`, xem `/tmp/pip-redis-install.log` |

### Sự cố thật đã gặp trong thực tế — nguyên nhân gốc đầy đủ (để không phải tự debug lại từ đầu)

**1. Đĩa đầy 100%, mọi thứ âm thầm hỏng (rsync, docker, mọi lệnh ghi)**
- Triệu chứng: pull loop trông như "đứng" mà không in lỗi gì; lệnh `docker` treo hoặc lỗi kỳ lạ.
- Kiểm tra: `df -h /` — nếu gần 100%, đúng là cái này.
- Nguyên nhân thật ở đây là layer/build cache của Docker chồng chất qua nhiều lần rebuild, không
  phải dữ liệu pcap. Cách sửa, theo thứ tự giải phóng được nhiều nhất:
  ```bash
  docker builder prune -af   # cache buildx — thường là kẻ chiếm nhiều nhất
  docker image prune -af
  ```
- **Đừng mặc định là do file pcap** — chạy `du -sh traffic/` để loại trừ trước; đĩa đầy do
  Docker cache không liên quan trông giống hệt từ góc nhìn của pull-loop.

**2. tcpdump chết với "Permission denied" sau đúng một lần rotate file**
- Nguyên nhân: `sudo tcpdump` tự hạ quyền từ root xuống user `tcpdump` sau khi mở file capture
  đầu tiên. File thứ hai (sau khi `-G <giây>` rotate) được tạo bởi user đã bị hạ quyền đó và
  thường không ghi được.
- Cách sửa: luôn chạy với `sudo tcpdump -Z root ...` để giữ quyền root cho MỌI lần rotate, không
  chỉ file đầu. Đã có sẵn trong `contest-runtime/monitor/deploy-capture-pull.sh` — nếu bạn tự viết
  tay một lệnh tcpdump khác thay vì dùng script đó, đừng quên flag này.

**3. File pcap đã pull về nhưng Tulip xử lý ra "0 packet" dù file có traffic thật**
- Đây KHÔNG phải file bị cắt ngang/đang-ghi (kiểm tra trước: `tcpdump -r traffic/<file>.pcap |
  wc -l` — nếu ra packet thật, file vẫn ổn).
- Nguyên nhân thật: assembler của Tulip áp filter `BPF` (từ `.env`, lấy từ field `port` của
  `services.json`) ngay cả khi đọc file đã capture xong, không chỉ lúc đọc interface sống. Nếu
  việc capture xảy ra trên một docker bridge **sau NAT** (port public 8003 → port nội bộ 80 của
  container), filter BPF cho "port 8003" không khớp gì cả, vì bridge chỉ bao giờ thấy port 80.
- Cách sửa: thêm `"capture_port": 80` bên cạnh entry `"port": 8003` của service đó trong
  `services.json` (chỉ cần khi điểm capture nằm sau một NAT — vulnbox truyền thống capture trên
  NIC thường không cần cái này). `contest-runtime/config/generators/gen-tulip-env.py` ưu tiên
  `capture_port` hơn `port` cho chuỗi BPF nếu có. Sau khi sửa, chạy lại:
  ```bash
  python3 contest-runtime/config/generators/gen-tulip-env.py
  cd offline-bundle/repos/tulip && docker compose up -d assembler
  ```
- Chẩn đoán nhanh điểm capture thực sự thấy port nào:
  ```bash
  tcpdump -r traffic/<file>.pcap "port <public_port>" | wc -l   # 0 = lệch
  tcpdump -r traffic/<file>.pcap "port <container_port>" | wc -l # phải >0
  ```

**4. Pull một file pcap giữa lúc đang ghi khiến Tulip nhận bản bị cắt ngang, không bao giờ thử lại**
- Triệu chứng: log assembler báo `PCAP OpenOffline error: truncated dump file` một lần, rồi
  không bao giờ nhìn lại tên file đó nữa dù một lần rsync sau đó đã lấy được bản đầy đủ.
- Đã sửa sẵn trong `deploy-capture-pull.sh`: chỉ rsync những file mà `find` ở remote báo cũ hơn
  ~35s (một chu kỳ rotate) — nghĩa là tcpdump chắc chắn đã chuyển sang file kế tiếp và file này
  đã ghi xong. Nếu bạn tự viết tay một pull loop, giữ đúng điều kiện này; một lệnh trần
  `rsync -az remote:dir/ local/` lặp mỗi N giây CHẮC CHẮN sẽ có lúc lấy trúng file đang ghi và
  mất âm thầm đoạn traffic đó.

**6. Một container bật bằng tay (`docker compose up -d <svc>`) crash vì config trống**
- Nguyên nhân: compose lấy giá trị từ biến môi trường chỉ tồn tại trong shell của `bringup.sh`.
  Đã sửa: `bringup.sh` giờ ghi chúng vào `./.env`, compose tự đọc file này. Nếu còn gặp lại, chạy
  `MODE=contest bash bringup.sh` một lần để sinh lại `.env`.

**7. Giới hạn một endpoint theo IP client không hoạt động trên máy này**
- Docker ở đây là rootless podman: mọi kết nối inbound tới container đều đi qua netns gateway
  (ví dụ 10.0.0.20), không bao giờ là IP client thật. Cái gì không được public phải nằm trên
  một port bind `127.0.0.1`, không phải dựa vào check IP. (Đây cũng là lý do `src_ip` của alert
  honeytoken là gateway, không phải kẻ tấn công.)

**8. Mọi port điều khiển đều nghe trên 0.0.0.0 (tới được từ VPN thi đấu)**
- Đã sửa: Dashboard (8080) và Tulip web UI (3000) bind theo `${BIND_IP}` (services.json
  `monitor_host.bind_ip`, mặc định `127.0.0.1`, cố ý cho đổi sang IP LAN để đồng đội mở được —
  xem `CONFIG.md`). Redis, API quản trị/test của detection, và Postgres của Tulip được hardcode
  `127.0.0.1` trong `docker-compose.contest.yml` / được `gen-tulip-env.py` vá đúng vậy, và
  **không** theo `bind_ip` nữa (sửa 2026-10-16 — trước đó chúng có theo, nghĩa là mở Dashboard
  ra LAN cũng vô tình phát luôn hàng đợi alert, `/test/inject-flag`, và database flow thô). Chỉ
  port 9999 (thu honeytoken + OS-watchdog) là public theo thiết kế. Kiểm tra bất cứ lúc nào:
  `ss -tlnp | grep -vE '127\.0\.0\.1|:9999 '` — còn lại gì thì phải là đúng địa chỉ của
  `BIND_IP` (8080/3000) hoặc thứ gì đó hoàn toàn ngoài repo này (xem mục kế tiếp nếu nghi có cả
  firewall phía BTC trong bức tranh).

**5. Container nginx của ctf_proxy kẹt, không gắn network nào**
- Xem ghi chú "Lỗi đã biết" dưới mục "Deploy ctf_proxy nhằm vào Vulnbox thật" ở trên. Tóm tắt:
  `docker rm -f` container nginx rồi `docker compose up -d nginx` lại; chỉ `restart` thường
  không sửa được.

### Khi firewall/router của BTC (pfSense hoặc tương đương) cấu hình khác giả định

Mọi thứ trong repo này (`ctf_proxy`, capture, honeytoken, OS-watchdog) đứng **sau** một thiết bị
mạng do ban tổ chức quản lý — thường là pfSense hoặc tương tự, làm NAT/port-forward/firewall
giữa "mạng ngoài" (nơi checker + đối thủ ở) và vulnbox/mạng team. **Mình không cấu hình được cái
đó, chỉ có thể TEST để biết nó đang xử lý traffic kiểu gì**, rồi thích nghi — không đoán. Mục
này cho một quy trình tự chẩn đoán, không cần tôi ngồi cạnh.

Nguyên tắc chung: *mọi container/service bên mình "lên" (`docker ps` xanh hết) không có nghĩa
traffic thật sự đi qua đúng đường*. Luôn test bằng traffic thật qua đúng port public, không chỉ
tin vào trạng thái container.

**1. NAT reflection / hairpin — lỗi pfSense kinh điển nhất trong hạ tầng CTF**

Triệu chứng: checker (chạy từ máy chấm điểm, ngoài mạng team) thấy service UP bình thường, nhưng
tự mình `curl` vào chính IP/port public của mình (từ MÁY TRONG CÙNG MẠNG team, hoặc từ chính
vulnbox) lại timeout/refused — dù service chạy tốt khi test qua `localhost`/IP nội bộ.

```bash
# Từ bên trong mạng team (vulnbox hoặc máy monitor), test đúng IP/port PUBLIC,
# không phải IP nội bộ:
curl -m 5 http://<IP public của vulnbox>:<port public>/
```

Nếu timeout/refused dù service chạy tốt qua IP nội bộ: pfSense có setting tên **"NAT
Reflection"** (hoặc "hairpin NAT") đang tắt — traffic từ TRONG mạng gửi tới IP PUBLIC của chính
mạng đó không được NAT phản hồi lại vào trong, dù traffic từ NGOÀI vào vẫn bình thường. Đây
**không phải lỗi của mình**, và checker thật (luôn ở ngoài mạng team) **không bị ảnh hưởng gì**
— chỉ gây nhiễu khi TỰ mình test. Nếu cần tự test từ trong mạng, test qua IP/port NỘI BỘ thay vì
IP public, hoặc nhờ ai ở ngoài mạng team test giúp.

**2. Hướng kết nối một chiều — đã gặp thật (xem `docs/STATUS.md` 2026-10-16)**

Đừng bao giờ coi "SSH monitor→vulnbox chạy được" là bằng chứng "mọi hướng kết nối đều ổn". SSH
chỉ chứng minh ĐÚNG MỘT hướng. Honeytoken/OS-watchdog cần hướng ngược lại (vulnbox→monitor) —
**hai bài test độc lập, không suy ra từ nhau được**. Quy trình test chuẩn (đã dùng thật):

```bash
# Hướng monitor -> vulnbox (SSH, capture, ctf_proxy deploy đều cần cái này):
ssh <vulnbox_ssh_alias> echo ok

# Hướng vulnbox -> monitor (honeytoken/OS-watchdog push cần cái này) --
# dựng một listener tạm, KHÔNG liên quan tới service nào đang chạy, để loại
# trừ khả năng do port/container cụ thể nào đó bị chặn riêng:
python3 -m http.server 19999 --bind 0.0.0.0 &     # chạy TRÊN máy monitor
ssh <vulnbox_ssh_alias> "curl -m 5 http://<IP máy monitor>:19999/"
kill %1                                            # dọn ngay sau khi test
```

Timeout ở bài test 2 (không phải "connection refused" — refused nghĩa là tới được, chỉ không ai
nghe) = firewall/router chặn chiều đó, không phải lỗi service. Hệ thống đã có cơ chế dự phòng
cho đúng tình huống này (honeytoken/OS-watchdog tự chuyển sang kiểu hỏi-ngược qua SSH, xem
`contest-runtime/hostagent/oswatchdog_pull.py` / `honeytoken_pull.py`) — **không cần sửa gì cả**,
chỉ cần biết để không hoảng khi thấy cảnh báo "can NOT reach" lúc deploy.

**3. ctf_proxy "mất tích" dù vẫn chạy — port-forward trỏ sai đích**

`ctf_proxy` hoạt động bằng cách CHIẾM đúng port public mà service gốc từng bind, trên CHÍNH máy
vulnbox — nó không tự "chen" vào giữa đường truyền ở tầng mạng. Nếu pfSense's NAT rule được cấu
hình trỏ cứng vào một IP nội bộ cụ thể (ví dụ IP riêng của container service gốc) từ trước khi
ctf_proxy được cài, thay vì trỏ vào IP của HOST vulnbox, traffic vẫn có thể đi tắt tới thẳng
service gốc, **bỏ qua hoàn toàn ctf_proxy** — rule chặn build xong, apply xong, báo thành công,
nhưng thực tế không chặn được gì vì traffic chưa từng đi qua.

```bash
# Xác nhận traffic qua port public THỰC SỰ tới đúng process ctf_proxy, không
# phải thẳng tới service gốc:
ssh <vulnbox_ssh_alias> "ss -tlnp | grep ':<port public> '"
# phải thấy process ctf_proxy (nginx/proxy container), không phải service gốc

# Test thật: gửi 1 request chứa chuỗi mà ctf_proxy ĐANG chặn, qua đúng IP/port
# PUBLIC (không phải localhost trên vulnbox) -- nếu service vẫn trả response
# bình thường (không bị khoá/đóng kết nối) dù rule báo "đã áp dụng", traffic
# không đi qua ctf_proxy.
```

Nếu phát hiện đúng trường hợp này: báo BTC port-forward đang trỏ sai đích (vào IP container cụ
thể thay vì IP host), hoặc dùng "Fallback block — theo NỘI DUNG" (tab SERVICES, iptables trên
chính vulnbox, không phụ thuộc NAT của BTC) làm phương án tạm trong lúc chờ sửa.

**4. Source IP bị NAT/masquerade mất, không còn là IP thật của kẻ tấn công**

Nếu pfSense (hoặc router giữa các team) làm NAT nguồn (masquerade) traffic giữa các team với
nhau, mọi traffic tới vulnbox của mình có thể trông như xuất phát từ MỘT IP duy nhất (IP NAT của
router) bất kể đội nào thật sự gửi — giống hệt vấn đề đã gặp với rootless podman (RUNBOOK mục 7
ở trên, netns gateway thay cho IP khách thật). Dấu hiệu: `teams_cidr` trong `services.json` không
còn phân biệt được gì, mọi honeytoken/watchdog alert đều ghi cùng một `src_ip`.

Không có cách tự sửa từ phía mình (NAT xảy ra ở thiết bị của BTC) — nếu nghi ngờ đúng trường hợp
này, đừng dựa vào so khớp IP nguồn để phân biệt checker/đồng minh/đối thủ; ưu tiên chặn/nhận diện
theo **nội dung request** (đã có sẵn: multi-condition ctf_proxy rule, Suricata content-match) hơn
là theo IP.

**5. Danh sách port cần hỏi BTC mở sẵn (chuẩn bị trước khi vào mạng thi)**

Nếu nghi pfSense của giải chặn mặc định (default-deny) những gì không được khai báo trước, đây
là toàn bộ danh sách port **thực sự** cần cho hệ thống này hoạt động — không hơn:

| Port/hướng | Ai cần nó | Nếu bị chặn |
|---|---|---|
| Port service public (`services[].port`), hướng ngoài→vulnbox | Traffic game thật (checker + đối thủ) | Hầu như không bao giờ bị chặn — đây là chính service đang thi; nếu bị chặn thì không ai chấm điểm được, báo BTC ngay |
| SSH tới vulnbox (`vulnbox.ssh_port` hoặc alias của `capture_ssh_alias`), hướng monitor→vulnbox | Capture, ctf_proxy deploy, honeytoken/OS-watchdog deploy, cơ chế pull mới | Gần như luôn mở (team tự quản lý vulnbox của mình); nếu không SSH được, mọi tính năng ở Phase 1/2 trong `docs/GOLIVE.md` đều không chạy được |
| Port 9999, hướng vulnbox→monitor | Honeytoken/OS-watchdog push (không bắt buộc — đã có cơ chế pull thay thế) | Không cần báo BTC mở riêng — hệ thống tự hoạt động qua cơ chế pull dù hướng này bị chặn (đã test thật, xem mục 2 trên) |

Không có port nào khác cần BTC mở thêm cho repo này — mọi thứ còn lại (Dashboard, Tulip, Redis,
API quản trị) chỉ chạy nội bộ trên máy monitor, không đi qua mạng thi.

---

*Xây cho giải Attack-Defense CTF 8 giờ. Sẵn sàng air-gap. Không tự động chặn. Chỉ con người quyết định.*
