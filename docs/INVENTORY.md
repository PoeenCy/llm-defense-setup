# INVENTORY.md — Item A: kiểm kê toàn bộ thành phần (trước khi tái cấu trúc)

> Được lập ra trước khi di chuyển bất kỳ file nào, theo đúng thứ tự xây dựng trong SPEC (A → B → C → …).
> Mỗi thư mục cấp cao nhất và mỗi service trong `docker-compose.yml` đều được gắn nhãn:
> **legal-runtime** (không phải AI, được phép chạy ở contest mode) · **AI/prep-only** (phải bị
> cách ly, không bao giờ khởi động ở contest mode) · **dead/remove** (đã cũ, không còn dùng) ·
> **ambiguous** (cần quyết định rõ ràng trước khi Item C di chuyển nó).
>
> Cơ sở grep: `ollama|transformers|torch|llama.cpp|vllm|anythingllm|openai|mcp|llm`
> trên toàn bộ source file (trừ `offline-bundle/`, `.git/`), cộng thêm `mongo`
> trên cùng tập đó. Đã chạy grep đầy đủ trong lúc kiểm kê; bằng chứng dưới đây trích dẫn
> những kết quả khớp có ý nghĩa.

## Chú giải

| Tag | Ý nghĩa |
|---|---|
| **legal** | Không tìm thấy phụ thuộc AI/model nào. Thuộc về `contest-runtime/`. |
| **AI** | Gọi hoặc chỉ tồn tại để phục vụ một model generative / đường dẫn MCP-tới-LLM. Thuộc về `prep-only/`. |
| **dead** | Tham chiếu đã cũ (thiết kế dựa trên Mongo cũ, hoặc artifact lạc loài không liên quan). Cần xoá. |
| **ambiguous** | Không phải generative, nhưng chạm vào "AI/ML" theo đúng nghĩa chữ của điều lệ giải, hoặc không có một vùng (zone) rõ ràng duy nhất để xếp vào. Đánh dấu để chờ quyết định rõ ràng, chưa di chuyển. |

---

## Các thư mục cấp cao nhất

| Đường dẫn | Tag | Bằng chứng / ghi chú |
|---|---|---|
| `dashboard/` | **legal**, có một route chạm **AI** | App FastAPI (`main.py`, `routes/*.py`, `rulegen/*.py`), UI tĩnh (`static/`). Không có import ollama/torch nào trong `dashboard/app/`. Một ngoại lệ: `dashboard/app/routes/analyze.py` (24 dòng) gọi ra `ioc-brain` (env `IOC_API_URL`) cho tính năng "Analyze"/sinh-rule-từ-LLM. Route này tự nó không suy luận gì — nó chỉ là một HTTP client gọi tới service đã bị cách ly. **Cần quyết định cho Item D/E**: ở `MODE=contest`, route này phải hoặc không có mặt trong compose/image, hoặc trả về rõ ràng response "disabled in contest mode", và nút điều khiển UI tương ứng (static/js) phải bị ẩn — xem tiêu chí nghiệm thu của Item D ("không có tác dụng gì ở contest mode bất kể cờ bật/tắt"). |
| `detection/` | **legal** | `detection_service.py` — regex flag-out (env `FLAG_REGEX`), bộ thu thập HTTP honeytoken, bộ ingest `eve.json` của Suricata. Thuần stdlib + `redis`/`fastapi`/`dpkt`/`scapy`. Không có import AI nào. → `contest-runtime/detection/`. |
| `watchdog/` | **legal** | `watchdog_service.py` — bộ dò SLA (đo thời gian connect/timeout socket) đọc `services.json`. Không có import AI nào. → `contest-runtime/watchdog/`. |
| `hostagent/` + `host_agent.py` ở root | **legal** | Tiến trình **host** (không phải container) chạy liên tục duy nhất: đẩy status mỗi 15s, thực thi một tập hành động đã whitelist (`actions/{config,ctfproxy,firewall,services,suricata}.py`) được dashboard yêu cầu qua hàng đợi Redis (`ops_requests`). Chỉ thực thi lệnh xác định (docker/systemctl/ghi file), không AI. → `contest-runtime/` (đặt cùng với `dashboard/` và `watchdog/`, vì nó là bộ thực thi phía host cho cả hai — vị trí thư mục con chính xác là quyết định của Item C, chưa di chuyển). |
| `generators/` | **legal** | `gen-ctfproxy.py`, `gen-tulip-env.py` — chỉ templating config thuần từ `services.json`. → `contest-runtime/config/`. |
| `services.json`, `validate-config.sh` | **legal** | Config trung tâm + validator. Đã không còn field Mongo nào (xem mục Dead) và có một mục `mcp.*` (xem Ambiguous — mục `mcp` ở đây chỉ là thông tin Tulip-Postgres do `mcp-tulip/` tiêu thụ, và `mcp-tulip/` tự nó bị gắn tag AI dưới đây vì consumer duy nhất của nó là `ioc-brain`). → `contest-runtime/config/`. |
| `suricata/` | **legal** | Các thư mục config/rule/log của IDS (`etc/`, `lib/rules/`, `log/`) — dựa trên rule, không AI. → `contest-runtime/detection/` hoặc `monitor/` (quyết định vị trí thuộc Item C). |
| `rules-library/` | **legal** | Mẫu rule sẵn sàng để bật: `ctfproxy/*.py` (method chặn, fail-open, khớp theo nội dung), `suricata/*.rules` (tổng 3260 dòng trải trên 15 file — 12 nhóm viết tay + 3 file kiểu ET cho response/web-server/exploit), `nginx/block-rules.conf`. Tất cả đều là khớp mẫu xác định (deterministic). → `contest-runtime/defense/` (ctfproxy + nginx) và `contest-runtime/detection/` (suricata) — hiện đang là một thư mục phục vụ cả 2 vùng, cần tách ở Item C. |
| `vulnbox-deploy/` | **legal** | `deploy-capture.sh`, `deploy-capture-pull.sh` (tcpdump+kéo pcap), `deploy-honeytoken.sh`, `deploy-ctfproxy.sh` (chèn proxy tùy chọn trước một service đang sống, tự xác minh lại mọi điều kiện tiên quyết qua SSH, không bao giờ sửa file của chính target), `deploy-os-watchdog.sh` + `os-watchdog-agent.sh` (agent phát hiện process/kết nối/hash-file/cron lệch, chạy NGAY TRÊN host vulnbox, báo về monitor). Toàn bộ là shell xác định, không AI. → chia vào `contest-runtime/monitor/` (capture), `contest-runtime/detection/` (honeytoken), `contest-runtime/defense/` (chèn ctfproxy), `contest-runtime/watchdog/` (os-watchdog). |
| `traffic/` | **legal** (dữ liệu runtime, không phải code) | Thư mục nhận pcap capture, gitignore trừ phần retention. Ở cùng chỗ với `monitor/` sau khi di chuyển. |
| `vault/` | **AI** | Chỉ được mount vào `ioc-brain` và `anythingllm` (volumes trong `docker-compose.yml`) làm nguồn tài liệu RAG. Gitignore trừ `.gitkeep`. → `prep-only/ai-ioc/vault/`. |
| `config-backups/` | **legal** (dữ liệu runtime) | Được `hostagent/actions/config.py` ghi mỗi lần apply config (hỗ trợ rollback). Không phải code — ở cùng chỗ với config/hostagent sau khi di chuyển. |
| `bringup.sh`, `deploy-all.sh`, `teardown.sh` | **legal**, cần viết lại | Các entrypoint điều phối. Hiện tại khởi động **mọi thứ** vô điều kiện, kể cả `ioc-brain`/`mcp-tulip`/`anythingllm` (xem bằng chứng `docker-compose.yml` dưới) và hoàn toàn không có khái niệm `MODE` — đây chính là lỗ hổng của Item B. Cũng có dòng comment duy nhất thừa nhận ngôn ngữ Mongo đã cũ: `bringup.sh:14` *"Safety: read-only MongoDB."* (comment đã chết, Tulip dùng Postgres — xem mục Dead). |
| `health_check.py`, `health-check.sh` | **legal** | Các probe trạng thái được vòng lặp status của `hostagent` và dashboard tiêu thụ. Không AI. |
| `mock-vulnbox/` | **ambiguous** | App dễ tổn thương giả (`svc1_http.py`, `svc2_tcp.py`, chỉ `python:3.11-slim`, không AI). Chỉ dùng để diễn tập cục bộ trước ngày thi (`services.json.mock_vulnbox.enabled`, mặc định `false`); `bringup.sh` đã bỏ qua nó khi tắt. Nó không thuộc stack phòng thủ thi thật và không được liệt kê ở bất kỳ vùng `contest-runtime/` nào trong SPEC. **Khuyến nghị**: chuyển vào `prep-only/training/` (dùng để luyện tập/diễn tập, khớp đúng mô tả vùng đó ở §1) thay vì `contest-runtime/`, vì nó chỉ tồn tại để chạy thử pipeline, không để phòng thủ gì trong 8 giờ thi thật. Đánh dấu chờ xác nhận rõ ràng trước khi Item C di chuyển, vì việc này đổi hành vi hiện tại của `bringup.sh` (hiện nó vẫn tồn tại ở contest mode, chỉ bị tắt bằng cờ, không bị gỡ vật lý). |
| `ioc-brain/` | **AI** | `ioc_api.py` — `import ollama`, gọi `ollama_lib.AsyncClient(...).chat(model=LLM_MODEL, ...)` (`ioc_api.py:158,171`); đi kèm `Foundation-Sec.Modelfile` (file build model Ollama). Đây là endpoint phân tích LLM generative (`/analyze`, `/generate-rule`). → `prep-only/ai-ioc/`. |
| `mcp-tulip/` | **AI** | MCP server (`from mcp.server.fastmcp import FastMCP`, `mcp_server.py:16`) cung cấp quyền đọc Postgres. Nó tự nó không suy luận gì, nhưng **nơi gọi nó duy nhất** trong toàn repo là `ioc-brain` (`MCP_URL` trong `ioc_api.py:53`, `fetch_flow_from_mcp`) — không có gì trong `detection/`, `watchdog/`, hay `dashboard/` nói chuyện với nó. Theo đúng danh sách grep của SPEC (`ollama/transformers/torch/mcp/llm`), MCP tự nó được coi là thuộc nhóm liên quan-AI, và vì nó chỉ tồn tại để nuôi LLM đã bị cách ly, nó không có lý do độc lập nào để ở lại `contest-runtime/`. → `prep-only/ai-ioc/`. |
| `llm-host/` | **AI** | `setup-llm-host.sh` — cài/cấu hình Ollama + build model Foundation-Sec trên **một máy riêng biệt**. Không nằm trong `docker-compose.yml` (không có service), nhưng là tooling bootstrap AI-host thuần túy. → `prep-only/ai-ioc/` (hoặc `prep-only/ai-ioc/llm-host/` để giữ đúng tinh thần "chạy cái này trên máy khác"). |
| `ml-fingerprint/` | **ambiguous — đánh dấu chờ quyết định rõ ràng** | `fingerprint_service.py`: `from sklearn.cluster import DBSCAN`, `from sklearn.preprocessing import StandardScaler` (dòng 36-37). Clustering không giám sát (unsupervised) trực tuyến trên đặc trưng flow L3/L4 (thời gian giữa các packet, kích thước packet, cờ handshake) để đánh dấu traffic lệch khỏi cụm bot-checker — rõ ràng là một lớp **chỉ gợi ý**, không bao giờ tự chặn (`fingerprint_service.py:16-20`). Cái này **không phải** generative AI và **không phải** deep learning (không có `torch`/`transformers`), nên nó không vướng vào danh sách phụ thuộc rõ ràng của SPEC trong bước kiểm tra tuân thủ ở Item 3. Tuy nhiên, điều lệ cứng của giải ở §0 viết *"không AI nào được chạy... kể cả model AI/ML cục bộ"* — DBSCAN đúng là một model ML kinh điển. **Khuyến nghị**: coi đây đúng là "bộ phân loại ML tùy chọn" mà vùng `prep-only/ml-classifier/` của chính SPEC đã dự tính (§1, Item D) — mặc định TẮT, có cờ config (`enable_ml_classifier`), không có mặt trong compose của contest, cần BTC xác nhận bằng văn bản mới được bật. Việc này làm mất một tín hiệu phát hiện đang hoạt động (dù chưa được nghiệm thu đầy đủ) khỏi stack contest mặc định, nên nêu ra ngay bây giờ thay vì tự quyết một mình, vì tiêu chí nghiệm thu của Item F không đề cập tới nó và STATUS.md tự nó ghi *"ml-fingerprint full acceptance — vẫn đang riêng/chưa xong"* (chưa phải tín hiệu đã được chứng minh, chịu trách nhiệm thật). |
| `offline-bundle/` | **hỗn hợp, cần build lại** | Gitignore, tự sinh lại được qua `pull-and-save.sh`. Hiện đang gộp **mọi thứ** chung một chỗ (repo Tulip/ctf_proxy/pcap-broker, image redis/nginx/mysql/php cho service giả, **và** `mintplexlabs/anythingllm`, wheel `ollama`, thư mục `ollama-models/` gần như trống (4KB — model blob thực ra chưa được lưu, nên "bundle AI offline" hiện tại thậm chí không hoạt động), cộng thêm artifact Mongo đã chết — xem dưới). Item I yêu cầu tách ra: một bundle offline chỉ-legal cho `contest-runtime`, và một bundle prep-only riêng (hoặc một cờ `--with-ai` rõ ràng) cho `prep-only`. |
| `docs/` | **hỗn hợp** | `ARCHITECTURE.md`, `DASHBOARD_GUIDE.md`, `GOLIVE.md`, `RUNBOOK.md`, `SCHEMA.md`, `STATUS.md`, `RULE_COOKBOOK.md`, `DEMO.md` — tất cả mô tả stack legal (DEMO.md cũng có sai lệch sự thật đã biết so với STATUS.md, không liên quan tới spec này). `REMOTE_LLM.md` là tài liệu chỉ-AI (tài liệu về dedicated Ollama host) → nên di chuyển hoặc đánh dấu rõ là tài liệu `prep-only`. |
| `__pycache__/` (root) | **dead** | Artifact build, đã gitignore; xóa ngay khi thấy, không phải thành phần thật. |

## Service trong `docker-compose.yml` (hiện tại là một file master duy nhất — Item B/C sẽ tách file này)

| Service | Tag | Bằng chứng |
|---|---|---|
| `mock-vulnbox` | ambiguous (xem trên) | `docker-compose.yml:15-25` |
| `redis` | legal | `docker-compose.yml:30-43` — hàng đợi alert/hint chung, không AI |
| `detection` | legal | `docker-compose.yml:48-76` |
| `ml-fingerprint` | ambiguous (xem trên) | `docker-compose.yml:81-101` |
| `watchdog` | legal | `docker-compose.yml:106-123` |
| `mcp-tulip` | **AI** | `docker-compose.yml:132-145` — join network `tulip-internal` *chỉ* để phục vụ `ioc-brain` |
| `ioc-brain` | **AI** | `docker-compose.yml:147-174` — env `OLLAMA_HOST`, `LLM_MODEL`, `EMBED_MODEL`, `GPU_LAYERS`; phụ thuộc `mcp-tulip` |
| `dashboard` | legal (xem lưu ý về analyze.py ở trên) | `docker-compose.yml:179-207` — env `IOC_API_URL` nối nó với service đã cách ly, chỉ cho một tính năng duy nhất |
| `anythingllm` | **AI** | `docker-compose.yml:212-233` — `mintplexlabs/anythingllm:latest`, `LLM_PROVIDER=ollama` |

**Hiện tại `bringup.sh` hoàn toàn không có cổng chặn nào** — mọi service kể trên (bao gồm cả
`ioc-brain`, `mcp-tulip`, `anythingllm`) đều khởi động vô điều kiện. Đây là lỗ hổng tuân thủ lớn
nhất, và Item B/D sẽ khép lại nó.

## Tàn tích Mongo (cần xóa — Tulip đã dùng Postgres/TimescaleDB từ lâu; `services.json`/`validate-config.sh` đã sạch, đây là những gì còn sót lại)

| Vị trí | Là gì | Hành động |
|---|---|---|
| `pull-and-save.sh:38` | `"mongo:7.0"` trong danh sách image cần pull | Xóa — không có gì trong stack chạy Mongo |
| `pull-and-save.sh:97` | `"pymongo>=4.7.0"` trong danh sách wheel | Xóa |
| `offline-restore.sh:88` | `pymongo` trong dòng fallback cài pip | Xóa |
| `offline-bundle/images/mongo_7.0.tar` | Image đã pull từ trước, đã cũ (gitignore, chỉ local) | Xóa cục bộ; sẽ không bị sinh lại nữa sau khi xóa 2 dòng trên |
| `offline-bundle/wheels/pymongo-4.18.2-*.whl` | Wheel đã cũ (gitignore, chỉ local) | Xóa cục bộ |
| `ioc-brain/ioc_api.py:9,13,48,50-52` | Comment *nói về* Mongo, giải thích rằng nó KHÔNG được dùng (MCP/Postgres đã thay thế) | Không cần đổi code, nhưng các comment này sẽ di chuyển nguyên vẹn cùng file vào `prep-only/ai-ioc/` — giữ như vậy là ổn, đã đúng sự thật |
| `rules-library/ctfproxy/block-injection.py:36` | `"""NoSQL (Mongo-style) injection...` | **Không phải tàn tích** — đây là rule phát hiện thật cho NoSQL injection nhắm vào service mục tiêu (service đó có thể dùng Mongo dù Tulip không dùng). Giữ nguyên. |
| `docs/STATUS.md`, `docs/DEMO.md`, `docs/RUNBOOK.md`, `docs/SCHEMA.md` | Nhắc tới thiết kế Mongo cũ / một endpoint `/mongo/test` trong lịch sử | STATUS.md tự nó đã cập nhật lại (có ghi lại việc sửa `/mongo/test` → `/mcp/test`); `RUNBOOK.md:347-348` và `SCHEMA.md:91` vẫn còn tham chiếu ví dụ curl `/mongo/test` đã chết và field `mongo_port` không còn tồn tại trong `services.json` — sửa trong lượt rà soát doc ở Item J. |

## Các mục chết/lạc loài khác tìm được (không phải Mongo, không phải AI — chỉ là nhiễu)

| Vị trí | Ghi chú |
|---|---|
| `offline-bundle/images/localhost_aquahome-northflank_test.tar` | Không được tham chiếu ở bất cứ đâu trong danh sách image của `pull-and-save.sh` — có vẻ là một image không liên quan được lưu tay vào thư mục này, hoặc từ project khác. Gitignore (chỉ local). Xóa. |
| `offline-bundle/images/composer_2.tar` | Cũng không nằm trong danh sách của `pull-and-save.sh`; `mock-vulnbox` chỉ dùng `python:3.11-slim` (không có PHP/composer nào trong repo này). Lạc loài. Xóa. |
| `offline-bundle/images/moby_buildkit_buildx-stable-1.tar` | Buildkit cần để *build* image, không phải để chạy stack thi — gói nó như image runtime là thừa thãi không cần thiết (gần như vô hại, nhưng `offline-restore.sh` không cần load nó). Bỏ ra khỏi lần build bundle kế tiếp. |
| `.host-agent.log`, `.status-pusher.log`, `.claude/scheduled_tasks.lock` | Artifact runtime/tooling, đã gitignore (trừ `.claude/`, không thuộc về app). Không cần làm gì. |

---

## Tổng kết

- **legal-runtime** (chuyển vào `contest-runtime/`): `dashboard/` (trừ lệnh gọi ioc-brain), `detection/`, `watchdog/`, `hostagent/` + `host_agent.py`, `generators/`, `services.json`, `validate-config.sh`, `suricata/`, `rules-library/`, `vulnbox-deploy/`, `traffic/`, `config-backups/`, `health_check.py`, `health-check.sh`, `bringup.sh`/`deploy-all.sh`/`teardown.sh` (viết lại cho khái niệm MODE).
- **AI/prep-only**: `ioc-brain/`, `mcp-tulip/`, service compose `anythingllm`, `llm-host/`, `vault/`, `docs/REMOTE_LLM.md`.
- **dead/remove**: các dòng Mongo trong `pull-and-save.sh`/`offline-restore.sh` + artifact cục bộ đã cũ của chúng, 3 file `offline-bundle/images/*.tar` lạc loài, `__pycache__/` ở root.
- **ambiguous — cần quyết định trước khi Item C/D tiếp tục**:
  1. `ml-fingerprint/` — là ML (DBSCAN) nhưng không generative; khuyến nghị cách ly vào `prep-only/ml-classifier/` theo đúng vùng mà SPEC tự quy định, cần BTC gật đầu, nhưng việc này làm mất một tín hiệu phát hiện đang hoạt động (dù chưa được nghiệm thu đầy đủ) khỏi stack contest mặc định.
  2. `mock-vulnbox/` — khuyến nghị `prep-only/training/` vì chỉ dùng để diễn tập, không phải phòng thủ thật.
  3. `dashboard/app/routes/analyze.py` (+ UI tương ứng) — cần một thiết kế cụ thể "vắng mặt/tắt ở contest mode", không chỉ để nó trỏ tới một URL đã chết.

Không có mục nào ở trên còn chưa được phân loại. Tiếp theo sẽ làm Item B (chuyển đổi mode), chờ bạn quyết định về 3 mục ambiguous trên.
