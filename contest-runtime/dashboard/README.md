# Dashboard — mọi thứ nằm ở đâu

Một tính năng = một file backend + một file frontend. Muốn debug một tab, chỉ cần mở đúng 2 file đó.

| Tab | Backend (FastAPI) | Frontend | Hành động phía host (chạy trong `host_agent.py`) |
|---|---|---|---|
| Monitor (luồng alert, thống kê, watchdog, gợi ý ML) | `app/routes/live.py` | `static/js/monitor.js` | — |
| Bảng System Status | `app/routes/status.py` | `static/js/status.js` | `health_check.py` (contest-runtime/) |
| Events | `app/routes/events.py` | `static/js/events.js` | — |
| Rules — Suricata | `app/routes/rules.py`, generator `app/rulegen/suricata.py` | `static/js/rules.js` | `hostagent/actions/suricata.py` |
| Rules — ctf_proxy | `app/routes/rules.py`, generator `app/rulegen/ctfproxy.py` | `static/js/rules.js` | `hostagent/actions/ctfproxy.py` |
| Rules — tải flow từ Tulip, chọn nhanh | `app/routes/tulip.py` | `static/js/rules.js` | — |
| Tra flow Tulip từ một Event (cột "Tulip flow" ở tab Events, nút Make rule) | `app/routes/tulip.py` (`/api/tulip/resolve`) | `static/js/events.js` | — |
| Tab Guide (hướng dẫn dùng, tiếng Việt) | — | `static/index.html` (`#tab-guide`) | — |
| Services | `app/routes/services.py` | `static/js/services.js` | `hostagent/actions/services.py` + whitelist `hostagent/registry.py` |
| Config | `app/routes/services.py` | `static/js/config.js` | `hostagent/actions/config.py` |
| Hunt (truy vấn events + flow Tulip để dựng lại một đòn tấn công) | `app/routes/hunt.py` | `static/js/hunt.js` | — |
| Applied (rule nào đang chạy thật + số lần khớp) | `app/routes/applied.py` | `static/js/applied.js` | `hostagent/actions/ctfproxy.py` (get) |
| Rule library (rule cảnh báo đã soạn sẵn) | `app/routes/rules.py` (`/api/rules/library`) | `static/js/rules.js` | — |
| Flag trace (hồ sơ flag-out, timeline, bằng chứng, re-analyse) | `app/routes/flagtrace.py` (proxy có whitelist tới API Flag-trace) | `static/js/flagtrace.js` | `contest-runtime/flagtrace/` |

Dùng chung: `app/core/` (settings, Redis client, `run_op()` = gửi lệnh cho host agent), `static/js/core.js`
(state, modal, toast, `escHtml`), `static/js/api.js` (helper gọi fetch), `static/js/main.js` (điều hướng tab, khởi động).

## Một lượt ghi/sửa hoạt động thế nào (vì sao dashboard không thể tự làm hỏng hệ thống)

Container dashboard **không có docker socket và không có SSH key**. Mọi thứ làm thay đổi hệ
thống đều được gửi dưới dạng một request có tên qua Redis (`run_op()` trong `app/core/ops.py`)
tới `host_agent.py` chạy trên host — nơi này chỉ thực hiện đúng các hành động đã liệt kê trong
`hostagent/actions/__init__.py` và chỉ đụng tới các service đã liệt kê trong
`hostagent/registry.py`. Mọi thay đổi đều được kiểm tra trước (Suricata `-T`, kiểm tra compile
Python, `validate-config.sh`), được backup, và được ghi vào tab Events (nguồn `host-agent`).

## Xem log khi có gì sai

```bash
docker logs ctf-dashboard --tail 50     # lỗi backend (routes)
tail -50 .host-agent.log                # host agent (áp rule, điều khiển service, sửa config)
```
Lỗi frontend: console devtools của trình duyệt (F12). Mỗi file JS nhỏ và đặt tên theo đúng tab của nó.

## Test

```bash
python3 contest-runtime/dashboard/tests/test_rulegen.py   # rule generator: escaping, cấp sid, an toàn khỏi injection, fail-open
```
