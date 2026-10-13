# Thư viện rule CHẶN cho ctf_proxy (IPS, chạy trên vulnbox)

Khác với thư viện Suricata (chỉ **alert**, rất nhiều rule kể cả chặn scanner), thư viện này **chặn thật** nên
đã **cắt bỏ phần đầu** (không chặn scanner/recon — chặn scanner chẳng được điểm mà lại dễ chặn nhầm). Ở đây chỉ
chặn các đòn **khai thác** thật: SQLi, NoSQLi, SSTI, SSRF, GraphQL lạm dụng, path traversal/LFI,
command injection/RCE, deserialization/XXE, upload webshell, LDAP, CRLF, XSS, JWT alg:none, và chặn flag rời service.

**Mọi rule chặn khớp theo NỘI DUNG request (URL/tham số/body), KHÔNG theo User-Agent hay IP** — vì checker có thể
dùng chung UA/IP, chặn theo đó dễ chặn nhầm bot chấm điểm (mất SLA).

## Nguyên tắc
- Mỗi method trong `class Module` là **một rule**. ctf_proxy gọi **mọi** method, method nào trả `True` thì chặn.
- Mọi rule **fail-open**: có lỗi gì thì trả `False` (không chặn) để không bao giờ tự làm hỏng service.
- Mỗi rule tự chứa (tự `import re` bên trong), để copy từng method độc lập.

## Cách dùng (trong Dashboard)
1. Tab **RULES** → khung **3b ctf_proxy** → **Load from vulnbox** (lấy filter hiện tại).
2. Mở file dưới đây, copy method bạn cần, dán vào trong `class Module` (trên dòng `def execute`).
3. **Check & Upload**. ctf_proxy tự nạp lại, chặn ngay.
4. Theo dõi tab **APPLIED** và **MONITOR → watchdog**: nếu rule chặn cả IP checker → **SERVICES → ctf_proxy → Pause filtering**, sửa rule, Resume.

## Quan trọng — test trước khi bật
Trước khi upload, làm **cùng điều kiện** thành 1 rule Suricata ở (2) → **Test on recent traffic**. Nếu khớp IP
checker hoặc traffic hợp lệ → rule quá rộng, **đừng** dùng để chặn, phải thu hẹp (giới hạn path/method).

## File
| File | Chặn gì |
|---|---|
| `block-injection.py` | SQLi, NoSQLi, command injection/RCE |
| `block-template-ssrf.py` | SSTI, SSRF, path traversal / LFI |
| `block-api-upload.py` | GraphQL introspection lạm dụng, upload webshell, deserialization/XXE |
| `block-extra.py` | LDAP, CRLF/header injection, XSS, open-redirect→SSRF, JWT alg:none |
| `block-flag-guard.py` | Chặn flag (và honeytoken) rời service trong response |

Mỗi method tự chứa — copy method cần dùng vào trong `class Module` của filter đang chạy (filter đó đã có sẵn `execute`). Đừng thay cả `web_in.py` bằng các file này (chúng không có `execute`).
