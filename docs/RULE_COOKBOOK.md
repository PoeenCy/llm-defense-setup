# Sổ tay viết rule khi thi (offline — không mạng, không AI ngoài)

Dành cho lúc **thấy một đòn tấn công mà không biết nó là gì** (kể cả RCE) và phải tự chặn.
Nguyên tắc cốt lõi: **bạn không cần biết tên đòn tấn công. Bạn chỉ cần tìm chuỗi mà request của kẻ tấn
công có, còn traffic hợp lệ (checker) thì không — rồi chặn đúng chuỗi đó.**

---

## 0. Ai/cái gì "cứu" bạn khi offline
Không có mạng, không có AI ngoài. Bốn thứ bạn có sẵn, theo thứ tự dùng:
1. **Thư viện rule sẵn** (`rules-library/`): hơn **3.200 rule CẢNH BÁO** (Suricata) — gồm bộ thật **Emerging Threats Open** (`20/21/22-et-*.rules`) + bộ tự soạn theo OWASP CRS — và bộ **CHẶN** cho ctf_proxy/nginx. Lấy ra áp trước.
2. **Trình tạo rule trong Dashboard** (tab RULES) — biến *bất kỳ* request thành rule mà **không cần biết code**: chọn phần độc hại bằng chuột → nó sinh rule → test → áp.
3. **LLM offline** (nút Ask LLM) — chạy trên máy bạn, gợi ý đòn tấn công là gì. **Chỉ tham khảo**, hay sai; đừng dựa vào để quyết định.
4. **Sổ tay này** — quy trình tự xử khi 3 cái trên chưa đủ.

---

## 1. Nguyên tắc vàng khi CHẶN: theo NỘI DUNG, không theo User-Agent/IP
Rule **chặn** (ctf_proxy/nginx/iptables) phải khớp **chuỗi độc hại trong request** (URL, tham số, body),
**KHÔNG** khớp User-Agent hay IP:
- **User-Agent**: checker có thể giả UA trình duyệt hoặc đổi UA → chặn UA dễ chặn nhầm checker.
- **IP**: checker và attacker thường ra cùng dải NAT → chặn IP dễ chặn nhầm checker.
UA/IP chỉ dùng để **CẢNH BÁO** (Suricata), tuyệt đối không để **chặn** (trừ iptables chặn 1 IP attacker cụ thể, là chốt cuối).

## 2. Ba chỗ có thể CHẶN (biết để chọn đúng)
Suricata **không chặn được** — nó đọc bản sao pcap trên máy bạn, chỉ cảnh báo. Chặn thật chỉ ở 3 nơi trên **vulnbox**:

| Nơi chặn | Thấy được gì | Chặn kiểu gì | Khi nào dùng |
|---|---|---|---|
| **ctf_proxy** (filter Python) | **Toàn bộ** request: URL, tham số, header, **body**, multipart | Linh hoạt nhất | Mặc định — đòn nào cũng chặn được, kể cả POST body |
| **nginx public-proxy** (của setup BTC, nhưng là container **đội bạn** nên bạn sửa được) | URL, tham số, header, User-Agent (khó xem body) | `return 403` theo regex | Khi **không cài được ctf_proxy**, và đòn nằm ở URL/tham số |
| **iptables** trên vulnbox | Chỉ IP nguồn | Chặn nguyên IP | Chốt chặn cuối, hoặc chặn gấp 1 kẻ tấn công |

> **BTC có chặn giúp không?** KHÔNG. nginx `public-proxy` chỉ **chuyển tiếp** traffic tới service của bạn; phòng thủ là việc của bạn. Nhưng container `public-proxy` là của **đội bạn**, nên bạn **được** sửa nginx của nó để thêm `return 403` (bộ sẵn: `rules-library/nginx/block-rules.conf`).

---

## 3. Quy trình chuẩn khi thấy một đòn LẠ (kể cả RCE)

### Bước 1 — Phát hiện
Dấu hiệu: alert `flag-out` không giải thích được · SLA đổi bất thường · `honeytoken` bị chạm · OS-watchdog báo tiến trình/cron lạ (dấu hiệu **RCE đã thành công**) · HUNT thấy request lạ.

### Bước 2 — Tìm request độc hại
- Tab **EVENTS** hoặc **HUNT**: lọc theo IP kẻ tấn công / thời gian → bấm cột **Tulip flow** mở flow, hoặc **Make rule**.
- Đọc phần **CLIENT → SERVER** (request). So sánh với request của checker (trông bình thường: đăng nhập, đọc đúng dữ liệu của nó).

### Bước 3 — Tìm chuỗi đặc trưng
Phần nào trong request kẻ tấn công **khác** request hợp lệ? Thường là:
- RCE/command injection: `;id`, `|`, `` ` ``, `$(...)`, `/bin/sh`, `bash -c`, `curl`, `wget`, `/dev/tcp/`, một đường dẫn webshell lạ (`/uploads/x.php?cmd=`).
- SSTI: `{{...}}`, `${...}`, `__class__`.
- SSRF: `http://169.254.169.254`, `file://`, `localhost`.
- Traversal/LFI: `../../`, `/etc/passwd`, `/proc/self`.
- Hoặc đơn giản: một tên file, tham số, hoặc chuỗi payload mà **chỉ kẻ tấn công dùng**.

### Bước 4 — Sinh rule (không cần biết code)
Trong tab RULES: bôi đen đúng chuỗi đó (hoặc bấm Quick pick) → builder tự sinh:
- **Suricata** (cảnh báo) để quan sát trước, hoặc
- **ctf_proxy** (chặn thật) — nó viết sẵn method Python cho bạn.

### Bước 5 — Test TRƯỚC khi chặn (quan trọng nhất)
**Test on recent traffic**: rule khớp bao nhiêu lần, từ IP nào.
- Chỉ khớp IP kẻ tấn công → an toàn, áp.
- Khớp IP checker / máy mình → **quá rộng**, thu hẹp (thêm điều kiện path/method, chọn chuỗi đặc trưng hơn), test lại.

### Bước 6 — Áp & theo dõi
Áp (ctf_proxy: Check & Upload). Nhìn **MONITOR → watchdog** 1–2 tick: SLA vẫn ✓ là ổn. Sai → **SERVICES → ctf_proxy → Pause filtering** rồi sửa.

---

## 4. Cấu trúc một rule ctf_proxy (để tự sửa tay)
File trên vulnbox: `ctf-proxy-<team>/proxy/filter_modules/web/web_in.py`.
Bên trong có `class Module`. **Mỗi method = một rule.** ctf_proxy gọi mọi method; method nào trả `True` thì **chặn (đóng kết nối)**. Khung một rule:

```python
    def blk_ten_rule(self, stream):           # tên bắt đầu bằng blk_ cho dễ nhận
        """Mô tả rule làm gì."""
        try:                                   # LUÔN bọc try: lỗi -> không chặn (an toàn)
            import re
            m = stream.current_http_message
            if m is None:
                return False
            url  = str(m.url or "")                                   # đường dẫn + query
            body = bytes(m.raw_body or b"").decode("latin-1", "replace")  # body POST
            # True = chặn. Ví dụ chặn webshell gọi lệnh:
            return bool(re.search(r"\.php\?(cmd|exec|c)=", url, re.I))
        except Exception:
            return False
```

Thứ lấy được từ `m`: `m.url`, `m.path`, `m.method`, `m.query_string`, `m.parameters` (dict),
`m.headers` (dict), `m.raw_body` (bytes). Thu hẹp bằng `if "POST" in m.method and "/upload" in m.url:` …

**Ví dụ RCE** (chặn chuỗi command injection trong bất kỳ tham số):
```python
    def blk_rce_cmd(self, stream):
        """Chặn dấu nối shell + lệnh phổ biến (command injection / RCE)."""
        try:
            import re
            m = stream.current_http_message
            if m is None:
                return False
            from urllib.parse import unquote_plus
            data = unquote_plus(str(m.url or "") + "\n" + bytes(m.raw_body or b"").decode("latin-1","replace"))
            return bool(re.search(r"(;|\||&&|`|\$\()\s*(id|cat|ls|nc|curl|wget|bash|sh|python3?|whoami)\b"
                                  r"|/dev/tcp/|/bin/sh\b", data, re.I))
        except Exception:
            return False
```
Bản đầy đủ đã có sẵn: `rules-library/ctfproxy/block-injection.py` → `blk_cmd_injection`. Copy vào `class Module` rồi Upload.

**Luôn test bằng Suricata trước** (builder cho phép làm cùng điều kiện) để chắc không chặn checker.

---

## 5. Nếu KHÔNG cài được ctf_proxy
1. **Sửa nginx của chính service** (public-proxy, container đội bạn): dán block từ `rules-library/nginx/block-rules.conf` vào `server {}`, `nginx -t && nginx -s reload`. Chặn được đòn ở URL/tham số/User-Agent (không xem được body kỹ).
2. **Chặn IP** kẻ tấn công: Dashboard → SERVICES → **⛔ Fallback block** (iptables trên vulnbox). Thô nhưng dứt điểm. Cẩn thận IP checker.

---

## 6. Ghi nhớ
- Không biết tên đòn tấn công **không sao** — chặn theo **chuỗi đặc trưng** là đủ.
- **Luôn Test on recent traffic trước khi chặn.** Chặn nhầm checker = mất SLA, tệ hơn bị thủng 1 service.
- RCE đã thành công thì OS-watchdog thường báo (tiến trình/cron/file lạ) — vào đó tìm dấu vết, rồi chặn request đã gây ra (tìm trong HUNT quanh thời điểm đó).
- Mọi thao tác có thể Rollback. Nghi ngờ thì Pause filtering, không panic.
