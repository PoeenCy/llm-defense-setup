# SETUP_CHECKLIST.md — CSCV2026 team18 (cyb3rkn1ght.tdtu)

File tạm, riêng cho giải này — xoá/đổi tên sau khi thi xong, không phải tài liệu dùng lại được
như `docs/GOLIVE.md`. Mục tiêu: **sau khi VPN kết nối được, điền đúng các mục dưới đây một lần,
rồi chạy đúng 4 lệnh ở cuối là xong.**

**Không có mật khẩu nào trong file này hoặc trong `services.json`.** Mật khẩu root (trong file
BTC cấp) chỉ dùng MỘT LẦN ở bước 2 để tự cài SSH key, sau đó không cần nữa.

---

## 0. Trạng thái hiện tại (đã làm / chưa làm)

- [x] Build + cài SoftEther VPN client, tạo account `team18cscv` — xem `~/softether-install/vpnclient/`.
- [ ] **VPN chưa kết nối được** — bị chặn vì IP công khai của máy chưa nằm trong Source IP
      Restriction List của Virtual Hub. Cần báo BTC whitelist IP `113.185.50.189` (hoặc IP mới
      nếu ISP đã đổi — kiểm tra lại bằng `curl -4 ifconfig.me`).
- [x] `contest-runtime/config/services.json` đã chuyển sang schema nhiều host (`vulnboxes[]`,
      6 host: edge-proxy/gitea/ci-runner/jenkins/dns-ops/web-app) — nhánh git `feature/multi-host-cscv`.
- [ ] Mọi giá trị cụ thể (port, IP máy giám sát, flag regex, SSH key...) — **chưa điền**, xem mục 1-4.

---

## 1. Sau khi VPN kết nối được — việc đầu tiên

```bash
# Kết nối (đã tạo account sẵn, chỉ cần connect lại):
cd ~/softether-install/vpnclient
./vpncmd localhost /CLIENT /CMD AccountConnect team18cscv
./vpncmd localhost /CLIENT /CMD AccountStatusGet team18cscv   # phải thấy "Session Status: Connected"

# Lấy đúng IP của máy này trên VPN (KHÔNG phải IP wifi nhà) -- điền vào mục 2 dưới:
ip -4 addr show   # tìm interface mới xuất hiện (thường tên "team18"/"vpn_...")
```

## 2. Cài SSH key cho cả 6 máy (dùng mật khẩu root MỘT LẦN duy nhất ở đây)

```bash
# Tạo key riêng cho giải này nếu chưa có:
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_cscv -N ""

# Copy key lên từng máy (sẽ hỏi mật khẩu root -- lấy từ file BTC cấp, KHÔNG gõ vào đây/lưu lại):
ssh-copy-id -i ~/.ssh/id_ed25519_cscv.pub root@172.16.118.102   # edge-proxy
ssh-copy-id -i ~/.ssh/id_ed25519_cscv.pub root@172.16.118.103   # gitea
ssh-copy-id -i ~/.ssh/id_ed25519_cscv.pub root@172.16.118.104   # ci-runner
ssh-copy-id -i ~/.ssh/id_ed25519_cscv.pub root@172.16.118.105   # jenkins
ssh-copy-id -i ~/.ssh/id_ed25519_cscv.pub root@172.16.118.109   # dns-ops
ssh-copy-id -i ~/.ssh/id_ed25519_cscv.pub root@172.16.118.111   # web-app
```

Sau đó dán đoạn này vào `~/.ssh/config` (tạo file nếu chưa có) — **đúng tên alias mà
`services.json` đang chờ sẵn**, không cần sửa gì thêm trong `services.json` nếu dùng đúng tên:

```
Host cscv-edge-proxy
  HostName 172.16.118.102
  User root
  IdentityFile ~/.ssh/id_ed25519_cscv
  StrictHostKeyChecking accept-new

Host cscv-gitea
  HostName 172.16.118.103
  User root
  IdentityFile ~/.ssh/id_ed25519_cscv
  StrictHostKeyChecking accept-new

Host cscv-ci-runner
  HostName 172.16.118.104
  User root
  IdentityFile ~/.ssh/id_ed25519_cscv
  StrictHostKeyChecking accept-new

Host cscv-jenkins
  HostName 172.16.118.105
  User root
  IdentityFile ~/.ssh/id_ed25519_cscv
  StrictHostKeyChecking accept-new

Host cscv-dns-ops
  HostName 172.16.118.109
  User root
  IdentityFile ~/.ssh/id_ed25519_cscv
  StrictHostKeyChecking accept-new

Host cscv-web-app
  HostName 172.16.118.111
  User root
  IdentityFile ~/.ssh/id_ed25519_cscv
  StrictHostKeyChecking accept-new
```

Test lại cả 6 (không hỏi mật khẩu nữa là đúng):
```bash
for h in cscv-edge-proxy cscv-gitea cscv-ci-runner cscv-jenkins cscv-dns-ops cscv-web-app; do
  echo "--- $h ---"; ssh "$h" "hostname; uptime"
done
```

## 3. Dò service thật trên mỗi máy (để biết điền port nào vào `services.json`)

Chạy trên từng host (đổi `cscv-<tên>` cho đúng máy):
```bash
ssh cscv-web-app "ss -tlnp; echo ---; docker ps 2>/dev/null"
```
Ghi lại: port nào đang LISTEN trên `0.0.0.0`/interface ngoài (không phải chỉ `127.0.0.1`), tên
service tương ứng (nhìn qua `docker ps` hoặc tên tiến trình).

## 4. Điền vào `contest-runtime/config/services.json` — đúng các mục còn thiếu

| Mục | Đường dẫn JSON | Lấy giá trị từ đâu |
|---|---|---|
| IP máy giám sát trên VPN | `monitor_host.ip` | Lệnh `ip -4 addr show` ở Bước 1 |
| CIDR mạng team | `teams_cidr` | Hỏi BTC, hoặc suy từ `ip route` sau khi VPN connect (thường cùng dải `172.16.118.0/24`-ish, **đừng đoán, hỏi BTC cho chắc**) |
| Flag regex | `flag.regex` | Xem format flag thật trên rCTF scoreboard, hoặc hỏi BTC |
| Flag submit | `flag.submit_url` | rCTF — **khác ForcAD**, có thể không cần `submit_url` kiểu PUT nữa, kiểm tra UI scoreboard trước khi điền bừa |
| rCTF scoreboard IP | `gameserver_hint.ip` | Hỏi BTC / domain scoreboard họ cấp |
| Service của từng host | `vulnboxes[].services` | Kết quả dò ở Bước 3 — mỗi service 1 object `{"name","port","proto","layer"}`, host nào không có service thật thì để `[]` (hệ thống tự bỏ qua, không lỗi) |

Sau khi điền xong:
```bash
bash contest-runtime/config/validate-config.sh     # phải PASS hết, không còn dòng CHANGE_ME nào FAIL
```

## 5. Chạy toàn bộ — đúng thứ tự, 1 lần

```bash
cd /home/poeency/Documents/Setup_tool
git checkout feature/multi-host-cscv      # nhánh đang chứa toàn bộ phần multi-host
bash contest-runtime/config/validate-config.sh
MODE=contest bash deploy-all.sh
bash health-check.sh
```

**Lưu ý quan trọng**: tới lúc viết file này, `ctf_proxy`/honeytoken/OS-watchdog deploy script
**chưa được chuyển sang nhiều host** (vẫn đang giả định 1 vulnbox) — `deploy-all.sh` ở bước
5-6 nhiều khả năng sẽ lỗi hoặc chỉ áp dụng cho 1 host. Capture (bắt traffic) và Suricata/Tulip
đã chuyển xong, chạy được cho tất cả host có khai `services[]`. Phần còn thiếu sẽ được bổ sung
tiếp — hỏi lại nếu tới bước đó mà chưa thấy cập nhật.
