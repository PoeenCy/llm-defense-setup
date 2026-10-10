# Quick Radar

Dùng [README tại gốc repo](../../../README.md) và [sổ tay thực chiến](../../../HUONG_DAN_THUC_CHIEN.md). Các script ở đây là entry point tương thích gọi implementation chung; cần checkout toàn repo.

```bash
./set_target.sh 10.13.2.10 2201 ~/.ssh/cyberknight_id "80 8080 3000 8000" 2
./start_dashboard.sh 8888
```

`push_def.sh` chỉ chuyển payload khi không có `--apply`. Cú pháp triển khai và recovery giống script tại gốc repo; không còn cú pháp `set_target.sh -i/-p/-t` trong README cũ.

`service.conf.hardened` tại thư mục này là **profile router `http://service`**, dùng khi upstream/router đó đã tồn tại. Profile ba backend theo graph nằm ở gốc repo. Sinh lại thay vì sửa hai bản:

```bash
python3 ../../../DEF/render_waf.py --config ../../../config.env \
  --topology router --output service.conf.hardened
```

Checker được miễn tất cả rule WAF/rate limit theo peer IP cấu hình. Radar bind loopback mặc định, đọc cả log JSON và combined, phân loại dấu hiệu thay vì khẳng định đã khai thác thành công. Tỷ lệ HTTP OK không xác nhận flag roundtrip hay SLA. AI không có cam kết thời gian 15 giây và không tự triển khai gợi ý.
