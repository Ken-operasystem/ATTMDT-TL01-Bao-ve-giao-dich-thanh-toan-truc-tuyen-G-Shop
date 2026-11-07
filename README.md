# ATTMDT TL-01 - Bảo vệ giao dịch thanh toán trực tuyến cho G-Shop

Mã nguồn kèm theo bài tiểu luận "Đề xuất giải pháp bảo vệ giao dịch thanh toán trực tuyến cho hệ thống thương mại điện tử G-Shop" (môn An toàn thương mại điện tử, mã đề TL-01).

Lab mô phỏng hệ thống G-Shop bằng Docker Compose và kiểm chứng bốn nhóm giải pháp của bài:

1. **Mật mã cho luồng thanh toán**: AES-256-GCM cho dữ liệu lưu trữ, SHA-256 cho session token, HMAC-SHA256 cho webhook, ECDSA trong chứng thư.
2. **Chứng thực điện tử và kênh truyền**: PKI hai tầng (Root CA, Issuing CA, chứng thư website), TLS 1.2/1.3, mTLS tới API ngân hàng, CRL, OCSP, gia hạn và thu hồi.
3. **Phân vùng mạng và tường lửa**: 6 vùng (Internet, DMZ, App, Data, Management, VPN), firewall nftables mặc định chặn, Bastion chỉ nhận khóa SSH.
4. **Giao dịch an toàn**: server tự tính số tiền, xác thực webhook, cửa sổ thời gian ±5 phút, idempotency theo event_id, đối soát ngân hàng, chặn truy cập đơn của phiên khác.

## Kiến trúc

| Vùng | Subnet | Máy | Vai trò |
|---|---|---|---|
| Internet | 10.66.10.0/24 | 10.66.10.66 tester, 10.66.10.20 gateway, 10.66.10.30 bank | Khách hàng/kẻ tấn công, cổng thanh toán, ngân hàng |
| (Firewall) | 10.66.x.2 | firewall | Router nftables nối 6 vùng, IP công khai 10.66.10.2 |
| DMZ | 10.66.20.0/24 | 10.66.20.10 web | Nginx, kết thúc TLS |
| App | 10.66.30.0/24 | 10.66.30.10 app | FastAPI: API 8000, API quản trị 9000 |
| Data | 10.66.40.0/24 | 10.66.40.10 db | PostgreSQL 16 |
| Management | 10.66.50.0/24 | 10.66.50.10 bastion | SSH chỉ nhận khóa |
| VPN | 10.66.60.0/24 | 10.66.60.10 admin | Máy quản trị viên sau khi vào VPN |

Mỗi container chỉ nằm trong một vùng và có route `10.66.0.0/16` qua firewall. Docker chặn lưu lượng giữa hai bridge khác nhau, nên đường duy nhất giữa các vùng là firewall. Các bridge tắt NAT ra ngoài, lab không ra được Internet thật.

## Firewall rules (`firewall/gshop.nft`)

| Rule | Nguồn | Đích | Giao thức/Cổng | Hành động |
|---|---|---|---|---|
| R1 | Internet | Web 10.66.20.10 (DNAT từ 10.66.10.2) | TCP 443 | ACCEPT |
| R2 | Web 10.66.20.10 | App 10.66.30.10 | TCP 8000 | ACCEPT |
| R3 | App 10.66.30.10 | DB 10.66.40.10 | TCP 5432 | ACCEPT |
| R4a | App 10.66.30.10 | Cổng thanh toán 10.66.10.20 | TCP 8443 | ACCEPT |
| R4b | App 10.66.30.10 | Ngân hàng 10.66.10.30 | TCP 9443 (mTLS) | ACCEPT |
| R5 | VPN 10.66.60.0/24 | Bastion 10.66.50.10 | TCP 22 | ACCEPT |
| R6a | Bastion | Web, App, DB | TCP 22 | ACCEPT |
| R6b | Bastion | App 10.66.30.10 | TCP 9000 | ACCEPT |
| R7 | Internet | Firewall (VPN gateway) | UDP 51820 | ACCEPT |
| R8 | Mọi nguồn | Mọi đích | Mọi giao thức | DROP (Default Deny) |

## Cách chạy

Yêu cầu: Docker Engine 28 trở lên (có Docker Compose v2), bash. Đã chạy trên Linux (WSL2) với Docker 29.4.

```bash
./run.sh          # build, sinh PKI, khởi động, kiểm thử, gia hạn chứng thư, gom bằng chứng
./run.sh clean    # dừng lab, xóa container, volume, image và PKI đã sinh
```

`run.sh` làm 10 bước và ghi kết quả vào `evidence/`:

| File | Nội dung |
|---|---|
| `00-summary.txt` | Tổng kết PASS/FAIL từng nhóm |
| `01-pytest.txt` | 16 test: 9 test thanh toán (TC01-TC09), 7 test TLS/mTLS |
| `02-network-matrix.txt` | 22 phép thử kết nối giữa các vùng, so với bảng rule |
| `03-firewall-counters.txt` | Counter từng rule nftables sau khi kiểm thử |
| `04-pki-tests.txt` | 10 phép thử chứng thư: chain, hostname, hạn, CRL, OCSP |
| `05-renewal.txt` | Gia hạn chứng thư website, reload Nginx, thu hồi bản cũ |
| `06-admin-access.txt` | SSH qua Bastion: mật khẩu và root bị từ chối, khóa được nhận |
| `07-audit-log.json` | Audit log của ứng dụng (đã che dữ liệu nhạy cảm) |
| `08`-`11` | Log Nginx, App, cổng thanh toán, ngân hàng, sshd |
| `12-secret-scan.txt` | Kiểm tra evidence không chứa secret hay khóa bí mật |

## Test case thanh toán

| Mã | Tình huống | Kết quả mong đợi |
|---|---|---|
| TC01 | Luồng thanh toán hợp lệ | Đơn PAID, cookie có Secure/HttpOnly/SameSite |
| TC02 | Trình duyệt gửi số tiền 1.000đ | Bị bỏ qua, server tính 700.000đ từ giá trong DB |
| TC03 | Sửa số tiền trong webhook, giữ chữ ký | 401 signature_invalid, đơn vẫn PENDING |
| TC04 | Webhook ký bằng khóa khác hoặc không ký | 401 |
| TC05 | Gửi lại webhook đã xử lý (replay) | 200 duplicate_event, đơn không đổi |
| TC06 | Webhook ký từ 10 phút trước | 401 timestamp_out_of_window |
| TC07 | Gửi trùng 10 lần đồng thời | Đúng 1 lần paid, 9 lần duplicate_event |
| TC08 | Webhook hợp lệ nhưng sai đơn hoặc sai số tiền | 409 txn_mismatch, 409 amount_mismatch |
| TC09 | Xem đơn của phiên khác, không có phiên | 404, 401 |

## Cấu trúc thư mục

```text
app/gshop/     ứng dụng G-Shop (FastAPI): API, webhook, mã hóa, API quản trị
gateway/       cổng thanh toán giả lập (TLS, API key, ký webhook HMAC)
bank/          API ngân hàng giả lập (mTLS, CRL, phân quyền theo CN)
firewall/      chính sách nftables
web/           cấu hình Nginx (TLS, HSTS, header bảo mật)
db/            pg_hba.conf, schema và tài khoản ít quyền
bastion/       sshd chỉ nhận khóa, máy quản trị viên
pki/           sinh PKI, kiểm thử chứng thư, gia hạn
tests/         pytest và kiểm thử phân vùng mạng
docs/diagrams/ sơ đồ draw.io dùng trong báo cáo
evidence/      kết quả của lần chạy ./run.sh gần nhất
```

## Lưu ý

- Đây là môi trường lab. Cổng thanh toán và ngân hàng là bản giả lập; endpoint `/v1/debug/*` và `test_options` của cổng chỉ nhận từ máy kiểm thử khi bật `GATEWAY_DEBUG=1`, dùng để tạo webhook bị bắt lại, quá hạn hoặc sai số liệu.
- Mọi khóa, chứng thư và secret được sinh ngẫu nhiên khi chạy, nằm trong `pki/out/` và không được commit. Tên miền dùng đuôi `.test` (RFC 2606), dải IP 10.66.0.0/16.
- `com.docker.network.bridge.gateway_mode_ipv4=nat-unprotected` tắt rule chặn truy cập thẳng IP container của Docker 28+, để gói tin định tuyến qua container firewall đi được. Việc lọc do nftables đảm nhận.
