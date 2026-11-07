"""Kiểm thử kênh truyền: TLS website và mTLS tới ngân hàng."""
import socket
import ssl
import subprocess

import httpx
import pytest

PUBLIC_CA = "/pki/trust/public-root.crt"
BANK_CA = "/pki/trust/bank-ca.crt"
BANK_URL = "https://api.bank.test:9443/v1/transactions"
CLIENT = ("/pki/client/gshop-app.crt", "/pki/client/gshop-app.key")
CLIENT_REVOKED = ("/pki/client/gshop-app-old.crt", "/pki/client/gshop-app-old.key")


def tls_connect(host: str, port: int, server_hostname: str, cafile=PUBLIC_CA,
                max_version=None):
    ctx = ssl.create_default_context(cafile=cafile)
    if max_version:
        ctx.maximum_version = max_version
    with socket.create_connection((host, port), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname=server_hostname) as tls:
            return tls.version(), tls.getpeercert()


def test_tls01_chain_hostname_va_phien_ban():
    version, cert = tls_connect("www.gshop.test", 443, "www.gshop.test")
    assert version == "TLSv1.3"
    assert ("DNS", "www.gshop.test") in cert["subjectAltName"]

    # Server gửi đủ chain: chứng thư website + Issuing CA (2 chứng thư)
    out = subprocess.run(
        ["openssl", "s_client", "-connect", "www.gshop.test:443", "-servername",
         "www.gshop.test", "-showcerts", "-CAfile", PUBLIC_CA],
        input=b"", capture_output=True, timeout=10).stdout.decode()
    assert out.count("BEGIN CERTIFICATE") == 2
    assert "Verify return code: 0 (ok)" in out


def test_tls02_sai_hostname_bi_tu_choi():
    # Chứng thư của cổng thanh toán không có SAN www.gshop.test
    with pytest.raises(ssl.SSLCertVerificationError, match="Hostname mismatch"):
        tls_connect("pay.gateway.test", 8443, "www.gshop.test")
    # SNI lạ: Nginx từ chối bắt tay
    with pytest.raises(ssl.SSLError):
        tls_connect("www.gshop.test", 443, "evil.gshop.test")


def test_tls03_ca_la_khong_duoc_tin():
    # Client chỉ tin CA của ngân hàng thì không chấp nhận chứng thư website
    with pytest.raises(ssl.SSLCertVerificationError):
        tls_connect("www.gshop.test", 443, "www.gshop.test", cafile=BANK_CA)


def test_tls04_tls_cu_bi_tu_choi():
    out = subprocess.run(
        ["openssl", "s_client", "-connect", "www.gshop.test:443", "-servername",
         "www.gshop.test", "-tls1_1", "-cipher", "DEFAULT@SECLEVEL=0"],
        input=b"", capture_output=True, timeout=10)
    # Client đã đề nghị TLS 1.1, chính server gửi alert 70 (protocol version)
    assert out.returncode != 0
    assert "alert protocol version" in out.stderr.decode()


def test_mtls01_khong_co_chung_thu_client():
    with pytest.raises((httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError)):
        httpx.get(f"{BANK_URL}/BK0000000000",
                  verify=ssl.create_default_context(cafile=BANK_CA), timeout=5)


def test_mtls02_chung_thu_client_da_thu_hoi():
    ctx = ssl.create_default_context(cafile=BANK_CA)
    ctx.load_cert_chain(*CLIENT_REVOKED)
    with pytest.raises((httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError)):
        httpx.get(f"{BANK_URL}/BK0000000000", verify=ctx, timeout=5)


def test_mtls03_chung_thu_hop_le_va_acl():
    ctx = ssl.create_default_context(cafile=BANK_CA)
    ctx.load_cert_chain(*CLIENT)
    # Được đọc giao dịch (mã không tồn tại thì 404, không phải lỗi TLS)
    assert httpx.get(f"{BANK_URL}/BK0000000000", verify=ctx, timeout=5).status_code == 404
    # gshop-app không được tạo giao dịch ghi nợ
    response = httpx.post(BANK_URL, json={}, verify=ctx, timeout=5)
    assert response.status_code == 403
    assert response.json()["error"] == "forbidden_for_client"
