"""Cổng thanh toán giả lập (bên thứ ba) - chỉ dùng trong lab.

- POST /v1/payments  : G-Shop tạo giao dịch (Bearer API key, Idempotency-Key)
- POST /pay/<txn_id> : khách thanh toán trên trang của cổng; cổng ghi nợ qua
                       ngân hàng (mTLS) rồi gửi webhook ký HMAC cho G-Shop
- GET  /v1/debug/deliveries/<txn_id> : xem webhook đã gửi (chỉ cho máy kiểm thử)
"""
import hashlib
import hmac
import json
import os
import secrets
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

sys.path.insert(0, "/srv/scripts")
from tlsserver import JSONHandler, TLSServer, log  # noqa: E402

API_KEY = open("/run/secrets/gateway_api_key").read().strip()
WEBHOOK_SECRET = open("/run/secrets/webhook_secret").read().strip().encode()
MERCHANT_WEBHOOK = "https://www.gshop.test/api/payments/webhook"
BANK_URL = "https://api.bank.test:9443"
PUBLIC_URL = "https://pay.gateway.test:8443"
# Tùy chọn kiểm thử (không gửi webhook, lùi timestamp, sửa trường) chỉ nhận
# từ máy kiểm thử khi bật GATEWAY_DEBUG=1
DEBUG = os.environ.get("GATEWAY_DEBUG") == "1"
TESTER_IP = os.environ.get("TESTER_IP", "10.66.10.66")

payments = {}      # txn_id -> giao dịch
idempotency = {}   # Idempotency-Key -> txn_id
deliveries = {}    # txn_id -> các webhook đã ký
lock = threading.Lock()


def sign(timestamp: str, body: bytes) -> str:
    message = timestamp.encode() + b"." + body
    return "v1=" + hmac.new(WEBHOOK_SECRET, message, hashlib.sha256).hexdigest()


def tls_context(cafile: str, client_cert=None) -> ssl.SSLContext:
    ctx = ssl.create_default_context(cafile=cafile)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if client_cert:
        ctx.load_cert_chain(*client_cert)
    return ctx


def post(url: str, body: bytes, headers: dict, ctx: ssl.SSLContext):
    request = urllib.request.Request(url, data=body, method="POST", headers={
        "Content-Type": "application/json", **headers})
    try:
        with urllib.request.urlopen(request, context=ctx, timeout=10) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        return error.code, json.loads(error.read() or b"{}")


class Handler(JSONHandler):
    def do_POST(self):
        if self.path == "/v1/payments":
            return self.create_payment()
        if self.path.startswith("/pay/"):
            return self.pay(self.path[len("/pay/"):])
        self.send_json(404, {"error": "not_found"})

    def do_GET(self):
        prefix = "/v1/debug/deliveries/"
        if self.path.startswith(prefix) and self.debug_allowed():
            txn_id = self.path[len(prefix):]
            return self.send_json(200, {"deliveries": deliveries.get(txn_id, [])})
        self.send_json(404, {"error": "not_found"})

    def debug_allowed(self) -> bool:
        return DEBUG and self.client_address[0] == TESTER_IP

    def create_payment(self):
        # Bước 1: Xác thực merchant bằng API key (so sánh thời gian hằng)
        auth = self.headers.get("Authorization", "")
        if not hmac.compare_digest(auth.encode(), f"Bearer {API_KEY}".encode()):
            return self.send_json(401, {"error": "invalid_api_key"})
        key = self.headers.get("Idempotency-Key", "")
        data = self.read_json()
        if not key or data.get("currency") != "VND" or int(data.get("amount_vnd", 0)) <= 0:
            return self.send_json(400, {"error": "invalid_request"})
        with lock:
            # Bước 2: Cùng Idempotency-Key thì trả lại đúng giao dịch cũ
            if key in idempotency:
                payment = payments[idempotency[key]]
            else:
                txn_id = "GW" + secrets.token_hex(8).upper()
                payment = {"txn_id": txn_id, "order_id": data["order_id"],
                           "amount_vnd": int(data["amount_vnd"]),
                           "currency": "VND", "status": "CREATED"}
                payments[txn_id] = payment
                idempotency[key] = txn_id
        self.send_json(201, {"txn_id": payment["txn_id"],
                             "pay_url": f"{PUBLIC_URL}/pay/{payment['txn_id']}"})

    def pay(self, txn_id: str):
        data = self.read_json()   # số thẻ (nếu có) không được ghi log
        options = data.get("test_options", {}) if self.debug_allowed() else {}
        with lock:
            payment = payments.get(txn_id)
            if payment is None or payment["status"] != "CREATED":
                return self.send_json(409, {"error": "payment_not_payable"})
            payment["status"] = "PROCESSING"

        # Bước 3: Ghi nợ qua API ngân hàng bằng mTLS (chứng thư client pay-gateway)
        bank_ctx = tls_context("/pki/trust/bank-ca.crt",
                               ("/pki/gw-client/gw.crt", "/pki/gw-client/gw.key"))
        status, bank = post(f"{BANK_URL}/v1/transactions", json.dumps({
            "txn_id": txn_id, "amount_vnd": payment["amount_vnd"],
            "currency": "VND", "merchant_id": "GSHOP"}).encode(), {}, bank_ctx)
        if status != 201:
            payment["status"] = "FAILED"
            return self.send_json(502, {"error": "bank_declined"})
        payment.update(status="SUCCESS", bank_ref=bank["bank_ref"])

        # Bước 4: Tạo sự kiện và ký HMAC-SHA256 trên "<timestamp>.<raw body>"
        event = {"event_id": "evt_" + secrets.token_hex(12), "type": "payment.succeeded",
                 "txn_id": txn_id, "order_id": payment["order_id"],
                 "amount_vnd": payment["amount_vnd"], "currency": "VND",
                 "bank_ref": bank["bank_ref"], "status": "SUCCESS",
                 "created_at": datetime.now(timezone.utc).isoformat()}
        event.update(options.get("override", {}))
        body = json.dumps(event, separators=(",", ":")).encode()
        timestamp = str(int(time.time()) - int(options.get("age_seconds", 0)))
        headers = {"X-GS-Timestamp": timestamp, "X-GS-Signature": sign(timestamp, body)}
        record = {"headers": headers, "body": body.decode(), "status": None}
        deliveries.setdefault(txn_id, []).append(record)

        # Bước 5: Gửi webhook tới G-Shop, kiểm tra chứng thư www.gshop.test
        if options.get("deliver", True):
            web_ctx = tls_context("/pki/trust/public-root.crt")
            for attempt in range(3):
                try:
                    status, _ = post(MERCHANT_WEBHOOK, body, headers, web_ctx)
                except (urllib.error.URLError, OSError) as error:
                    log("gateway", f"webhook lỗi lần {attempt + 1}: {error}")
                    status = None
                record["status"] = status
                if status is not None and status < 500:
                    break
                time.sleep(1)
        self.send_json(200, {"txn_id": txn_id, "status": "SUCCESS",
                             "bank_ref": bank["bank_ref"],
                             "webhook_status": record["status"]})


def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain("/pki/gateway-tls/fullchain.pem", "/pki/gateway-tls/pay.key")
    server = TLSServer(("0.0.0.0", 8443), Handler, ctx, "gateway")
    log("gateway", f"nghe 8443, debug={DEBUG}")
    server.serve_forever()


if __name__ == "__main__":
    main()
