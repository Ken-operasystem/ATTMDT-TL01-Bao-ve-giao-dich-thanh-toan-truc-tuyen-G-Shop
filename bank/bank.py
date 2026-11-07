"""API ngân hàng giả lập, bắt buộc mTLS - chỉ dùng trong lab.

Client phải trình chứng thư do Bank Lab mTLS CA cấp, chưa bị thu hồi (CRL),
và chỉ được gọi những API có trong ACL theo CN của chứng thư.
"""
import secrets
import ssl
import sys
import threading

sys.path.insert(0, "/srv/scripts")
from tlsserver import JSONHandler, TLSServer, log  # noqa: E402

# Quyền theo danh tính client (CN trong chứng thư)
ACL = {
    "pay-gateway": {"POST /v1/transactions", "GET /v1/transactions"},
    "gshop-app": {"GET /v1/transactions"},
}

transactions = {}   # bank_ref -> giao dịch
lock = threading.Lock()


class Handler(JSONHandler):
    def allowed(self, action: str) -> bool:
        if action in ACL.get(self.peer_name(), set()):
            return True
        self.send_json(403, {"error": "forbidden_for_client", "client": self.peer_name()})
        return False

    def do_POST(self):
        if self.path != "/v1/transactions":
            return self.send_json(404, {"error": "not_found"})
        if not self.allowed("POST /v1/transactions"):
            return
        data = self.read_json()
        with lock:
            bank_ref = "BK" + "".join(secrets.choice("0123456789") for _ in range(10))
            transactions[bank_ref] = {
                "bank_ref": bank_ref, "txn_id": data["txn_id"],
                "amount_vnd": int(data["amount_vnd"]), "currency": data["currency"],
                "merchant_id": data["merchant_id"], "status": "SUCCESS"}
        self.send_json(201, transactions[bank_ref])

    def do_GET(self):
        prefix = "/v1/transactions/"
        if not self.path.startswith(prefix):
            return self.send_json(404, {"error": "not_found"})
        if not self.allowed("GET /v1/transactions"):
            return
        record = transactions.get(self.path[len(prefix):])
        if record is None:
            return self.send_json(404, {"error": "not_found"})
        self.send_json(200, record)


def main():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain("/pki/bank/api.crt", "/pki/bank/api.key")
    # Bắt buộc client có chứng thư hợp lệ của Bank CA và chưa bị thu hồi
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations("/pki/trust/bank-ca.crt")
    ctx.load_verify_locations("/pki/trust/bank-ca.crl.pem")
    ctx.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF
    server = TLSServer(("0.0.0.0", 9443), Handler, ctx, "bank")
    log("bank", "nghe 9443, mTLS bắt buộc, kiểm tra CRL")
    server.serve_forever()


if __name__ == "__main__":
    main()
