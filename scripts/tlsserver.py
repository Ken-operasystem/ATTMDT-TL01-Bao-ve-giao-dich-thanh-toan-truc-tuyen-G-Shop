"""HTTP server có TLS dùng chung cho gateway và bank (thư viện chuẩn Python).

Bắt tay TLS làm trong verify_request để ghi log lý do khi client bị từ chối
(không có chứng thư, chứng thư bị thu hồi, CA lạ...).
"""
import json
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class TLSServer(ThreadingHTTPServer):
    def __init__(self, address, handler, context: ssl.SSLContext, name: str):
        super().__init__(address, handler)
        self.context = context
        self.name = name

    def get_request(self):
        sock, addr = self.socket.accept()
        sock.settimeout(10)
        tls = self.context.wrap_socket(sock, server_side=True,
                                       do_handshake_on_connect=False)
        return tls, addr

    def verify_request(self, request, client_address):
        try:
            request.do_handshake()
            return True
        except (ssl.SSLError, OSError) as error:
            reason = getattr(error, "reason", None) or type(error).__name__
            log(self.name, f"{client_address[0]} TLS_REJECT {reason}")
            return False


class JSONHandler(BaseHTTPRequestHandler):
    server_version = "lab"
    sys_version = ""

    def log_request(self, code="-", size="-"):
        log(self.server.name, f"{self.client_address[0]} {self.peer_name()} "
                              f"{self.command} {self.path.split('?')[0]} {code}")

    def log_message(self, fmt, *args):
        pass

    def peer_name(self) -> str:
        cert = self.connection.getpeercert()
        if not cert:
            return "-"
        subject = dict(item[0] for item in cert["subject"])
        return subject.get("commonName", "-")

    def read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length))

    def send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def log(name: str, message: str) -> None:
    print(f"{name}: {message}", file=sys.stdout, flush=True)
