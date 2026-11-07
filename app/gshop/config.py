"""Cấu hình G-Shop. Secret đọc từ file do Docker mount vào /run/secrets."""
import base64
import os
from pathlib import Path

SECRETS_DIR = Path(os.environ.get("SECRETS_DIR", "/run/secrets"))


def read_secret(name: str) -> str:
    return (SECRETS_DIR / name).read_text().strip()


DB_DSN = (
    f"host={os.environ.get('DB_HOST', '10.66.40.10')} port=5432 dbname=gshop "
    f"user=gshop_app password={read_secret('db_app_password')} connect_timeout=5"
)

# Khóa AES-256 (32 byte) để mã hóa thông tin giao hàng trong DB
DATA_KEY = base64.b64decode(read_secret("data_key"))
assert len(DATA_KEY) == 32, "data_key phải là 32 byte"

# Secret HMAC dùng chung với cổng thanh toán để xác thực webhook
WEBHOOK_SECRET = read_secret("webhook_secret").encode()
WEBHOOK_TOLERANCE_SECONDS = 300

# API key G-Shop dùng khi gọi cổng thanh toán
GATEWAY_API_KEY = read_secret("gateway_api_key")
GATEWAY_URL = os.environ.get("GATEWAY_URL", "https://pay.gateway.test:8443")

# mTLS tới ngân hàng: chứng thư client do ngân hàng cấp từ CSR của G-Shop
BANK_URL = os.environ.get("BANK_URL", "https://api.bank.test:9443")
BANK_CLIENT_CERT = ("/pki/client/gshop-app.crt", "/pki/client/gshop-app.key")
BANK_CA = "/pki/trust/bank-ca.crt"

# CA công khai để kiểm tra chứng thư TLS của cổng thanh toán
PUBLIC_ROOT_CA = "/pki/trust/public-root.crt"

ADMIN_TOKEN = read_secret("admin_token")
SESSION_TTL_SECONDS = 30 * 60
