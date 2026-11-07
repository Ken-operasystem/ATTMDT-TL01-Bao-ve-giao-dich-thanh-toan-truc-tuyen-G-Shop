"""Các hàm mật mã dùng trong G-Shop."""
import hashlib
import hmac
import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

NONCE_SIZE = 12  # 96 bit, theo khuyến nghị NIST SP 800-38D cho GCM


# Bước 1: Mã hóa đối xứng AES-256-GCM cho dữ liệu lưu trữ.
# AAD = mã đơn hàng: dữ liệu được xác thực nhưng không mã hóa, nên bản mã
# của đơn này không thể chép sang đơn khác.
def encrypt_field(key: bytes, plaintext: str, aad: str) -> bytes:
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext.encode(), aad.encode())
    return nonce + ciphertext


def decrypt_field(key: bytes, blob: bytes, aad: str) -> str:
    nonce, ciphertext = blob[:NONCE_SIZE], blob[NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, ciphertext, aad.encode()).decode()


# Bước 2: Session token ngẫu nhiên 256 bit; DB chỉ lưu SHA-256 của token
def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def hash_token(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


# Bước 3: HMAC-SHA256 cho webhook. Chuỗi được ký = "<timestamp>.<raw body>"
def webhook_signature(secret: bytes, timestamp: str, body: bytes) -> str:
    message = timestamp.encode() + b"." + body
    return "v1=" + hmac.new(secret, message, hashlib.sha256).hexdigest()


def verify_webhook(secret: bytes, timestamp: str, body: bytes,
                   signature: str, now: float, tolerance: int):
    """Trả về (True, "") nếu hợp lệ, ngược lại (False, lý do)."""
    if not timestamp.isdigit():
        return False, "timestamp_invalid"
    expected = webhook_signature(secret, timestamp, body)
    # So sánh thời gian hằng để không lộ chữ ký đúng qua thời gian phản hồi
    if not hmac.compare_digest(expected, signature):
        return False, "signature_invalid"
    if abs(now - int(timestamp)) > tolerance:
        return False, "timestamp_out_of_window"
    return True, ""


def mask_phone(phone: str) -> str:
    if len(phone) < 4:
        return "***"
    return phone[:2] + "*" * (len(phone) - 4) + phone[-2:]
