"""Gọi cổng thanh toán (TLS + API key) và ngân hàng (mTLS)."""
import ssl

import httpx

from gshop import config


def _public_tls() -> ssl.SSLContext:
    # Kiểm tra chain tới Root CA công khai và hostname/SAN của cổng thanh toán
    ctx = ssl.create_default_context(cafile=config.PUBLIC_ROOT_CA)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return ctx


def _bank_mtls() -> ssl.SSLContext:
    # Chỉ tin CA của ngân hàng, và gửi chứng thư client của G-Shop
    ctx = ssl.create_default_context(cafile=config.BANK_CA)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(*config.BANK_CLIENT_CERT)
    return ctx


def create_payment(order_id: str, amount_vnd: int, currency: str) -> dict:
    """Tạo giao dịch ở cổng thanh toán. Idempotency-Key = mã đơn hàng."""
    response = httpx.post(
        f"{config.GATEWAY_URL}/v1/payments",
        json={"order_id": order_id, "amount_vnd": amount_vnd, "currency": currency},
        headers={
            "Authorization": f"Bearer {config.GATEWAY_API_KEY}",
            "Idempotency-Key": order_id,
        },
        verify=_public_tls(),
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


def bank_get_transaction(bank_ref: str) -> dict:
    """Đối soát với ngân hàng qua mTLS trước khi ghi nhận đơn đã thanh toán."""
    response = httpx.get(
        f"{config.BANK_URL}/v1/transactions/{bank_ref}",
        verify=_bank_mtls(),
        timeout=10,
    )
    response.raise_for_status()
    return response.json()
