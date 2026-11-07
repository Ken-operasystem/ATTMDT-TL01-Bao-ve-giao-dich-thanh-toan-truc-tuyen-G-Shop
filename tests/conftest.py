"""Hàm dùng chung cho kiểm thử. Máy kiểm thử nằm ở vùng Internet (10.66.10.66)."""
import json
import ssl

import httpx
import pytest

SHOP_URL = "https://www.gshop.test"
GATEWAY_URL = "https://pay.gateway.test:8443"
PUBLIC_CA = "/pki/trust/public-root.crt"
# Chỉ tin Root CA của lab, kiểm tra chain và hostname như trình duyệt
TRUST = ssl.create_default_context(cafile=PUBLIC_CA)
SHIPPING = {"name": "Nguyen Van A", "phone": "0901234567",
            "address": "12 Nguyen Hue, Quan 1, TP.HCM"}


def new_shop() -> httpx.Client:
    """Một khách hàng mới: client HTTPS có phiên riêng."""
    client = httpx.Client(base_url=SHOP_URL, verify=TRUST, timeout=20)
    client.post("/api/session").raise_for_status()
    return client


def create_order(client: httpx.Client, product_id=2, quantity=1, **extra) -> dict:
    body = {"product_id": product_id, "quantity": quantity,
            "shipping": SHIPPING, **extra}
    response = client.post("/api/orders", json=body)
    assert response.status_code == 201, response.text
    return response.json()


def pay(txn_id: str, **test_options) -> dict:
    """Khách thanh toán trên trang của cổng thanh toán."""
    response = httpx.post(f"{GATEWAY_URL}/pay/{txn_id}", verify=TRUST, timeout=30,
                          json={"card_number": "4111111111111111",
                                "test_options": test_options})
    assert response.status_code == 200, response.text
    return response.json()


def captured_webhooks(txn_id: str) -> list:
    """Webhook cổng đã ký cho giao dịch (mô phỏng gói tin bị bắt lại)."""
    response = httpx.get(f"{GATEWAY_URL}/v1/debug/deliveries/{txn_id}",
                         verify=TRUST, timeout=10)
    return response.json()["deliveries"]


def send_webhook(headers: dict, body) -> httpx.Response:
    if isinstance(body, str):
        body = body.encode()
    return httpx.post(f"{SHOP_URL}/api/payments/webhook", content=body,
                      headers={"Content-Type": "application/json", **headers},
                      verify=TRUST, timeout=20)


def order_status(client: httpx.Client, order_id: str) -> dict:
    response = client.get(f"/api/orders/{order_id}")
    assert response.status_code == 200, response.text
    return response.json()


def compact(data: dict) -> str:
    return json.dumps(data, separators=(",", ":"))


@pytest.fixture
def shop():
    client = new_shop()
    yield client
    client.close()
