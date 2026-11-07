"""Kiểm thử luồng thanh toán: sửa số tiền, giả webhook, replay, trùng, truy cập trái phép."""
import hashlib
import hmac
import json
import secrets
import time
from concurrent.futures import ThreadPoolExecutor

from conftest import (captured_webhooks, compact, create_order, new_shop,
                      order_status, pay, send_webhook)


def test_tc01_luong_thanh_toan_hop_le(shop):
    # Cookie phiên phải có Secure, HttpOnly, SameSite
    cookie = shop.post("/api/session").headers["set-cookie"].lower()
    assert "secure" in cookie and "httponly" in cookie and "samesite=lax" in cookie

    order = create_order(shop, product_id=2, quantity=1)
    assert order["amount_vnd"] == 1_250_000 and order["status"] == "PENDING"

    result = pay(order["txn_id"])
    assert result["webhook_status"] == 200

    status = order_status(shop, order["order_id"])
    assert status["status"] == "PAID"
    assert status["paid_at"] is not None
    assert status["shipping"]["phone"] == "09******67"   # dữ liệu giải mã và che


def test_tc02_trinh_duyet_sua_so_tien_bi_bo_qua(shop):
    # Kẻ tấn công sửa request, gửi giá 1.000đ cho 2 sản phẩm 350.000đ
    order = create_order(shop, product_id=3, quantity=2, amount_vnd=1000)
    assert order["amount_vnd"] == 700_000          # server tự tính từ giá trong DB
    pay(order["txn_id"])
    assert order_status(shop, order["order_id"])["amount_vnd"] == 700_000


def test_tc03_sua_so_tien_trong_webhook_bi_tu_choi(shop):
    order = create_order(shop)
    pay(order["txn_id"], deliver=False)
    webhook = captured_webhooks(order["txn_id"])[0]

    # Giữ nguyên chữ ký, chỉ đổi số tiền trong body
    event = json.loads(webhook["body"])
    event["amount_vnd"] = 1000
    response = send_webhook(webhook["headers"], compact(event))
    assert response.status_code == 401
    assert response.json()["error"] == "signature_invalid"
    assert order_status(shop, order["order_id"])["status"] == "PENDING"

    # Bản gốc chưa bị sửa vẫn được chấp nhận
    response = send_webhook(webhook["headers"], webhook["body"])
    assert response.status_code == 200 and response.json()["result"] == "paid"


def test_tc04_webhook_gia_mao_khong_co_secret(shop):
    order = create_order(shop)
    pay(order["txn_id"], deliver=False)
    body = captured_webhooks(order["txn_id"])[0]["body"].encode()

    # Kẻ tấn công không có secret, tự ký bằng khóa khác
    timestamp = str(int(time.time()))
    fake_key = secrets.token_bytes(32)
    fake = "v1=" + hmac.new(fake_key, timestamp.encode() + b"." + body,
                            hashlib.sha256).hexdigest()
    response = send_webhook({"X-GS-Timestamp": timestamp, "X-GS-Signature": fake}, body)
    assert response.status_code == 401

    # Không có chữ ký
    response = send_webhook({"X-GS-Timestamp": timestamp}, body)
    assert response.status_code == 401
    assert order_status(shop, order["order_id"])["status"] == "PENDING"


def test_tc05_replay_webhook_da_xu_ly(shop):
    order = create_order(shop)
    pay(order["txn_id"])
    paid_at = order_status(shop, order["order_id"])["paid_at"]

    # Gửi lại đúng gói tin hợp lệ đã bắt được
    webhook = captured_webhooks(order["txn_id"])[0]
    response = send_webhook(webhook["headers"], webhook["body"])
    assert response.status_code == 200
    assert response.json()["result"] == "duplicate_event"
    assert order_status(shop, order["order_id"])["paid_at"] == paid_at


def test_tc06_webhook_qua_5_phut_bi_tu_choi(shop):
    order = create_order(shop)
    pay(order["txn_id"], deliver=False, age_seconds=600)   # ký từ 10 phút trước
    webhook = captured_webhooks(order["txn_id"])[0]
    response = send_webhook(webhook["headers"], webhook["body"])
    assert response.status_code == 401
    assert response.json()["error"] == "timestamp_out_of_window"
    assert order_status(shop, order["order_id"])["status"] == "PENDING"


def test_tc07_gui_trung_10_lan_dong_thoi(shop):
    order = create_order(shop)
    pay(order["txn_id"], deliver=False)
    webhook = captured_webhooks(order["txn_id"])[0]

    with ThreadPoolExecutor(max_workers=10) as pool:
        responses = list(pool.map(
            lambda _: send_webhook(webhook["headers"], webhook["body"]), range(10)))
    results = sorted(r.json().get("result") for r in responses)
    assert results.count("paid") == 1
    assert results.count("duplicate_event") == 9
    assert order_status(shop, order["order_id"])["status"] == "PAID"


def test_tc08_webhook_hop_le_nhung_sai_don_hoac_sai_tien(shop):
    expensive = create_order(shop, product_id=2)   # 1.250.000đ
    cheap = create_order(shop, product_id=3)       # 350.000đ

    # Dùng giao dịch của đơn rẻ để ghi nhận cho đơn đắt
    pay(cheap["txn_id"], deliver=False,
        override={"order_id": expensive["order_id"]})
    webhook = captured_webhooks(cheap["txn_id"])[0]
    response = send_webhook(webhook["headers"], webhook["body"])
    assert response.status_code == 409 and response.json()["error"] == "txn_mismatch"

    # Cổng báo số tiền khác số tiền của đơn
    pay(expensive["txn_id"], deliver=False, override={"amount_vnd": 1000})
    webhook = captured_webhooks(expensive["txn_id"])[0]
    response = send_webhook(webhook["headers"], webhook["body"])
    assert response.status_code == 409 and response.json()["error"] == "amount_mismatch"
    assert order_status(shop, expensive["order_id"])["status"] == "PENDING"


def test_tc09_khong_xem_duoc_don_cua_phien_khac(shop):
    order = create_order(shop)
    other = new_shop()
    assert other.get(f"/api/orders/{order['order_id']}").status_code == 404

    anonymous = new_shop()
    anonymous.cookies.clear()
    assert anonymous.get(f"/api/orders/{order['order_id']}").status_code == 401
    anonymous.cookies.set("__Host-gshop_sid", "token-doan-mo", domain="www.gshop.test")
    assert anonymous.get(f"/api/orders/{order['order_id']}").status_code == 401
