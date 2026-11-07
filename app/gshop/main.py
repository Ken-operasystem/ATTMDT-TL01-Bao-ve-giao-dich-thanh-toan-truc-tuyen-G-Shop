"""API công khai của G-Shop (sau Nginx trong DMZ): phiên, đơn hàng, webhook."""
import json
import time
import uuid

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from starlette.concurrency import run_in_threadpool

from gshop import config, db, partners
from gshop.security import (decrypt_field, encrypt_field, hash_token,
                            mask_phone, new_session_token, verify_webhook)

app = FastAPI(title="G-Shop", docs_url=None, redoc_url=None, openapi_url=None)
SESSION_COOKIE = "__Host-gshop_sid"


class Shipping(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    phone: str = Field(pattern=r"^0\d{9}$")
    address: str = Field(min_length=5, max_length=200)


class OrderIn(BaseModel):
    product_id: int
    quantity: int = Field(ge=1, le=10)
    shipping: Shipping
    # Trình duyệt có gửi số tiền thì cũng bị bỏ qua, server tự tính lại
    amount_vnd: int | None = None


class Reject(Exception):
    def __init__(self, status: int, reason: str):
        self.status = status
        self.reason = reason


def require_session(request: Request) -> bytes:
    token = request.cookies.get(SESSION_COOKIE, "")
    if not token:
        raise HTTPException(401, "session_required")
    token_hash = hash_token(token)
    with db.connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM sessions WHERE token_hash = %s AND expires_at > now()",
            (token_hash,),
        ).fetchone()
    if row is None:
        raise HTTPException(401, "session_invalid")
    return token_hash


@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/session", status_code=201)
def create_session(response: Response):
    token = new_session_token()
    with db.connect() as conn:
        conn.execute(
            "INSERT INTO sessions (token_hash, expires_at) "
            "VALUES (%s, now() + make_interval(secs => %s))",
            (hash_token(token), config.SESSION_TTL_SECONDS),
        )
        conn.commit()
    # Cookie chỉ gửi qua HTTPS, JavaScript không đọc được, chặn gửi chéo trang
    response.set_cookie(SESSION_COOKIE, token, max_age=config.SESSION_TTL_SECONDS,
                        secure=True, httponly=True, samesite="lax", path="/")
    return {"session": "created", "expires_in": config.SESSION_TTL_SECONDS}


@app.get("/api/products")
def list_products():
    with db.connect() as conn:
        return conn.execute(
            "SELECT id, name, price_vnd FROM products ORDER BY id").fetchall()


@app.post("/api/orders", status_code=201)
def create_order(body: OrderIn, request: Request,
                 session_hash: bytes = Depends(require_session)):
    order_id = str(uuid.uuid4())
    with db.connect() as conn, conn.cursor() as cur:
        cur.execute("SELECT price_vnd FROM products WHERE id = %s", (body.product_id,))
        product = cur.fetchone()
        if product is None:
            raise HTTPException(404, "product_not_found")

        # Bước 1: Số tiền tính ở server từ giá trong DB
        amount = product["price_vnd"] * body.quantity

        # Bước 2: Mã hóa thông tin giao hàng bằng AES-256-GCM, AAD = mã đơn
        shipping_enc = encrypt_field(config.DATA_KEY,
                                     body.shipping.model_dump_json(), order_id)
        cur.execute(
            "INSERT INTO orders (id, session_hash, product_id, quantity, "
            "amount_vnd, shipping_enc) VALUES (%s, %s, %s, %s, %s, %s)",
            (order_id, session_hash, body.product_id, body.quantity,
             amount, shipping_enc),
        )
        if body.amount_vnd is not None and body.amount_vnd != amount:
            db.audit(cur, "customer", "client_amount_ignored", order_id=order_id,
                     client_amount=body.amount_vnd, server_amount=amount,
                     ip=request.client.host)
        db.audit(cur, "customer", "order_created", order_id=order_id,
                 amount_vnd=amount, ip=request.client.host)
        conn.commit()

    # Bước 3: Tạo giao dịch ở cổng thanh toán bằng API key qua TLS
    try:
        payment = partners.create_payment(order_id, amount, "VND")
    except httpx.HTTPError:
        raise HTTPException(502, "gateway_unavailable")
    with db.connect() as conn:
        conn.execute(
            "UPDATE orders SET gateway_txn_id = %s "
            "WHERE id = %s AND gateway_txn_id IS NULL",
            (payment["txn_id"], order_id),
        )
        conn.commit()
    return {"order_id": order_id, "amount_vnd": amount, "currency": "VND",
            "status": "PENDING", "txn_id": payment["txn_id"],
            "pay_url": payment["pay_url"]}


@app.get("/api/orders/{order_id}")
def get_order(order_id: uuid.UUID, session_hash: bytes = Depends(require_session)):
    with db.connect() as conn:
        row = conn.execute(
            "SELECT id, product_id, quantity, amount_vnd, currency, status, "
            "gateway_txn_id, paid_at, shipping_enc FROM orders "
            "WHERE id = %s AND session_hash = %s",
            (order_id, session_hash),
        ).fetchone()
    # Đơn của phiên khác cũng trả 404 để không lộ đơn đó có tồn tại hay không
    if row is None:
        raise HTTPException(404, "order_not_found")
    shipping = json.loads(decrypt_field(config.DATA_KEY,
                                        bytes(row["shipping_enc"]), str(row["id"])))
    return {
        "order_id": str(row["id"]), "product_id": row["product_id"],
        "quantity": row["quantity"], "amount_vnd": row["amount_vnd"],
        "currency": row["currency"].strip(), "status": row["status"],
        "txn_id": row["gateway_txn_id"],
        "paid_at": row["paid_at"].isoformat() if row["paid_at"] else None,
        "shipping": {"name": shipping["name"], "phone": mask_phone(shipping["phone"])},
    }


@app.post("/api/payments/webhook")
async def payment_webhook(request: Request):
    raw_body = await request.body()
    timestamp = request.headers.get("X-GS-Timestamp", "")
    signature = request.headers.get("X-GS-Signature", "")
    source_ip = request.client.host

    # Bước 1: Kiểm tra HMAC-SHA256 và cửa sổ thời gian ±5 phút trên raw body
    ok, reason = verify_webhook(config.WEBHOOK_SECRET, timestamp, raw_body,
                                signature, time.time(),
                                config.WEBHOOK_TOLERANCE_SECONDS)
    if not ok:
        await run_in_threadpool(_audit_reject, reason, source_ip, None)
        return JSONResponse({"error": reason}, status_code=401)

    # Bước 2: Chỉ đọc nội dung sau khi chữ ký đã đúng
    try:
        event = json.loads(raw_body)
        fields = ("event_id", "type", "txn_id", "order_id", "amount_vnd",
                  "currency", "bank_ref", "status")
        if not all(key in event for key in fields):
            raise ValueError
        uuid.UUID(event["order_id"])
    except ValueError:
        return JSONResponse({"error": "payload_invalid"}, status_code=400)

    status, result = await run_in_threadpool(_process_event, event, source_ip)
    return JSONResponse(result, status_code=status)


def _audit_reject(reason: str, source_ip: str, event: dict | None) -> None:
    detail = {"reason": reason, "ip": source_ip}
    if event:
        detail.update(event_id=event["event_id"], order_id=event["order_id"])
    with db.connect() as conn, conn.cursor() as cur:
        db.audit(cur, "gateway", "webhook_rejected", **detail)
        conn.commit()


def _process_event(event: dict, source_ip: str):
    if event["type"] != "payment.succeeded" or event["status"] != "SUCCESS":
        return 200, {"result": "ignored"}
    with db.connect() as conn:
        try:
            with conn.transaction(), conn.cursor() as cur:
                # Bước 3: Idempotency - event_id đã có thì không xử lý lại
                cur.execute(
                    "INSERT INTO webhook_events (event_id, txn_id, order_id) "
                    "VALUES (%s, %s, %s) ON CONFLICT (event_id) DO NOTHING "
                    "RETURNING event_id",
                    (event["event_id"], event["txn_id"], event["order_id"]),
                )
                if cur.fetchone() is None:
                    db.audit(cur, "gateway", "webhook_duplicate",
                             event_id=event["event_id"], ip=source_ip)
                    return 200, {"result": "duplicate_event"}

                # Bước 4: Khóa dòng đơn hàng rồi đối chiếu mã giao dịch, số tiền
                cur.execute(
                    "SELECT amount_vnd, currency, status, gateway_txn_id "
                    "FROM orders WHERE id = %s FOR UPDATE",
                    (event["order_id"],),
                )
                order = cur.fetchone()
                if order is None:
                    raise Reject(409, "order_not_found")
                if order["gateway_txn_id"] != event["txn_id"]:
                    raise Reject(409, "txn_mismatch")
                if (order["amount_vnd"] != event["amount_vnd"]
                        or order["currency"].strip() != event["currency"]):
                    raise Reject(409, "amount_mismatch")
                if order["status"] == "PAID":
                    db.audit(cur, "gateway", "webhook_already_paid",
                             event_id=event["event_id"], order_id=event["order_id"])
                    return 200, {"result": "already_paid"}
                if order["status"] != "PENDING":
                    raise Reject(409, "invalid_state")

                # Bước 5: Đối soát với ngân hàng qua mTLS
                try:
                    bank = partners.bank_get_transaction(event["bank_ref"])
                except httpx.HTTPError:
                    raise Reject(502, "bank_unreachable")
                if (bank["status"] != "SUCCESS" or bank["txn_id"] != event["txn_id"]
                        or bank["amount_vnd"] != order["amount_vnd"]):
                    raise Reject(409, "bank_mismatch")

                # Bước 6: Ghi nhận thanh toán (cùng transaction với event_id)
                cur.execute(
                    "UPDATE orders SET status = 'PAID', bank_ref = %s, "
                    "paid_at = now() WHERE id = %s",
                    (event["bank_ref"], event["order_id"]),
                )
                db.audit(cur, "gateway", "order_paid", event_id=event["event_id"],
                         order_id=event["order_id"], amount_vnd=order["amount_vnd"],
                         bank_ref=event["bank_ref"], ip=source_ip)
                return 200, {"result": "paid", "order_id": event["order_id"]}
        except Reject as rejected:
            # Transaction đã rollback nên event_id chưa bị đánh dấu đã xử lý
            _audit_reject(rejected.reason, source_ip, event)
            return rejected.status, {"error": rejected.reason}
