"""API quản trị, nghe ở cổng 9000. Firewall chỉ cho Bastion truy cập cổng này."""
import hmac

from fastapi import Depends, FastAPI, Header, HTTPException, Request

from gshop import config, db

app = FastAPI(title="G-Shop admin", docs_url=None, redoc_url=None, openapi_url=None)


def require_admin(request: Request, x_admin_token: str = Header(default="")):
    if not hmac.compare_digest(x_admin_token.encode(), config.ADMIN_TOKEN.encode()):
        raise HTTPException(401, "admin_token_invalid")
    with db.connect() as conn, conn.cursor() as cur:
        db.audit(cur, "admin", "admin_access", path=request.url.path,
                 ip=request.client.host)
        conn.commit()


@app.get("/admin/orders", dependencies=[Depends(require_admin)])
def list_orders(limit: int = 20):
    with db.connect() as conn:
        rows = conn.execute(
            "SELECT id, amount_vnd, status, gateway_txn_id, bank_ref, created_at, "
            "paid_at FROM orders ORDER BY created_at DESC LIMIT %s",
            (min(limit, 100),),
        ).fetchall()
    return [{**row, "id": str(row["id"])} for row in rows]


@app.get("/admin/audit", dependencies=[Depends(require_admin)])
def list_audit(limit: int = 30):
    with db.connect() as conn:
        return conn.execute(
            "SELECT id, at, actor, action, detail FROM audit_log "
            "ORDER BY id DESC LIMIT %s",
            (min(limit, 200),),
        ).fetchall()
