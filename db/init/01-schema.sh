#!/bin/sh
# Tạo bảng và tài khoản ứng dụng ít quyền (chạy một lần khi khởi tạo DB)
set -eu
APP_PASSWORD=$(cat /run/secrets/db_app_password)

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v app_password="$APP_PASSWORD" <<'SQL'
CREATE ROLE gshop_app LOGIN PASSWORD :'app_password';

CREATE TABLE products (
    id         int PRIMARY KEY,
    name       text NOT NULL,
    price_vnd  bigint NOT NULL CHECK (price_vnd > 0)
);
INSERT INTO products VALUES
    (1, 'Tai nghe Bluetooth G1', 590000),
    (2, 'Bàn phím cơ G-K87', 1250000),
    (3, 'Chuột không dây G-M2', 350000);

-- Chỉ lưu SHA-256 của session token, không lưu token gốc
CREATE TABLE sessions (
    token_hash  bytea PRIMARY KEY,
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL
);

CREATE TABLE orders (
    id              uuid PRIMARY KEY,
    session_hash    bytea NOT NULL REFERENCES sessions(token_hash),
    product_id      int NOT NULL REFERENCES products(id),
    quantity        int NOT NULL CHECK (quantity BETWEEN 1 AND 10),
    amount_vnd      bigint NOT NULL CHECK (amount_vnd > 0),
    currency        char(3) NOT NULL DEFAULT 'VND',
    status          text NOT NULL DEFAULT 'PENDING'
                    CHECK (status IN ('PENDING', 'PAID', 'FAILED')),
    gateway_txn_id  text UNIQUE,
    bank_ref        text,
    shipping_enc    bytea NOT NULL,   -- nonce || AES-256-GCM(ciphertext + tag)
    created_at      timestamptz NOT NULL DEFAULT now(),
    paid_at         timestamptz
);

-- Khóa idempotency: mỗi event_id của webhook chỉ được xử lý một lần
CREATE TABLE webhook_events (
    event_id     text PRIMARY KEY,
    txn_id       text NOT NULL,
    order_id     uuid NOT NULL,
    received_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE audit_log (
    id      bigserial PRIMARY KEY,
    at      timestamptz NOT NULL DEFAULT now(),
    actor   text NOT NULL,
    action  text NOT NULL,
    detail  jsonb NOT NULL DEFAULT '{}'
);

-- Least privilege: không DDL, không DELETE đơn hàng, audit chỉ được thêm
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO gshop_app;
GRANT SELECT ON products TO gshop_app;
GRANT SELECT, INSERT ON sessions TO gshop_app;
GRANT SELECT, INSERT ON orders TO gshop_app;
GRANT UPDATE (status, gateway_txn_id, bank_ref, paid_at) ON orders TO gshop_app;
GRANT SELECT, INSERT ON webhook_events TO gshop_app;
GRANT SELECT, INSERT ON audit_log TO gshop_app;
GRANT USAGE ON SEQUENCE audit_log_id_seq TO gshop_app;
SQL
echo "db: schema và role gshop_app đã tạo"
