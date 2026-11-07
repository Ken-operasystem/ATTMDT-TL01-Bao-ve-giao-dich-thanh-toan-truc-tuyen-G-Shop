"""Kết nối PostgreSQL bằng tài khoản ít quyền gshop_app."""
import json
import time
from contextlib import contextmanager

import psycopg
from psycopg.rows import dict_row

from gshop import config


@contextmanager
def connect():
    conn = psycopg.connect(config.DB_DSN, row_factory=dict_row)
    try:
        yield conn
    finally:
        conn.close()


def wait_for_db(timeout: int = 60) -> None:
    deadline = time.time() + timeout
    while True:
        try:
            with connect() as conn:
                conn.execute("SELECT 1")
            return
        except psycopg.OperationalError:
            if time.time() > deadline:
                raise
            time.sleep(1)


def audit(cur, actor: str, action: str, **detail) -> None:
    # Audit log chỉ ghi dữ liệu đã che, không ghi secret hay chữ ký
    cur.execute(
        "INSERT INTO audit_log (actor, action, detail) VALUES (%s, %s, %s)",
        (actor, action, json.dumps(detail, ensure_ascii=False)),
    )
