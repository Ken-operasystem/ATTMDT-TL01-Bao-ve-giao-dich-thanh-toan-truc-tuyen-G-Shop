"""Chạy API công khai (8000) và API quản trị (9000) trong cùng tiến trình."""
import asyncio

import uvicorn

from gshop import db


async def main():
    db.wait_for_db()
    public = uvicorn.Server(uvicorn.Config(
        "gshop.main:app", host="0.0.0.0", port=8000,
        proxy_headers=True, forwarded_allow_ips="10.66.20.10", log_level="info"))
    admin = uvicorn.Server(uvicorn.Config(
        "gshop.admin:app", host="0.0.0.0", port=9000, log_level="info"))
    await asyncio.gather(public.serve(), admin.serve())


if __name__ == "__main__":
    asyncio.run(main())
