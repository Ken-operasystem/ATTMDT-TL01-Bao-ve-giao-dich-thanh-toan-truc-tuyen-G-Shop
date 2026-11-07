#!/bin/sh
# Trả lời các vùng khác qua firewall (10.66.40.2), sau đó chạy PostgreSQL
set -eu
ip route replace 10.66.0.0/16 via 10.66.40.2
exec docker-entrypoint.sh postgres \
    -c hba_file=/etc/postgresql/pg_hba.conf \
    -c password_encryption=scram-sha-256 \
    -c log_connections=on
