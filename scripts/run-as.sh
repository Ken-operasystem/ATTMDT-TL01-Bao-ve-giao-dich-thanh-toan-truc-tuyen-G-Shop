#!/bin/sh
# Dùng: run-as.sh <IP firewall của vùng | -> <user> <lệnh...>
# Thêm route sang các vùng khác qua firewall (cần NET_ADMIN), sau đó hạ quyền.
set -eu
FIREWALL_IP=$1
RUN_USER=$2
shift 2
if [ "$FIREWALL_IP" != "-" ]; then
    ip route replace 10.66.0.0/16 via "$FIREWALL_IP"
fi
exec su-exec "$RUN_USER" "$@"
