#!/bin/sh
# Mọi lưu lượng sang vùng khác phải đi qua firewall (10.66.20.2)
set -eu
ip route replace 10.66.0.0/16 via 10.66.20.2
exec nginx -c /etc/nginx/gshop.conf -g 'daemon off;'
