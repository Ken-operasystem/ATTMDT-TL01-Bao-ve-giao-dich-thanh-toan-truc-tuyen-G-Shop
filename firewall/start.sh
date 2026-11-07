#!/bin/sh
# Nạp chính sách nftables rồi giữ container chạy làm router giữa các vùng.
set -eu
nft -f /srv/firewall/gshop.nft
echo "firewall: đã nạp $(nft -a list table inet gshop | grep -c comment) rule có tên"
exec sleep infinity
