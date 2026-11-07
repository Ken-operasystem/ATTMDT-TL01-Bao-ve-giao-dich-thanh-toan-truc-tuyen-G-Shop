#!/bin/sh
# Máy quản trị viên sau khi đã vào VPN: chỉ đi được tới Bastion
set -eu
ip route replace 10.66.0.0/16 via 10.66.60.2
mkdir -p /root/.ssh
install -m 600 /pki/ssh/id_ed25519 /root/.ssh/id_ed25519
# Ghim host key của Bastion, không chấp nhận host key lạ
install -m 644 /pki/ssh/known_hosts /root/.ssh/known_hosts
exec sleep infinity
