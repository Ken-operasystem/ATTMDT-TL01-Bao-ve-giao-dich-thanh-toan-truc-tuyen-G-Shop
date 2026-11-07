#!/bin/sh
# Bastion trong vùng Management: route qua firewall, nạp host key và khóa
# công khai của quản trị viên, rồi chạy sshd.
set -eu
ip route replace 10.66.0.0/16 via 10.66.50.2
install -m 600 /pki/ssh/host_ed25519 /etc/ssh/ssh_host_ed25519_key
mkdir -p /etc/ssh/authorized_keys
install -m 644 /pki/ssh/authorized_ops.pub /etc/ssh/authorized_keys/ops
exec /usr/sbin/sshd -D -e -f /srv/bastion/sshd_config
