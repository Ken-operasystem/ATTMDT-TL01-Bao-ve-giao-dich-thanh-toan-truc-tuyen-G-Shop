#!/usr/bin/env bash
# Chạy toàn bộ lab G-Shop và gom bằng chứng vào thư mục evidence/.
#   ./run.sh         build, sinh PKI, khởi động, kiểm thử, gia hạn chứng thư
#   ./run.sh clean   dừng lab, xóa container, volume, image và PKI đã sinh
set -euo pipefail
cd "$(dirname "$0")"
export HOST_UID=$(id -u) HOST_GID=$(id -g)
COMPOSE="docker compose --profile test"
EVIDENCE=evidence
RESULTS=()

step() { printf '\n== %s\n' "$1"; }
record() { RESULTS+=("$1: $2"); }

if [ "${1:-}" = "clean" ]; then
    docker compose --profile test --profile tools down -v --remove-orphans
    docker image rm tl01-gshop:latest 2>/dev/null || true
    rm -rf pki/out
    exit 0
fi

mkdir -p "$EVIDENCE"

step "1. Build image dùng chung"
docker compose build firewall

step "2. Sinh PKI, khóa SSH và secret (pki/out)"
docker compose --profile tools run --rm -T pki

step "3. Khởi động 9 container trong 6 vùng mạng"
$COMPOSE up -d --wait
for _ in $(seq 1 30); do
    if $COMPOSE exec -T tester curl -sf --cacert /pki/trust/public-root.crt \
        https://www.gshop.test/api/health >/dev/null; then break; fi
    sleep 1
done

step "4. Kiểm thử thanh toán, TLS và mTLS (pytest trên máy Internet)"
if $COMPOSE exec -T -w /srv/tests tester pytest -v -p no:cacheprovider \
    2>&1 | tee "$EVIDENCE/01-pytest.txt"; then
    record "pytest" PASS
else
    record "pytest" FAIL
fi

step "5. Kiểm thử phân vùng mạng (22 kết nối)"
if sh tests/network-matrix.sh 2>&1 | tee "$EVIDENCE/02-network-matrix.txt"; then
    record "network-matrix" PASS
else
    record "network-matrix" FAIL
fi
docker compose exec -T firewall nft list table inet gshop > "$EVIDENCE/03-firewall-counters.txt"

step "6. Kiểm thử chứng thư: chain, hostname, hạn, CRL, OCSP"
if docker compose --profile tools run --rm -T pki sh pki/test-pki.sh 2>&1 \
    | grep -v Container | tee "$EVIDENCE/04-pki-tests.txt"; then
    record "pki-tests" PASS
else
    record "pki-tests" FAIL
fi

step "7. Gia hạn chứng thư website và reload Nginx"
{
    docker compose --profile tools run --rm -T pki sh pki/renew-web.sh 2>&1 | grep -v Container
    docker compose exec -T web nginx -c /etc/nginx/gshop.conf -s reload
    sleep 1
    echo "Chung thu Nginx dang phuc vu sau khi reload:"
    $COMPOSE exec -T tester sh -c 'openssl s_client -connect www.gshop.test:443 \
        -servername www.gshop.test -CAfile /pki/trust/public-root.crt </dev/null 2>/dev/null \
        | openssl x509 -noout -serial -enddate -checkend 2592000' | sed 's/^/  /'
} 2>&1 | tee "$EVIDENCE/05-renewal.txt"
if grep -q "Certificate will not expire" "$EVIDENCE/05-renewal.txt"; then
    record "renewal" PASS
else
    record "renewal" FAIL
fi

step "8. Quản trị qua VPN -> Bastion (SSH khóa) -> API quản trị"
{
    echo "## Dang nhap bang mat khau (phai bi tu choi)"
    docker compose exec -T admin ssh -o BatchMode=yes -o PubkeyAuthentication=no \
        -o PreferredAuthentications=password ops@10.66.50.10 true 2>&1 || true
    echo "## Dang nhap root (phai bi tu choi)"
    docker compose exec -T admin ssh -o BatchMode=yes root@10.66.50.10 true 2>&1 || true
    echo "## Dang nhap ops bang khoa, goi API quan tri tu Bastion"
    docker compose exec -T admin ssh -o BatchMode=yes ops@10.66.50.10 \
        'curl -s -o /dev/null -w "admin API HTTP %{http_code}\n" -H "X-Admin-Token: $(cat /run/secrets/admin_token)" http://10.66.30.10:9000/admin/orders'
    echo "## Goi API quan tri tu Bastion khong co token"
    docker compose exec -T admin ssh -o BatchMode=yes ops@10.66.50.10 \
        'curl -s -o /dev/null -w "admin API HTTP %{http_code}\n" http://10.66.30.10:9000/admin/orders'
} 2>&1 | tee "$EVIDENCE/06-admin-access.txt"
docker compose exec -T admin ssh -o BatchMode=yes ops@10.66.50.10 \
    'curl -s -H "X-Admin-Token: $(cat /run/secrets/admin_token)" "http://10.66.30.10:9000/admin/audit?limit=200"' \
    | python3 -m json.tool --no-ensure-ascii > "$EVIDENCE/07-audit-log.json"
if grep -q "Permission denied (publickey)" "$EVIDENCE/06-admin-access.txt" \
    && grep -q "HTTP 200" "$EVIDENCE/06-admin-access.txt" \
    && grep -q "HTTP 401" "$EVIDENCE/06-admin-access.txt"; then
    record "admin-access" PASS
else
    record "admin-access" FAIL
fi

step "9. Log dịch vụ (Nginx, App, cổng thanh toán, ngân hàng, Bastion)"
docker compose logs --no-color --no-log-prefix web > "$EVIDENCE/08-nginx-access.log"
docker compose logs --no-color --no-log-prefix app > "$EVIDENCE/09-app.log"
docker compose logs --no-color gateway bank > "$EVIDENCE/10-gateway-bank.log"
docker compose logs --no-color --no-log-prefix bastion > "$EVIDENCE/11-bastion-sshd.log"

step "10. Quét evidence: không được chứa secret nào"
leaks=0
for file in pki/out/secrets/*; do
    if grep -rqF -f "$file" "$EVIDENCE"; then
        echo "LO SECRET: $(basename "$file")"
        leaks=$((leaks + 1))
    fi
done
if grep -rqE "BEGIN (EC |)PRIVATE KEY" "$EVIDENCE"; then
    echo "LO KHOA BI MAT"
    leaks=$((leaks + 1))
fi
echo "So secret bi lo trong evidence: $leaks" | tee "$EVIDENCE/12-secret-scan.txt"
[ "$leaks" -eq 0 ] && record "secret-scan" PASS || record "secret-scan" FAIL

step "Tổng kết"
printf '%s\n' "${RESULTS[@]}" | tee "$EVIDENCE/00-summary.txt"
! grep -q FAIL "$EVIDENCE/00-summary.txt"
