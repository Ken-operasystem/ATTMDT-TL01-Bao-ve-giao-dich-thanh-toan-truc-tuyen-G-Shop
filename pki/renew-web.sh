#!/bin/sh
# Gia hạn chứng thư website khi còn dưới 30 ngày:
#   tạo khóa mới + CSR -> Issuing CA ký 90 ngày -> thay file -> thu hồi bản cũ
#   (superseded) -> phát hành CRL mới. Sau đó run.sh reload Nginx.
set -eu
cd "${1:-/work/pki/out}"
CA=public-ca/issuing
export SAN="DNS:www.gshop.test,DNS:gshop.test"

show() {
    printf '  %s: serial=%s, het han=%s\n' "$1" \
        "$(openssl x509 -in "$2" -noout -serial | cut -d= -f2)" \
        "$(openssl x509 -in "$2" -noout -enddate | cut -d= -f2)"
}

if openssl x509 -in web/www.crt -noout -checkend $((30 * 86400)) >/dev/null; then
    echo "Chung thu con tren 30 ngay, chua can gia han."
    show "Hien tai" web/www.crt
    exit 0
fi

echo "Buoc 1: Chung thu con duoi 30 ngay, bat dau gia han"
show "Ban cu" web/www.crt

echo "Buoc 2: Tao khoa ECDSA P-256 moi va CSR (khoa khong roi may chu)"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout web/www-new.key -out web/www-new.csr \
    -subj "/O=G-Shop/CN=www.gshop.test" 2>/dev/null

echo "Buoc 3: Issuing CA kiem tra CSR va ky chung thu 90 ngay"
openssl req -in web/www-new.csr -noout -verify 2>&1 | sed 's/^/  CSR: /'
openssl ca -batch -notext -config $CA/ca.cnf -extensions server_leaf -days 90 \
    -in web/www-new.csr -out web/www-new.crt 2>/dev/null
openssl verify -CAfile trust/public-root.crt -untrusted trust/public-issuing.crt \
    -verify_hostname www.gshop.test web/www-new.crt | sed 's/^/  /'

echo "Buoc 4: Thay chung thu tren Web (giu ban cu de thu hoi)"
cp web/www.crt web/www-prev.crt
cat web/www-new.crt trust/public-issuing.crt > web/fullchain.pem.tmp
mv web/www-new.key web/www.key
mv web/www-new.crt web/www.crt
mv web/fullchain.pem.tmp web/fullchain.pem
chmod 644 web/www.key web/www.crt web/fullchain.pem
show "Ban moi" web/www.crt

echo "Buoc 5: Thu hoi ban cu (superseded) va phat hanh CRL moi"
openssl ca -config $CA/ca.cnf -revoke web/www-prev.crt -crl_reason superseded 2>/dev/null
openssl ca -gencrl -config $CA/ca.cnf -out $CA/ca.crl.pem 2>/dev/null
cp $CA/ca.crl.pem trust/issuing.crl.pem
chmod 644 trust/issuing.crl.pem $CA/ca.crl.pem
openssl verify -crl_check -CAfile trust/public-root.crt -untrusted trust/public-issuing.crt \
    -CRLfile trust/issuing.crl.pem web/www-prev.crt 2>&1 | grep -E "error|OK" | sed 's/^/  Ban cu: /'
if [ -n "${HOST_UID:-}" ]; then
    chown -R "$HOST_UID:${HOST_GID:-$HOST_UID}" .
fi
echo "Xong: can reload Nginx de dung chung thu moi."
