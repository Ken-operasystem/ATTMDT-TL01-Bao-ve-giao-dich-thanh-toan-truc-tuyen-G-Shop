#!/bin/sh
# Kiểm thử các bước client kiểm tra chứng thư: chain, hostname/SAN, thời hạn,
# trạng thái thu hồi (CRL và OCSP). Chạy trong container pki (không có mạng).
set -u
cd "${1:-/work/pki/out}"
TMP=$(mktemp -d)
PASS=0
FAIL=0
ROOT=trust/public-root.crt
ISSUING=trust/public-issuing.crt
CRL=trust/issuing.crl.pem

check() {
    # $1 mã phép thử  $2 mô tả  $3 chuỗi mong đợi  $4.. lệnh
    id=$1; desc=$2; expect=$3; shift 3
    out=$("$@" 2>&1)
    if echo "$out" | grep -q -- "$expect"; then
        PASS=$((PASS + 1)); verdict=PASS
    else
        FAIL=$((FAIL + 1)); verdict=FAIL
    fi
    echo "$verdict $id $desc"
    echo "$out" | grep -v '^$' | sed 's/^/      /' | tail -2
}

check P1 "Chain day du Root -> Issuing -> www.gshop.test" "www.crt: OK" \
    openssl verify -CAfile $ROOT -untrusted $ISSUING web/www.crt

check P2 "Thieu Intermediate CA" "error 20" \
    openssl verify -CAfile $ROOT web/www.crt

check P3 "Hostname dung www.gshop.test" "www.crt: OK" \
    openssl verify -CAfile $ROOT -untrusted $ISSUING -verify_hostname www.gshop.test web/www.crt

check P4 "Hostname sai shop.attacker.test" "error 62" \
    openssl verify -CAfile $ROOT -untrusted $ISSUING -verify_hostname shop.attacker.test web/www.crt

LATER=$(( $(date +%s) + 30 * 86400 ))
check P5 "Kiem tra tai thoi diem 30 ngay sau (het han)" "error 10" \
    openssl verify -CAfile $ROOT -untrusted $ISSUING -attime $LATER web/www.crt

check P6 "CRL: chung thu dang dung chua bi thu hoi" "www.crt: OK" \
    openssl verify -crl_check -CAfile $ROOT -untrusted $ISSUING -CRLfile $CRL web/www.crt

check P7 "CRL: chung thu cu da thu hoi (keyCompromise)" "error 23" \
    openssl verify -crl_check -CAfile $ROOT -untrusted $ISSUING -CRLfile $CRL web/www-old.crt

# OCSP: client gửi yêu cầu, responder của Issuing CA trả lời có ký
cat $ROOT $ISSUING > "$TMP/chain.pem"
ocsp_status() {
    openssl ocsp -issuer $ISSUING -cert "$1" -no_nonce -reqout "$TMP/req.der" >/dev/null 2>&1
    openssl ocsp -index public-ca/issuing/index.txt -CA $ISSUING \
        -rsigner public-ca/issuing/ocsp.crt -rkey public-ca/issuing/ocsp.key \
        -reqin "$TMP/req.der" -respout "$TMP/resp.der" -nmin 5 >/dev/null 2>&1
    openssl ocsp -respin "$TMP/resp.der" -issuer $ISSUING -cert "$1" \
        -CAfile "$TMP/chain.pem" 2>&1
}
check P8 "OCSP: www.crt -> good" "www.crt: good" ocsp_status web/www.crt
check P9 "OCSP: www-old.crt -> revoked" "www-old.crt: revoked" ocsp_status web/www-old.crt

check P10 "Canh bao sap het han (con duoi 30 ngay)" "will expire" \
    openssl x509 -in web/www.crt -noout -checkend $((30 * 86400))

rm -rf "$TMP"
echo "Tong: $PASS PASS, $FAIL FAIL"
[ "$FAIL" -eq 0 ]
