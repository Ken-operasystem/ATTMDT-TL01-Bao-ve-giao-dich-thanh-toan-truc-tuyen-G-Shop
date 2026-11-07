#!/bin/sh
# Kiểm thử phân vùng mạng: thử mở kết nối TCP từ từng vùng tới từng đích và so
# với kết quả mong đợi theo bảng firewall rule. Chạy trên máy host (cần Docker).
# Mỗi phép thử chạy nc trong network namespace của container nguồn, nên dùng
# đúng địa chỉ IP và route của máy đó.
set -u
IMAGE=tl01-gshop:latest
PASS=0
FAIL=0

probe() {
    # $1 nguồn (service)  $2 IP đích  $3 port  $4 mong đợi  $5 rule  $6 mô tả
    out=$(docker run --rm --network "container:gshop-lab-$1-1" "$IMAGE" \
          nc -z -v -w 2 "$2" "$3" 2>&1)
    if echo "$out" | grep -q "succeeded"; then
        got=ALLOW
    elif echo "$out" | grep -q "timed out"; then
        got=BLOCK
    else
        got="LOI($(echo "$out" | tail -1))"
    fi
    if [ "$got" = "$4" ]; then
        verdict=PASS
        PASS=$((PASS + 1))
    else
        verdict=FAIL
        FAIL=$((FAIL + 1))
    fi
    printf '%-4s %-8s %-15s %-5s %-6s %-6s %-5s %s\n' \
        "$verdict" "$1" "$2" "$3" "$4" "$got" "$5" "$6"
}

printf '%-4s %-8s %-15s %-5s %-6s %-6s %-5s %s\n' \
    KQ NGUON DICH PORT MONGDOI THUCTE RULE "MO TA"

# Từ Internet
probe tester  10.66.10.2  443  ALLOW R1 "Internet -> IP cong khai HTTPS (DNAT toi Web)"
probe tester  10.66.10.2  22   BLOCK R8 "Internet -> SSH tren firewall"
probe tester  10.66.10.2  5432 BLOCK R8 "Internet -> PostgreSQL qua IP cong khai"
probe tester  10.66.40.10 5432 BLOCK R8 "Internet -> DB truc tiep"
probe tester  10.66.50.10 22   BLOCK R8 "Internet -> Bastion SSH truc tiep"
probe tester  10.66.30.10 8000 BLOCK R8 "Internet -> App truc tiep, bo qua Web"
probe tester  10.66.30.10 9000 BLOCK R8 "Internet -> API quan tri"

# Từ DMZ (Web)
probe web     10.66.30.10 8000 ALLOW R2 "Web -> App API"
probe web     10.66.40.10 5432 BLOCK R8 "Web -> DB"
probe web     10.66.30.10 9000 BLOCK R8 "Web -> API quan tri"
probe web     10.66.50.10 22   BLOCK R8 "Web -> Bastion"

# Từ vùng App
probe app     10.66.40.10 5432 ALLOW R3 "App -> DB"
probe app     10.66.10.20 8443 ALLOW R4a "App -> cong thanh toan"
probe app     10.66.10.30 9443 ALLOW R4b "App -> API ngan hang (mTLS)"
probe app     10.66.50.10 22   BLOCK R8 "App -> Bastion"

# Từ vùng Data
probe db      10.66.10.30 9443 BLOCK R8 "DB -> Internet (chong lay du lieu ra)"
probe db      10.66.30.10 8000 BLOCK R8 "DB -> App"

# Quản trị viên đã vào VPN
probe admin   10.66.50.10 22   ALLOW R5 "VPN -> Bastion SSH"
probe admin   10.66.30.10 9000 BLOCK R8 "VPN -> API quan tri, khong qua Bastion"
probe admin   10.66.40.10 5432 BLOCK R8 "VPN -> DB truc tiep"

# Từ Bastion
probe bastion 10.66.30.10 9000 ALLOW R6b "Bastion -> API quan tri"
probe bastion 10.66.40.10 5432 BLOCK R8 "Bastion -> DB 5432 (chi mo SSH)"

echo "Tong: $PASS PASS, $FAIL FAIL"
[ "$FAIL" -eq 0 ]
