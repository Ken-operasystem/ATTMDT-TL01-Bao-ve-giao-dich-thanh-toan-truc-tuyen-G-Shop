#!/bin/sh
# Sinh toàn bộ PKI và secret cho lab G-Shop.
#  - CA công khai 2 tầng: GS Lab Root CA -> GS Lab Issuing CA -> chứng thư website
#  - CA riêng của ngân hàng: chứng thư server API ngân hàng và chứng thư client mTLS
#  - Khóa SSH của quản trị viên và các secret ứng dụng
# Chạy trong container (xem run.sh). Kết quả nằm ở pki/out (không commit).
set -eu

OUT=${1:-/work/pki/out}
if [ -f "$OUT/.done" ]; then
    echo "PKI đã có tại $OUT, xóa thư mục này nếu muốn sinh lại."
    exit 0
fi
mkdir -p "$OUT"
cd "$OUT"
umask 077
export SAN="DNS:unused.invalid"

# Bước 1: Hàm tạo thư mục CA và file cấu hình cho lệnh openssl ca
make_ca_dir() {
    # $1 = thư mục CA, $2 = URL CRL, $3 = URL OCSP (có thể rỗng)
    mkdir -p "$1/newcerts"
    : > "$1/index.txt"
    echo "unique_subject = no" > "$1/index.txt.attr"
    openssl rand -hex 8 > "$1/serial"
    echo 1000 > "$1/crlnumber"
    aia=""
    if [ -n "$3" ]; then
        aia="authorityInfoAccess = OCSP;URI:$3"
    fi
    cat > "$1/ca.cnf" <<EOF
[ ca ]
default_ca = this_ca

[ this_ca ]
dir              = $OUT/$1
database         = \$dir/index.txt
serial           = \$dir/serial
crlnumber        = \$dir/crlnumber
new_certs_dir    = \$dir/newcerts
certificate      = \$dir/ca.crt
private_key      = \$dir/ca.key
default_md       = sha256
default_crl_days = 1
policy           = policy_any
copy_extensions  = none
unique_subject   = no

[ policy_any ]
organizationName = optional
commonName       = supplied

[ v3_intermediate ]
basicConstraints       = critical, CA:true, pathlen:0
keyUsage               = critical, keyCertSign, cRLSign
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always
crlDistributionPoints  = URI:$2

[ server_leaf ]
basicConstraints       = critical, CA:false
keyUsage               = critical, digitalSignature
extendedKeyUsage       = serverAuth
subjectAltName         = \${ENV::SAN}
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid
crlDistributionPoints  = URI:$2
$aia

[ client_leaf ]
basicConstraints       = critical, CA:false
keyUsage               = critical, digitalSignature
extendedKeyUsage       = clientAuth
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid
crlDistributionPoints  = URI:$2

[ ocsp_signer ]
basicConstraints       = critical, CA:false
keyUsage               = critical, digitalSignature
extendedKeyUsage       = critical, OCSPSigning
EOF
}

# Bước 2: Hàm tạo khóa ECDSA và CSR. Khóa bí mật không rời thư mục của bên sở hữu.
make_key_csr() {
    # $1 = đường cong, $2 = file khóa, $3 = file CSR, $4 = subject
    openssl req -new -newkey ec -pkeyopt "ec_paramgen_curve:$1" -nodes \
        -keyout "$2" -out "$3" -subj "$4" 2>/dev/null
}

# Bước 3: Hàm để CA ký CSR
sign_csr() {
    # $1 = thư mục CA, $2 = section extension, $3 = số ngày, $4 = CSR, $5 = cert
    openssl ca -batch -notext -config "$1/ca.cnf" -extensions "$2" \
        -days "$3" -in "$4" -out "$5" 2>/dev/null
}

echo "[1/6] GS Lab Root CA (ECDSA P-384, 10 năm)"
make_ca_dir public-ca/root http://pki.gshop.test/root.crl ""
openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-384 -nodes \
    -keyout public-ca/root/ca.key -out public-ca/root/ca.crt -days 3650 \
    -subj "/O=GS Lab Trust/CN=GS Lab Root CA" \
    -addext "basicConstraints=critical,CA:true" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" 2>/dev/null

echo "[2/6] GS Lab Issuing CA (Intermediate, pathlen:0, 5 năm)"
make_ca_dir public-ca/issuing http://pki.gshop.test/issuing.crl http://ocsp.gshop.test
make_key_csr P-384 public-ca/issuing/ca.key public-ca/issuing/ca.csr \
    "/O=GS Lab Trust/CN=GS Lab Issuing CA"
sign_csr public-ca/root v3_intermediate 1825 \
    public-ca/issuing/ca.csr public-ca/issuing/ca.crt

echo "[3/6] Chứng thư website www.gshop.test (20 ngày, mô phỏng sắp hết hạn)"
mkdir -p web
make_key_csr P-256 web/www.key web/www.csr "/O=G-Shop/CN=www.gshop.test"
SAN="DNS:www.gshop.test,DNS:gshop.test" sign_csr public-ca/issuing server_leaf 20 \
    web/www.csr web/www.crt
cat web/www.crt public-ca/issuing/ca.crt > web/fullchain.pem

# Chứng thư cũ bị lộ khóa, dùng để kiểm thử thu hồi
make_key_csr P-256 web/www-old.key web/www-old.csr "/O=G-Shop/CN=www.gshop.test"
SAN="DNS:www.gshop.test" sign_csr public-ca/issuing server_leaf 90 \
    web/www-old.csr web/www-old.crt
openssl ca -config public-ca/issuing/ca.cnf -revoke web/www-old.crt \
    -crl_reason keyCompromise 2>/dev/null

# Chứng thư TLS của cổng thanh toán (bên ngoài, cũng do CA công khai cấp)
mkdir -p gateway-tls
make_key_csr P-256 gateway-tls/pay.key gateway-tls/pay.csr \
    "/O=Lab Payment Gateway/CN=pay.gateway.test"
SAN="DNS:pay.gateway.test" sign_csr public-ca/issuing server_leaf 90 \
    gateway-tls/pay.csr gateway-tls/pay.crt
cat gateway-tls/pay.crt public-ca/issuing/ca.crt > gateway-tls/fullchain.pem

# Chứng thư ký phản hồi OCSP của Issuing CA
make_key_csr P-256 public-ca/issuing/ocsp.key public-ca/issuing/ocsp.csr \
    "/O=GS Lab Trust/CN=GS Lab Issuing CA OCSP Responder"
sign_csr public-ca/issuing ocsp_signer 90 \
    public-ca/issuing/ocsp.csr public-ca/issuing/ocsp.crt

echo "[4/6] CRL của Root CA và Issuing CA"
openssl ca -gencrl -config public-ca/root/ca.cnf -out public-ca/root/ca.crl.pem 2>/dev/null
openssl ca -gencrl -config public-ca/issuing/ca.cnf -out public-ca/issuing/ca.crl.pem 2>/dev/null

echo "[5/6] Bank Lab mTLS CA, server api.bank.test, client gshop-app và pay-gateway"
make_ca_dir bank-ca http://pki.bank.test/bank-ca.crl ""
openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout bank-ca/ca.key -out bank-ca/ca.crt -days 3650 \
    -subj "/O=Lab Bank/CN=Bank Lab mTLS CA" \
    -addext "basicConstraints=critical,CA:true,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" \
    -addext "subjectKeyIdentifier=hash" 2>/dev/null

mkdir -p bank gshop-client gateway-client
make_key_csr P-256 bank/api.key bank/api.csr "/O=Lab Bank/CN=api.bank.test"
SAN="DNS:api.bank.test" sign_csr bank-ca server_leaf 365 bank/api.csr bank/api.crt

# G-Shop tự tạo khóa và gửi CSR cho ngân hàng; ngân hàng chỉ trả lại chứng thư
make_key_csr P-256 gshop-client/gshop-app.key gshop-client/gshop-app.csr \
    "/O=G-Shop/CN=gshop-app"
sign_csr bank-ca client_leaf 365 gshop-client/gshop-app.csr gshop-client/gshop-app.crt

make_key_csr P-256 gateway-client/gw.key gateway-client/gw.csr \
    "/O=Lab Payment Gateway/CN=pay-gateway"
sign_csr bank-ca client_leaf 365 gateway-client/gw.csr gateway-client/gw.crt

# Chứng thư client cũ của G-Shop đã bị thay thế và thu hồi
make_key_csr P-256 gshop-client/gshop-app-old.key gshop-client/gshop-app-old.csr \
    "/O=G-Shop/CN=gshop-app"
sign_csr bank-ca client_leaf 365 gshop-client/gshop-app-old.csr gshop-client/gshop-app-old.crt
openssl ca -config bank-ca/ca.cnf -revoke gshop-client/gshop-app-old.crt \
    -crl_reason superseded 2>/dev/null
openssl ca -gencrl -config bank-ca/ca.cnf -out bank-ca/ca.crl.pem 2>/dev/null

# Thư mục trust: chỉ chứa chứng thư CA và CRL (công khai)
mkdir -p trust
cp public-ca/root/ca.crt trust/public-root.crt
cp public-ca/issuing/ca.crt trust/public-issuing.crt
cp public-ca/root/ca.crl.pem trust/root.crl.pem
cp public-ca/issuing/ca.crl.pem trust/issuing.crl.pem
cp bank-ca/ca.crt trust/bank-ca.crt
cp bank-ca/ca.crl.pem trust/bank-ca.crl.pem

echo "[6/6] Khóa SSH quản trị và secret ứng dụng"
# ssh/admin: khóa của quản trị viên; ssh/bastion: host key + khóa công khai được phép
mkdir -p ssh/admin ssh/bastion secrets
ssh-keygen -q -t ed25519 -N "" -C "ops@vpn-admin" -f ssh/admin/id_ed25519
cp ssh/admin/id_ed25519.pub ssh/bastion/authorized_ops.pub
ssh-keygen -q -t ed25519 -N "" -C "bastion" -f ssh/bastion/host_ed25519
echo "10.66.50.10 $(cut -d' ' -f1,2 ssh/bastion/host_ed25519.pub)" > ssh/admin/known_hosts
openssl rand -hex 24 > secrets/db_owner_password
openssl rand -hex 24 > secrets/db_app_password
openssl rand -hex 32 > secrets/webhook_secret
openssl rand -hex 32 > secrets/gateway_api_key
openssl rand -base64 32 > secrets/data_key
openssl rand -hex 32 > secrets/admin_token

# Quyền: thư mục gốc 700 (chỉ chủ máy), thư mục con 755 để service trong
# container đọc được file được mount; khóa CA giữ 600.
chmod 700 "$OUT"
find "$OUT" -mindepth 1 -type d -exec chmod 755 {} +
find "$OUT" -type f -exec chmod 644 {} +
chmod 600 public-ca/root/ca.key public-ca/issuing/ca.key bank-ca/ca.key
touch "$OUT/.done"
if [ -n "${HOST_UID:-}" ]; then
    chown -R "$HOST_UID:${HOST_GID:-$HOST_UID}" "$OUT"
fi
echo "Xong: $OUT"
