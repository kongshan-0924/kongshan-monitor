#!/bin/sh
# 生成私有 CA 与服务端证书(IP SAN)。在服务器上以 root 运行:
#   sh gen-pki.sh <公网IP>
# 输出:/etc/outpost/pki/{ca.pem,ca.key,server.key,server-fullchain.pem}
set -eu
IP="${1:?用法: gen-pki.sh <公网IP>}"
DIR=/etc/outpost/pki
mkdir -p "$DIR"
cd "$DIR"
umask 077

if [ ! -f ca.key ]; then
  openssl ecparam -genkey -name prime256v1 -out ca.key
  openssl req -x509 -new -key ca.key -sha256 -days 3650 \
    -subj "/CN=Outpost Private CA" -out ca.pem
  echo "CA 已生成"
fi

openssl ecparam -genkey -name prime256v1 -out server.key
openssl req -new -key server.key -subj "/CN=outpost" -out server.csr
cat > server.ext <<EOF
subjectAltName=IP:$IP,IP:127.0.0.1,DNS:localhost
keyUsage=critical,digitalSignature
extendedKeyUsage=serverAuth
basicConstraints=CA:FALSE
EOF
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -days 825 -sha256 -extfile server.ext -out server.crt
cat server.crt ca.pem > server-fullchain.pem
rm -f server.csr server.ext

# nginx(root)读取私钥;CA 公钥可公开
chmod 0600 ca.key server.key
chmod 0644 ca.pem server.crt server-fullchain.pem

echo "证书已生成:"
openssl x509 -in server.crt -noout -subject -dates -ext subjectAltName
echo "CA 指纹(sha256 of ca.pem 文件):"
sha256sum ca.pem
