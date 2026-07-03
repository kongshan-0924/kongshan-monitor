#!/bin/sh
# Outpost 服务端容器入口:首启生成自签证书 + 写配置 + (可选)拉取 agent 二进制,
# 然后以非 root 用户 outpost 运行服务端。管理员由 OUTPOST_ADMIN_USER/PASSWORD 首启引导。
set -eu

ETC=/etc/outpost
VAR=/var/lib/outpost
REPO="Ks-Ht/kongshan-monitor"
PORT="${OP_PORT:-25510}"
HOST="${OP_HOST:-127.0.0.1}"

# 1) 自签证书(内置 TLS;持久化于 /etc/outpost 卷,指纹稳定)
if [ ! -f "$ETC/pki/server.key" ]; then
  echo "[entrypoint] 生成自签证书 (CN=$HOST)"
  mkdir -p "$ETC/pki"; cd "$ETC/pki"; umask 077
  openssl ecparam -genkey -name prime256v1 -out ca.key
  openssl req -x509 -new -key ca.key -sha256 -days 3650 -subj "/CN=Outpost Private CA" -out ca.pem
  case "$HOST" in
    *[!0-9.]*) SAN="DNS:$HOST,IP:127.0.0.1,DNS:localhost" ;;
    *)         SAN="IP:$HOST,IP:127.0.0.1,DNS:localhost" ;;
  esac
  openssl ecparam -genkey -name prime256v1 -out server.key
  openssl req -new -key server.key -subj "/CN=$HOST" -out server.csr
  printf 'subjectAltName=%s\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' "$SAN" > server.ext
  openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 825 -sha256 -extfile server.ext -out server.crt
  cat server.crt ca.pem > server-fullchain.pem
  rm -f server.csr server.ext
  chmod 0600 ca.key server.key; chmod 0644 ca.pem server-fullchain.pem
  cd /
fi

# 2) 配置(首启写入;之后可手动编辑该卷内文件)
if [ ! -f "$ETC/config.toml" ]; then
  echo "[entrypoint] 写入默认配置"
  cat > "$ETC/config.toml" <<EOF
[server]
listen = "0.0.0.0:$PORT"
behind_proxy = false
trusted_proxies = []
public_url = "https://$HOST:$PORT"
[server.tls]
enabled = true
cert_path = "$ETC/pki/server-fullchain.pem"
key_path = "$ETC/pki/server.key"
[security]
# 自签证书的 LAN 部署把 OP_COOKIE_SECURE/OP_HSTS 设为 false:浏览器会拒绝存储
# 不可信源的 __Host-/Secure cookie 导致登录后无会话。服务端仅监听 HTTPS,无明文端点。
cookie_secure = ${OP_COOKIE_SECURE:-true}
hsts = ${OP_HSTS:-true}
[storage]
db_path = "$VAR/outpost.db"
[install]
mode = "pinned_ca"
ca_cert_path = "$ETC/pki/ca.pem"
dist_dir = "$VAR/dist"
[metrics]
ws_max_message_bytes = 262144
ts_skew_secs = 300
[notify]
allow_private_targets = false
EOF
fi

# 3) agent 二进制(用于面板一键装 agent;缺失则尽力从 Release 拉取,失败不阻塞)
mkdir -p "$VAR/dist"
if [ ! -f "$VAR/dist/outpost-agent-x86_64-unknown-linux-musl" ]; then
  echo "[entrypoint] 拉取 agent 二进制(best-effort)"
  BASE="https://github.com/$REPO/releases/latest/download"
  if curl -fsSL --max-time 30 "$BASE/SHA256SUMS" -o "$VAR/dist/.sums" 2>/dev/null; then
    for a in outpost-agent-x86_64-unknown-linux-musl outpost-agent-aarch64-unknown-linux-musl; do
      if curl -fsSL --max-time 120 "$BASE/$a" -o "$VAR/dist/$a" 2>/dev/null; then
        if ( cd "$VAR/dist" && grep " $a\$" .sums | sha256sum -c - >/dev/null 2>&1 ); then
          chmod 0755 "$VAR/dist/$a"
        else
          echo "[entrypoint] 警告:$a 校验失败,已移除"; rm -f "$VAR/dist/$a"
        fi
      fi
    done
    rm -f "$VAR/dist/.sums"
  else
    echo "[entrypoint] 警告:无法拉取 agent(离线?),面板一键装 agent 暂不可用;可手动放入 $VAR/dist"
  fi
fi

# 4) 权限归属并降权运行
chown -R outpost:outpost "$VAR" "$ETC" 2>/dev/null || true
chmod 0640 "$ETC/config.toml" 2>/dev/null || true
echo "[entrypoint] 启动服务端(用户 outpost)"
exec gosu outpost /usr/local/bin/outpost-server
