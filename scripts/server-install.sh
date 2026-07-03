#!/bin/sh
# ============================================================================
# Outpost 哨站 — 服务端一键安装脚本(高位端口 + 自签 TLS,不占用 80/443)
#
#   curl -fsSL https://github.com/Ks-Ht/kongshan-monitor/releases/latest/download/server-install.sh | sh
#
# 默认在 18080 端口起服务,直接用 https://<IP>:18080 访问(自签证书,浏览器首次会提示
# 不受信任,点继续即可 —— 流量仍是加密的)。不碰 80/443,方便与已有服务共存。
#
# 想用域名 + 浏览器信任的证书:装好后在前面加个 nginx 反代即可(见 README「加域名」),
#   proxy_pass https://127.0.0.1:18080;   # proxy_ssl_verify off;
#
# 免交互(自动化)可用环境变量:OP_PORT OP_HOST OP_ADMIN_USER OP_ADMIN_PASS OP_VERSION
# ============================================================================
set -eu

REPO="Ks-Ht/kongshan-monitor"
VERSION="${OP_VERSION:-latest}"
PREFIX="/usr/local/bin"
ETC="/etc/outpost"
VAR="/var/lib/outpost"

info() { printf '\033[32m==>\033[0m %s\n' "$1"; }
err()  { printf '\033[31m错误:\033[0m %s\n' "$1" >&2; exit 1; }

[ "$(id -u)" = "0" ] || err "请以 root 运行(sudo sh server-install.sh)"
for c in curl sha256sum openssl; do command -v "$c" >/dev/null 2>&1 || err "缺少依赖:$c"; done
command -v systemctl >/dev/null 2>&1 || err "需要 systemd(systemctl)"

case "$(uname -m)" in
  x86_64)  ARCH="x86_64-unknown-linux-musl" ;;
  aarch64) ARCH="aarch64-unknown-linux-musl" ;;
  *) err "暂不支持的架构:$(uname -m)" ;;
esac
if [ "$VERSION" = "latest" ]; then
  BASE="https://github.com/$REPO/releases/latest/download"
else
  BASE="https://github.com/$REPO/releases/download/$VERSION"
fi

# --- 交互输入(优先环境变量;从 /dev/tty 读,兼容 curl|sh)---
TTY=/dev/tty
ask() {
  eval "cur=\${$1:-}"; [ -n "${cur:-}" ] && { eval "$1=\"$cur\""; return; }
  printf '%s [%s]: ' "$2" "$3" > "$TTY"; read ans < "$TTY" || ans=""
  [ -n "$ans" ] || ans="$3"; eval "$1=\"\$ans\""
}
ask_secret() {
  eval "cur=\${$1:-}"; [ -n "${cur:-}" ] && { eval "$1=\"$cur\""; return; }
  printf '%s: ' "$2" > "$TTY"; stty -echo < "$TTY" 2>/dev/null || true
  read ans < "$TTY" || ans=""; stty echo < "$TTY" 2>/dev/null || true
  printf '\n' > "$TTY"; eval "$1=\"\$ans\""
}

info "Outpost 哨站 服务端安装(架构 $ARCH,版本 $VERSION)"
DETECT_IP="$(curl -fsS --max-time 5 https://api.ipify.org 2>/dev/null || echo '')"
ask OP_PORT "服务端口(避开 80/443)" "18080"
ask OP_HOST "访问地址(公网 IP 或主机名,用于证书与访问链接)" "${DETECT_IP:-127.0.0.1}"
ask OP_ADMIN_USER "管理员用户名(3~32 位)" "admin"
if [ -z "${OP_ADMIN_PASS:-}" ]; then
  ask_secret OP_ADMIN_PASS "管理员密码(≥10 位,含字母和数字)"
  ask_secret OP_ADMIN_PASS2 "再次输入密码"
  [ "$OP_ADMIN_PASS" = "${OP_ADMIN_PASS2:-}" ] || err "两次密码不一致"
fi
case "$OP_PORT" in ''|*[!0-9]*) err "端口非法" ;; esac
[ -n "${OP_HOST:-}" ] || err "访问地址不能为空"
[ -n "$OP_ADMIN_PASS" ] || err "密码不能为空"
if [ "$OP_PORT" = "443" ]; then PUBURL="https://$OP_HOST"; else PUBURL="https://$OP_HOST:$OP_PORT"; fi

# --- 下载并校验二进制 ---
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT INT TERM
info "下载成品与校验和"
curl -fsSL --proto '=https' "$BASE/SHA256SUMS" -o "$TMP/SHA256SUMS"
dl() {
  curl -fsSL --proto '=https' "$BASE/$1" -o "$TMP/$1"
  grep " $1\$" "$TMP/SHA256SUMS" > "$TMP/sum" || err "$1 无校验和记录"
  ( cd "$TMP" && sha256sum -c sum >/dev/null ) || err "$1 SHA-256 校验失败"
}
dl "outpost-server-$ARCH"
dl "outpost-agent-x86_64-unknown-linux-musl"
dl "outpost-agent-aarch64-unknown-linux-musl"

# --- 用户与目录 ---
info "创建用户与目录"
id -u outpost >/dev/null 2>&1 || useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin outpost
mkdir -p "$ETC/pki" "$VAR/dist"
install -m 0755 "$TMP/outpost-server-$ARCH" "$PREFIX/outpost-server"
install -m 0755 "$TMP/outpost-agent-x86_64-unknown-linux-musl" "$VAR/dist/outpost-agent-x86_64-unknown-linux-musl"
install -m 0755 "$TMP/outpost-agent-aarch64-unknown-linux-musl" "$VAR/dist/outpost-agent-aarch64-unknown-linux-musl"

# --- 自签证书 ---
info "生成自签证书"
cd "$ETC/pki"; umask 077
[ -f ca.key ] || { openssl ecparam -genkey -name prime256v1 -out ca.key
  openssl req -x509 -new -key ca.key -sha256 -days 3650 -subj "/CN=Outpost Private CA" -out ca.pem; }
case "$OP_HOST" in *[!0-9.]*) HOSTSAN="DNS:$OP_HOST" ;; *) HOSTSAN="IP:$OP_HOST" ;; esac
openssl ecparam -genkey -name prime256v1 -out server.key
openssl req -new -key server.key -subj "/CN=$OP_HOST" -out server.csr
printf 'subjectAltName=%s,IP:127.0.0.1,DNS:localhost\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' "$HOSTSAN" > server.ext
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 825 -sha256 -extfile server.ext -out server.crt
cat server.crt ca.pem > server-fullchain.pem; rm -f server.csr server.ext
chmod 0600 ca.key server.key; chmod 0644 ca.pem server.crt server-fullchain.pem
cd - >/dev/null

# --- 配置 ---
info "写入配置"
cat > "$ETC/config.toml" <<EOF
[server]
listen = "0.0.0.0:$OP_PORT"
behind_proxy = false
trusted_proxies = []
public_url = "$PUBURL"

[server.tls]
enabled = true
cert_path = "$ETC/pki/server-fullchain.pem"
key_path = "$ETC/pki/server.key"

[security]
cookie_secure = true
session_ttl_hours = 24
hsts = true

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
chown -R root:outpost "$ETC"
chmod 0640 "$ETC/config.toml"
chmod 0640 "$ETC/pki/server.key"   # 服务以 outpost 用户运行,需读服务端私钥
chmod 0600 "$ETC/pki/ca.key"       # CA 私钥仅 root 可读

# --- 创建管理员(密码经环境变量,不入 argv)---
info "创建管理员账户"
OUTPOST_CONFIG="$ETC/config.toml" OUTPOST_ADMIN_PASSWORD="$OP_ADMIN_PASS" \
  "$PREFIX/outpost-server" admin-create --username "$OP_ADMIN_USER" || err "创建管理员失败"
chown -R outpost:outpost "$VAR"

# --- systemd(低端口才授予 net_bind)---
if [ "$OP_PORT" -lt 1024 ]; then CAPS="AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE"; else CAPS="CapabilityBoundingSet="; fi
cat > /etc/systemd/system/outpost-server.service <<EOF
[Unit]
Description=Outpost monitoring dashboard server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=outpost
Group=outpost
Environment=OUTPOST_CONFIG=$ETC/config.toml
ExecStart=$PREFIX/outpost-server
Restart=always
RestartSec=5
MemoryMax=256M
TasksMax=64
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$VAR
ReadOnlyPaths=$ETC
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
$CAPS
SystemCallFilter=@system-service
SystemCallArchitectures=native
UMask=0077

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now outpost-server >/dev/null 2>&1

sleep 2
echo
if systemctl is-active --quiet outpost-server; then
  info "安装完成 ✔"
  echo "  面板地址 : $PUBURL"
  echo "  管理员   : $OP_ADMIN_USER"
  echo "  证书     : 自签(浏览器首次提示不受信任,点继续访问即可;流量已加密)"
  echo "  CA 指纹  : $(sha256sum "$ETC/pki/ca.pem" | awk '{print $1}')"
  echo
  echo "  · 登录后在「总览 → 添加节点」复制命令即可给其他服务器装 agent。"
  echo "  · 想用域名 + 受信任证书:在本机加 nginx 反代 $PUBURL(见 README「加域名」)。"
else
  err "服务未能启动,请查看:journalctl -u outpost-server -n 50"
fi
