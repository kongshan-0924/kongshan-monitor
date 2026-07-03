#!/bin/sh
# outpost-agent 一键安装脚本(POSIX sh,简短可审计,无隐蔽操作)
# 用法: sh install.sh --server https://<host:port> --key <一次性密钥> [--ca /path/ca.pem]
#
# 安全设计:
#  - 全程 HTTPS;--ca 提供时 curl 严格用该 CA 校验(不是跳过校验)
#  - 二进制 SHA-256 与服务端 manifest 比对,不符即终止
#  - 创建专用低权限用户 outpost-agent;token 以 0600 写入
#  - 一次性密钥经 stdin 传给 curl,不出现在子进程 argv
#  - 建议:执行前先阅读本脚本(curl -fsS <server>/install.sh | less)
set -eu

SERVER="" KEY="" CA=""
while [ $# -gt 0 ]; do
  case "$1" in
    --server) SERVER="$2"; shift 2 ;;
    --key)    KEY="$2";    shift 2 ;;
    --ca)     CA="$2";     shift 2 ;;
    *) echo "未知参数: $1" >&2; exit 1 ;;
  esac
done
[ -n "$SERVER" ] && [ -n "$KEY" ] || { echo "用法: install.sh --server https://host:port --key KEY [--ca ca.pem]" >&2; exit 1; }
case "$SERVER" in https://*) ;; *) echo "错误: --server 必须是 https://" >&2; exit 1 ;; esac
[ "$(id -u)" = "0" ] || { echo "请以 root 运行(sudo sh install.sh ...)" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || { echo "需要 curl" >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "需要 sha256sum" >&2; exit 1; }

CURL="curl -fsS --proto =https --max-time 120"
[ -n "$CA" ] && CURL="$CURL --cacert $CA"

case "$(uname -m)" in
  x86_64)  TARGET="x86_64-unknown-linux-musl" ;;
  aarch64) TARGET="aarch64-unknown-linux-musl" ;;
  *) echo "暂不支持的架构: $(uname -m)" >&2; exit 1 ;;
esac

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

echo "[1/6] 获取产物清单并核对架构 ${TARGET}"
$CURL "$SERVER/api/agent/manifest" -o "$TMP/manifest"
LINE="$(grep "^$TARGET " "$TMP/manifest" || true)"
[ -n "$LINE" ] || { echo "服务端没有 ${TARGET} 的构建产物" >&2; exit 1; }
SHA="$(echo "$LINE" | awk '{print $2}')"
BINPATH="$(echo "$LINE" | awk '{print $3}')"

echo "[2/6] 下载 agent 二进制并校验 SHA-256"
$CURL "$SERVER$BINPATH" -o "$TMP/outpost-agent"
echo "$SHA  $TMP/outpost-agent" | sha256sum -c - >/dev/null
install -m 0755 "$TMP/outpost-agent" /usr/local/bin/outpost-agent

echo "[3/6] 创建专用用户与目录"
if ! id -u outpost-agent >/dev/null 2>&1; then
  NOLOGIN="$(command -v nologin || echo /usr/sbin/nologin)"
  useradd --system --no-create-home --home-dir /nonexistent --shell "$NOLOGIN" outpost-agent
fi
mkdir -p /etc/outpost-agent /var/lib/outpost-agent
chown outpost-agent:outpost-agent /var/lib/outpost-agent
chmod 0700 /var/lib/outpost-agent
if [ -n "$CA" ]; then
  install -m 0644 "$CA" /etc/outpost-agent/ca.pem
fi

echo "[4/6] 写入配置"
umask 077
{
  echo "server = \"$SERVER\""
  [ -n "$CA" ] && echo "ca_file = \"/etc/outpost-agent/ca.pem\""
  echo "token_file = \"/var/lib/outpost-agent/token\""
} > /etc/outpost-agent/config.toml
chown root:outpost-agent /etc/outpost-agent/config.toml
chmod 0640 /etc/outpost-agent/config.toml

echo "[5/6] 注册节点(一次性密钥换 token)"
# 密钥经 stdin 传输,避免出现在 ps/argv;token 只写入 0600 文件,不回显
RESP="$(printf 'key=%s' "$KEY" | $CURL -X POST --data-binary @- "$SERVER/api/agent/register")" || {
  echo "注册失败:密钥无效/过期,或服务端不可达" >&2; exit 1;
}
case "$RESP" in
  token=*) ;;
  *) echo "注册响应异常" >&2; exit 1 ;;
esac
printf '%s\n' "${RESP#token=}" | head -c 128 > /var/lib/outpost-agent/token
chown outpost-agent:outpost-agent /var/lib/outpost-agent/token
chmod 0600 /var/lib/outpost-agent/token

echo "[6/6] 安装并启动 systemd 服务(加固)"
cat > /etc/systemd/system/outpost-agent.service <<'UNIT'
[Unit]
Description=Outpost monitoring agent (read-only collector)
Documentation=https://github.com/local/outpost
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=outpost-agent
Group=outpost-agent
ExecStart=/usr/local/bin/outpost-agent
Restart=always
RestartSec=5

# --- 资源自限制 ---
MemoryMax=64M
TasksMax=16
CPUQuota=30%

# --- 安全加固 ---
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=
ReadOnlyPaths=/etc/outpost-agent /var/lib/outpost-agent
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictAddressFamilies=AF_INET AF_INET6
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallFilter=@system-service
SystemCallArchitectures=native
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable --now outpost-agent >/dev/null 2>&1

sleep 2
if systemctl is-active --quiet outpost-agent; then
  echo "✔ outpost-agent 已启动,面板将在数秒内显示该节点在线"
else
  echo "✘ 服务未能启动,请查看: journalctl -u outpost-agent -n 50" >&2
  exit 1
fi
