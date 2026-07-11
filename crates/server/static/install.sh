#!/bin/sh
# outpost-agent 一键安装脚本(POSIX sh,简短可审计,无隐蔽操作)
# 用法: OP_KEY=<一次性密钥> sh install.sh --server https://<host:port> [--ca /path/ca.pem]
#
# 安全设计:
#  - 全程 HTTPS;--ca 提供时 curl 严格用该 CA 校验(不是跳过校验)
#  - 二进制 SHA-256 与服务端 manifest 比对,不符即终止
#  - 创建专用低权限用户 outpost-agent;token 以 0600 写入
#  - 一次性密钥经环境变量 OP_KEY 传入(不出现在本脚本 argv/进程列表);经 stdin 传给 curl
#  - 建议:执行前先阅读本脚本(curl -fsS <server>/install.sh | less)
set -eu

# 密钥优先从环境变量 OP_KEY 读取,随即 unset,避免被子进程(curl 等)继承或出现在 argv。
SERVER="" KEY="${OP_KEY:-}" CA=""
unset OP_KEY 2>/dev/null || true
while [ $# -gt 0 ]; do
  case "$1" in
    --server) SERVER="$2"; shift 2 ;;
    --key)    KEY="$2";    shift 2 ;;   # 兼容旧安装命令;新命令改用 OP_KEY 环境变量
    --ca)     CA="$2";     shift 2 ;;
    *) echo "未知参数: $1" >&2; exit 1 ;;
  esac
done
[ -n "$SERVER" ] && [ -n "$KEY" ] || { echo "用法: install.sh --server https://host:port --key KEY [--ca ca.pem]" >&2; exit 1; }
case "$SERVER" in https://*) ;; *) echo "错误: --server 必须是 https://" >&2; exit 1 ;; esac
[ "$(id -u)" = "0" ] || { echo "请以 root 运行(sudo sh install.sh ...)" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || { echo "需要 curl" >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "需要 sha256sum" >&2; exit 1; }

CURL="curl -fsS --proto =https --max-time 120 --retry 3 --retry-delay 2 --retry-connrefused"
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

echo "[6/7] 安装远程升级助手(规范 6.4 红线破例,详见 SECURITY_AUDIT 附录 F)"
# outpost-agent 进程本身不提权;通过 systemd socket activation 触发一个独立的、不受
# outpost-agent.service 沙箱限制的 oneshot 单元,由该单元以 root 身份完成"下载清单+
# SHA-256 校验+替换二进制+重启服务"。特意不用 sudo——不少精简云主机镜像根本不预装
# sudo(只给 root 直接登录),这个机制只依赖 systemd 本身(本项目已强依赖),不需要额外
# 判断某个外部工具是否存在。
cat > /usr/local/bin/outpost-agent-upgrade-helper <<'HELPER'
#!/bin/sh
# root 专用升级助手:仅由 outpost-agent-upgrade.service 调用,零参数、不接受外部输入。
# 服务器地址/CA 只从本机只读配置读取,agent 低权限账号无法写这份配置(root:outpost-agent 0640)。
set -eu
CFG=/etc/outpost-agent/config.toml
SERVER="$(sed -n 's/^server *= *"\(.*\)"/\1/p' "$CFG" | head -n1)"
CA="$(sed -n 's/^ca_file *= *"\(.*\)"/\1/p' "$CFG" | head -n1)"
[ -n "$SERVER" ] || { echo "配置中未找到 server" >&2; exit 1; }
CURL="curl -fsS --proto =https --max-time 120 --retry 3 --retry-delay 2 --retry-connrefused"
[ -n "$CA" ] && [ -f "$CA" ] && CURL="$CURL --cacert $CA"
case "$(uname -m)" in
  x86_64)  TARGET="x86_64-unknown-linux-musl" ;;
  aarch64) TARGET="aarch64-unknown-linux-musl" ;;
  *) echo "不支持的架构: $(uname -m)" >&2; exit 1 ;;
esac
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT INT TERM
$CURL "$SERVER/api/agent/manifest" -o "$TMP/manifest"
LINE="$(grep "^$TARGET " "$TMP/manifest" || true)"
[ -n "$LINE" ] || { echo "服务端无 $TARGET 产物" >&2; exit 1; }
SHA="$(echo "$LINE" | awk '{print $2}')"
BINPATH="$(echo "$LINE" | awk '{print $3}')"
$CURL "$SERVER$BINPATH" -o "$TMP/outpost-agent"
echo "$SHA  $TMP/outpost-agent" | sha256sum -c - >/dev/null
install -m 0755 "$TMP/outpost-agent" /usr/local/bin/outpost-agent
systemctl restart outpost-agent
HELPER
chown root:root /usr/local/bin/outpost-agent-upgrade-helper
chmod 0700 /usr/local/bin/outpost-agent-upgrade-helper

# 独立 oneshot 单元:不套用 outpost-agent.service 的 ProtectSystem=strict 等沙箱限制,
# 否则即使提权到 root 也写不了 /usr/local/bin(命名空间级只读,与 UID 无关)。
# 用模板单元(@.service)配合下面 socket 的 Accept=yes——助手是个不知道 socket-activation
# 协议的纯 shell 脚本,不会自己 accept() 传入的连接;若用 Accept=no,连接会一直留在 内核
# backlog 里没被取走,systemd 每次 oneshot 跑完都会认为"还有连接等处理"而重新触发同一个
# 连接,实测(2026-07-06 hermes 真机)一次真实点击能在同一秒内触发 5 次,直接打满
# systemd 默认启动频率限制,连 socket 一起被拖成 failed(下一次点击直接 Connection
# refused)。Accept=yes 让 systemd 自己 accept() 每个连接、每连接一个独立服务实例,
# backlog 正确排空,不会被重复触发。
rm -f /etc/systemd/system/outpost-agent-upgrade.service
cat > "/etc/systemd/system/outpost-agent-upgrade@.service" <<'UNIT'
[Unit]
Description=Outpost agent upgrade helper (one-shot, root, sandbox-free by design)
[Service]
Type=oneshot
ExecStart=/usr/local/bin/outpost-agent-upgrade-helper
StandardInput=null
UNIT

# socket-activated:outpost-agent 低权限进程只需要连接这个 socket(哪怕立即断开),
# systemd(本身已是 root)就会自动拉起上面的 oneshot 单元。socket 文件权限限定
# root:outpost-agent 0660,只有 agent 自己的运行账号能连接。不依赖 sudo/pkexec。
cat > /etc/systemd/system/outpost-agent-upgrade.socket <<'SOCK'
[Unit]
Description=Outpost agent upgrade trigger socket
[Socket]
ListenStream=/run/outpost-agent-upgrade.sock
SocketMode=0660
SocketUser=root
SocketGroup=outpost-agent
Accept=yes
[Install]
WantedBy=sockets.target
SOCK
systemctl daemon-reload
systemctl enable --now outpost-agent-upgrade.socket >/dev/null 2>&1 || \
  echo "警告: 升级触发 socket 启动失败,远程升级功能将不可用(不影响正常监控)" >&2

echo "[7/7] 安装并启动 systemd 服务(加固)"
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
# 远程升级(规范 6.4 红线破例,见 SECURITY_AUDIT 附录 F)靠连接 socket 触发,不经
# sudo/setuid,所以 NoNewPrivileges 可以照常开启,不影响升级功能。
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
# AF_UNIX 供两个可选的只读探测使用本地 UNIX socket:
#  - watch_services:systemctl is-active 经 D-Bus;
#  - docker_stats:直连 /var/run/docker.sock(需 agent 运行账号在 docker 组,等效 root,
#    默认关闭,请自行评估后再开启,见 README)。
# 均只读查询、不执行控制命令。
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
AmbientCapabilities=
SystemCallFilter=@system-service
SystemCallArchitectures=native
UMask=0077

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable outpost-agent >/dev/null 2>&1
# 用 restart 而非 start/enable --now:本脚本也用于"重置密钥后重新执行"的升级/重装场景,
# 此时服务往往已在运行,--now 对已激活单元是空操作,不会让进程重新加载新写入的
# token/二进制,导致旧进程继续用已失效的旧 token 连接、收到 401 而无法上线。
# restart 对未运行的单元等价于 start,新装场景行为不变。
systemctl restart outpost-agent

sleep 2
if systemctl is-active --quiet outpost-agent; then
  echo "✔ outpost-agent 已启动,面板将在数秒内显示该节点在线"
else
  echo "✘ 服务未能启动,请查看: journalctl -u outpost-agent -n 50" >&2
  exit 1
fi
