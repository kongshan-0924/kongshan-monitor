#!/bin/sh
# outpost-agent 升级脚本:下载最新二进制(SHA-256 校验)后原地替换并重启。
# 不改动配置、不重新注册。用法:sh upgrade.sh --server https://host:port [--ca ca.pem]
set -eu
SERVER="" CA=""
while [ $# -gt 0 ]; do
  case "$1" in
    --server) SERVER="$2"; shift 2 ;;
    --ca)     CA="$2";     shift 2 ;;
    *) echo "未知参数: $1" >&2; exit 1 ;;
  esac
done
[ -n "$SERVER" ] || { echo "用法: upgrade.sh --server https://host:port [--ca ca.pem]" >&2; exit 1; }
case "$SERVER" in https://*) ;; *) echo "错误: --server 必须是 https://" >&2; exit 1 ;; esac
[ "$(id -u)" = "0" ] || { echo "请以 root 运行" >&2; exit 1; }
command -v curl >/dev/null && command -v sha256sum >/dev/null || { echo "需要 curl 与 sha256sum" >&2; exit 1; }

CURL="curl -fsS --proto =https --max-time 120"
[ -n "$CA" ] && CURL="$CURL --cacert $CA"
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

OLD="$(/usr/local/bin/outpost-agent --version 2>/dev/null || echo unknown)"
install -m 0755 "$TMP/outpost-agent" /usr/local/bin/outpost-agent
systemctl restart outpost-agent
sleep 2
if systemctl is-active --quiet outpost-agent; then
  echo "✔ 升级完成:$OLD → $(/usr/local/bin/outpost-agent --version 2>/dev/null)"
else
  echo "✘ 升级后服务未启动,请查看 journalctl -u outpost-agent" >&2; exit 1
fi
