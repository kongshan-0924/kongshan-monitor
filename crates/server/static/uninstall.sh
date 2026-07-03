#!/bin/sh
# outpost-agent 卸载脚本:停止服务、移除二进制/配置/token/用户。
set -eu
[ "$(id -u)" = "0" ] || { echo "请以 root 运行" >&2; exit 1; }

systemctl disable --now outpost-agent 2>/dev/null || true
rm -f /etc/systemd/system/outpost-agent.service
systemctl daemon-reload 2>/dev/null || true

rm -f /usr/local/bin/outpost-agent
rm -rf /etc/outpost-agent /var/lib/outpost-agent
if id -u outpost-agent >/dev/null 2>&1; then
  userdel outpost-agent 2>/dev/null || true
fi
echo "✔ outpost-agent 已卸载(如需同时删除面板中的节点,请在面板操作)"
