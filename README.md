# Outpost 哨站 · 私有化服务器探针 / 监控系统

安全优先、极致轻量的自托管服务器监控。Rust + axum + SQLite + rustls,单二进制部署;
agent 空闲内存 ~2MB,服务端 ~6MB,可在 1 核 512MB 机器流畅运行。

- **Dashboard(服务端)**:接收上报、存储、Web 管理界面(总览 / 节点详情 / 设置)。
- **Agent(探针)**:被监控机上的只读采集器,经 WSS 主动上报。**只采集、不接受远程命令。**

> 设计原则:安全 > 功能 > 性能 > 开发速度。默认拒绝、最小权限、纵深防御。
> 威胁模型与逐条安全说明见 [SECURITY.md](SECURITY.md) 与 [SECURITY_AUDIT.md](SECURITY_AUDIT.md)。

---

## 架构

```
浏览器 ──HTTPS/WSS──► nginx(TLS 25510)──► outpost-server(127.0.0.1:25511)──► SQLite
                                                     ▲
   被监控机 outpost-agent ──── WSS(每 agent 唯一 token)────┘
```

- 服务端默认只监听 `127.0.0.1`,对外由 nginx 终止 TLS(或启用内置 rustls)。
- Agent 与服务端全程 WSS;agent 严格校验服务端证书(支持私有 CA,**从不跳过校验**)。
- 服务端 → agent 下行仅一个白名单枚举 `UpdateConfig{report_interval_secs}`,**无法承载命令**。

## 技术栈

| 层 | 选型 |
|---|---|
| 语言/运行时 | Rust stable · Tokio |
| Web | axum 0.8(含 WS) |
| DB | SQLite via sqlx(`query!` 编译期校验) |
| TLS | rustls(ring,纯 Rust) |
| 采集 | 直接读 `/proc` `/sys` + statvfs(rustix) |
| 密码哈希 | argon2id |
| 前端 | 原生 JS + 自写 canvas 图表(零 npm 依赖),内嵌单二进制 |

## 从源码构建

前置:Rust stable、`zig` + `cargo-zigbuild`(交叉编译 musl)、`sqlite3`。

```bash
sh scripts/dev-db.sh          # 生成 sqlx 编译期校验用库
cargo test --workspace        # 单元 + 恶意输入测试
cargo clippy --workspace --all-targets -- -D warnings
cargo audit && cargo deny check
sh scripts/build-release.sh   # 产出 dist/(x86_64 + aarch64 musl 全静态 + SHA256SUMS)
```

## 部署(nginx + TLS,推荐)

在服务器以 root:

```bash
# 1. 用户与目录
useradd --system --no-create-home --shell /usr/sbin/nologin outpost
mkdir -p /etc/outpost /var/lib/outpost/dist
install -m0755 dist/outpost-server-x86_64-unknown-linux-musl /usr/local/bin/outpost-server
cp dist/outpost-agent-*-musl /var/lib/outpost/dist/
chown -R outpost:outpost /var/lib/outpost

# 2. 证书(私有 CA + IP SAN);记下打印的 CA 指纹
sh deploy/gen-pki.sh <你的公网IP>

# 3. 配置:复制 config.example.toml → /etc/outpost/config.toml,改 public_url
#    权限 0640 root:outpost

# 4. systemd + nginx
install -m0644 deploy/server.service /etc/systemd/system/outpost-server.service
install -m0644 deploy/nginx-outpost.conf /etc/nginx/sites-available/outpost
ln -sf /etc/nginx/sites-available/outpost /etc/nginx/sites-enabled/outpost
nginx -t && systemctl reload nginx
systemctl daemon-reload && systemctl enable --now outpost-server
```

浏览器打开 `https://<IP>:25510/setup` 创建管理员(无内置默认账号)。
私有 CA 场景浏览器会提示证书不受信任 —— 属预期(自签),可导入 `deploy 生成的 ca.pem` 消除提示。

## 添加节点(一键安装)

面板「添加节点」→ 复制命令 → 目标机 root 执行。命令会:
下载并核对 CA 指纹 → 经 TLS 取安装脚本 → 下载 agent 并校验 **SHA-256** →
建专用用户 → 一次性密钥换长期 token(写入 `0600`)→ 装 systemd 加固服务。

一次性注册密钥 **30 分钟有效、用后即焚**。

> `curl | sh` 需要你信任服务端。如需人工审阅,可先 `curl https://<IP>:25510/install.sh`
> 查看脚本内容(简短、无隐蔽操作)再执行。卸载:`sh /var/lib/.../uninstall.sh` 或面板删除节点。

## 采集指标

CPU(总/负载/温度)、内存/Swap、磁盘各挂载点用量+读写速率+IOPS、网络各网卡收发+速率、
TCP 连接数、uptime、进程数、主机名/OS/内核/架构。单项采集失败降级为缺省,不影响整次上报。

**进程监控**(可选):在 agent 配置 `/etc/outpost-agent/config.toml` 加一行即可探测指定进程存活/CPU/内存(进程名为 agent 本地配置,服务端无法下发):

```toml
watch_processes = ["nginx", "sshd", "postgres"]   # 最多 12 个
```

## 功能一览

- **告警闭环**:阈值/离线规则(CPU/内存/磁盘/Swap/负载/CPU温度/TCP连接数/离线)→ 触发/恢复消抖状态机 → 通知。
- **通知渠道**:Webhook(飞书/钉钉/企业微信/Slack 自动适配)、Telegram、Bark;出站 SSRF 加固、去重节流;登录新设备通知。
- **数据出口**:只读 API Token、Prometheus 兼容 `/metrics`、历史 CSV/JSON 导出。
- **账号安全**:TOTP 两步验证(+一次性恢复码)、会话/设备管理(远程踢出)、SQLite 一致性备份。
- **规模化**:总览搜索/过滤/排序/告警高亮、批量操作、agent 版本漂移看板、一键升级命令。
- **其他**:多节点对比图、节点备注、审计日志导出、公开只读状态页(默认关闭、脱敏)。

### Prometheus 接入

设置页新建只读 API Token,然后:

```yaml
scrape_configs:
  - job_name: outpost
    scheme: https
    authorization: { credentials: "opk_你的token" }
    static_configs: [{ targets: ["你的IP:25510"] }]
```

### Agent 升级

设置页「Agent 升级」复制命令到目标机 root 执行(下载新二进制 → SHA-256 校验 → 原地替换 → 重启,不改配置)。

### 数据恢复

备份为 SQLite 一致性快照。恢复:`systemctl stop outpost-server` → 用备份替换 `/var/lib/outpost/outpost.db` → `systemctl start outpost-server`。

## 配置

见 [config.example.toml](config.example.toml)(带注释)。所有项可用 `OUTPOST_` 环境变量覆盖。

## 许可

MIT。
