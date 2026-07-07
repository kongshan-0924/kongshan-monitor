# SECURITY_AUDIT — 空山Outpost 最终安全审计报告

日期:2026-07-03 · 版本:0.1.0 · 审计范围:server / agent / common / frontend / 安装脚本 / 部署

结论:**未发现高危未修复项。** 全部红线(第 13 节)零违反。已在真实服务器(cc)完成
部署与恶意输入实测,详见 §4。

---

## 1. 威胁建模(攻击面 × 缓解)

见 [SECURITY.md](SECURITY.md#威胁模型)。四个入口逐一分析:

1. **公网 nginx 入口**:TLS 终止;限速(令牌桶,按 IP×端点类别)+ 登录退避;
   会话鉴权由类型系统强制(`SessionUser` 提取器,漏加即编译不过);CSP+Origin/CSRF 校验。
2. **Agent 上报入口(/ws/agent)**:升级前完成 Bearer token 校验(常量时间);
   严格反序列化 + 数值越界拒绝 + 字符串清洗;`revoked` 每条上报即时复核 → 吊销秒级生效。
3. **注册通道(/api/agent/register)**:一次性密钥,原子 `UPDATE ... WHERE used_at IS NULL` 防双花。
4. **下行通道**:`ServerToAgent` 仅 `UpdateConfig` 变体,`deny_unknown_fields`;agent 端 clamp+严格解析。

## 2. 端点清单核对

| 端点 | 方法 | 认证 | 输入校验 | 限速 |
|---|---|---|---|---|
| `/api/setup` | GET/POST | 公开(仅未初始化可 POST,原子防竞态) | 强类型+强度 | Login |
| `/api/login` | POST | 公开 | 强类型 | Login+退避 |
| `/api/logout`,`/logout_all` | POST | 会话 | — | Api |
| `/api/password` | POST | 会话 | 强度校验 | Api |
| `/api/me` | GET | 会话 | — | Api |
| `/api/nodes` | GET/POST | 会话 | 名称清洗+唯一 | Api |
| `/api/nodes/{id}` | GET/DELETE | 会话 | id 类型化 | Api |
| `/api/nodes/{id}/metrics` | GET | 会话 | secs clamp | Api |
| `/api/nodes/{id}/{rename,revoke,regen_key}` | POST | 会话 | 强类型 | Api |
| `/api/settings` | GET/POST | 会话 | 范围校验 | Api |
| `/api/audit` | GET | 会话 | — | Api |
| `/api/agent/register` | POST | 一次性密钥(常量时间) | hex 格式 | Register |
| `/api/agent/manifest`,`/download/{name}` | GET | 公开(完整性靠 SHA-256) | 文件名白名单 | Api |
| `/ca.pem`,`/install.sh`,`/uninstall.sh`,`/healthz` | GET | 公开(设计如此) | — | Api |
| `/ws/agent` | GET | Bearer token(常量时间,升级前) | 见 §1.2 | Ws |
| `/ws/ui` | GET | 会话 + Origin 校验 | 单向下发 | Ws |
| 页面 `/`,`/nodes/{id}`,`/settings` | GET | 会话(未登录 302) | — | Api |

**认证覆盖核对:** 除设计上公开的端点(登录/引导、agent 注册、分发/CA/脚本、健康检查、静态资源)外,所有端点均经会话或 token 认证,无遗漏。

## 3. 第 7 节「AI 常见漏洞清单」逐条自查

| # | 项 | 结果 |
|---|---|---|
| 1 | 拼接 SQL | ✅ 全部 `query!` 参数化+编译期校验,零拼接 |
| 2 | 跳过 TLS 校验 | ✅ 全仓库无跳过分支;自定义 CA 亦为校验 |
| 3 | 硬编码密钥 | ✅ 秘密扫描无命中;token/密码不入日志/版本库 |
| 4 | 攻击面 unwrap/expect/裸索引 | ✅ 生产代码 0;lint `unwrap_used`/`expect_used`/`indexing_slicing`=deny 机器强制 |
| 5 | 整数溢出 | ✅ 速率/差值全 `saturating_*`/`checked_*`;计数器回绕→0 |
| 6 | 路径遍历 | ✅ 下载走白名单文件名;页面/静态全内嵌无路径拼接 |
| 7 | 命令注入 | ✅ 服务端不调用外部命令;安装脚本用参数、密钥走 stdin 不入 argv |
| 8 | 反序列化无限制 | ✅ 全类型 `deny_unknown_fields`;body/消息大小上限 |
| 9 | 时序不安全比较 | ✅ token/密钥用 `subtle` 常量时间;登录哑哈希均衡 |
| 10 | CORS*/CSP 缺失/响应头 | ✅ 无 CORS;严格 CSP+完整安全头 |
| 11 | 认证中间件遗漏 | ✅ 提取器类型强制,见 §2 清单 |
| 12 | 越权(IDOR) | ✅ 单管理员;所有资源操作需会话;无信任客户端所属关系 |
| 13 | 日志泄露敏感信息 | ✅ token 不入日志(实测 journal 无 64-hex);错误对外脱敏 |
| 14 | 存储型 XSS | ✅ 入库清洗 + 前端仅 textContent;实测 XSS 载荷未执行 |
| 15 | 默认凭据/默认开放/调试端点 | ✅ 无默认账号;默认监听回环;无调试端点 |
| 16 | 错误泄露内部细节 | ✅ `AppError` 对外统一文案,sqlx 错误仅入日志 |
| 17 | 竞态 | ✅ 注册双花/首次建号用原子 SQL 条件更新 |
| 18 | 无理由 unsafe | ✅ `#![forbid(unsafe_code)]` 全 crate |
| 19 | 未限制请求体/消息 | ✅ body 64KB、WS 帧 256KB |
| 20 | 非 CSPRNG 生成 token | ✅ `OsRng` 32 字节;失败返回错误不降级 |

## 4. 模糊/异常输入实测(生产环境 cc,2026-07-03)

| 用例 | 期望 | 实测 |
|---|---|---|
| 注册密钥重放 | 拒绝 | 403 ✅ |
| 密钥注入 `' OR 1=1 --` | 拒绝 | 403 ✅ |
| 未认证访问 `/api/nodes` | 401 | 401 ✅ |
| 伪造 Origin 改状态 | 403 | 403 ✅ |
| 无 Origin 且无自定义头 | 403 | 403 ✅ |
| 200KB 请求体 | 413 | 413 ✅ |
| 路径遍历下载 | 拒绝 | 400 ✅(未泄露文件) |
| 假 token 连 WS | 拒绝 | 400 ✅(未建立连接) |
| 未知字段夹带 `cmd` | 拒绝 | 422 ✅ |
| 登录爆破 12 次 | 后段 429 | 4 次后即 429 ✅ |
| XSS 节点名 | 存储但不执行 | 200 存储,前端 textContent 渲染 ✅ |
| 服务健康度 | 保持 active | 全程 active ✅ |

## 5. 依赖审计

- `cargo audit`:通过(2 项豁免,见下)。`cargo deny check`:advisories/bans/licenses/sources 全 ok。
- **RUSTSEC-2023-0071(rsa)**:不在实际构建图(`cargo tree -i rsa` 为空),系 sqlx 可选 MySQL 特性残留于 lockfile,二进制不含该代码。已在 `deny.toml`/`.cargo/audit.toml` 记录豁免。
- **RUSTSEC-2025-0134(rustls-pemfile unmaintained,警告级)**:经 axum-server 传递引入,仅用于启动时解析本地受信证书文件;我方代码已迁移至 `rustls-pki-types`。等待上游更新。
- 许可证:全为 MIT/Apache-2.0/BSD/ISC/OpenSSL 等宽松许可(ring 表达式已 clarify)。

## 6. 配置与部署审计

- 默认配置安全:监听 `127.0.0.1`;非回环明文监听被配置校验拒绝(除非显式开关)。
- server systemd:非 root(outpost)、`ProtectSystem=strict`、`MemoryDenyWriteExecute`、`CapabilityBoundingSet=` 空、`SystemCallFilter=@system-service`、`MemoryMax=256M`。
- agent systemd:非 root(outpost-agent)、同等沙箱 + `RestrictAddressFamilies=AF_INET AF_INET6`、`MemoryMax=64M`、`CPUQuota=30%`。实测运行用户 `outpost-agent`,token `0600`。
- 文件权限:配置 `0640 root:outpost`、CA 私钥 `0600`、token `0600`。

## 7. 残留风险与建议

1. **私有 CA 信任模型**:安装命令用 `curl -k` 取 `ca.pem` 后**核对指纹**再使用——首次信任锚定于面板展示的指纹,需保证获取安装命令的信道(已登录的 TLS 面板)可信。有公网域名者建议改用 `public_ca` 模式 + Let's Encrypt,消除自签提示。
2. **rustls-pemfile** 上游停维护(见 §5),低风险,持续跟踪。
3. **单管理员模型**:未实现多用户/RBAC(规模假设 <20 节点,符合规范)。如需多用户须补充授权层与相应 IDOR 测试。
4. 阈值告警/Webhook 为 P2,未实现(规范允许首版仅界面标红)。

## 8. 里程碑自查记录

- 阶段0-1(脚手架/服务端核心):clippy(-D warnings)通过、common 恶意输入单测 11 项通过。
- 阶段2-3(注册/上报/agent):parsers 恶意输入单测(溢出/畸形/回绕)10 项通过;TLS 无跳过分支复核。
- 阶段4(前端):innerHTML/eval 扫描为空;CSP 实测生效。
- 阶段5-6(构建/部署):musl 全静态产物 + SHA256;真实部署 + §4 实测。
- 阶段7:本报告 + SECURITY.md + README + config.example。`cargo audit`/`deny`/`clippy`/`test` 全绿。

---

## 附录 A:v0.2 功能扩展安全审计(2026-07-03)

在初版基础上新增告警闭环、多渠道通知、数据出口、进阶采集、账号安全、规模化与状态页等。
每批次均过 `clippy -D warnings` / `cargo test`(39 项)/ `cargo audit` / `cargo deny` 并在生产环境实测。

### A.1 新增攻击面与缓解

| 新入口 | 主要威胁 | 缓解 | 实测 |
|---|---|---|---|
| 告警 Webhook 出站 | **SSRF**(打内网/云元数据 169.254.169.254) | 强制 https、自解析 DNS 校验目标 IP 非私网、连已校验 IP(防 rebinding)、禁重定向、超时限长 | 回环/私网/元数据全 403 ✓ |
| Telegram/Bark 渠道 | token 泄露、SSRF | token 形态白名单校验、列表脱敏展示、公网目标经同一 SSRF 客户端 | 坏 token 拒、脱敏正确 ✓ |
| 登录新设备通知 | 通知放大/信息泄露 | 纯出站文本(不含密码/token);去重节流 | ✓ |
| 只读 API Token | 越权写、token 泄露 | 独立 `opk_` 前缀、仅存 SHA-256、常量时间比较、**仅授予 GET 只读**、明文仅创建时返回一次 | 无 token 401、错 token 401 ✓ |
| Prometheus `/metrics` | label 注入/断行 | label 值转义(`\`、`"`、`\n`、控制字符),单测锁定 | ✓ |
| 历史导出 / 审计导出 CSV | **CSV 公式注入**、断行注入 | `=+-@`/制表前缀加 `'`、引号包裹转义、去 CR/LF;审计 detail 为用户可控字符串重点处理 | 单测覆盖 ✓ |
| TOTP 两步验证 | 时序侧信道、暴力破解 | HMAC-SHA1 自实现 + 常量时间比较、±1 窗口、失败计入登录退避;RFC6238 向量单测通过 | 纯密码拒/错码拒/一次性恢复码 ✓ |
| 会话/设备管理 | **IDOR**(撤销他人会话) | 撤销 SQL 限定 `user_id = 当前用户`;标识为 SHA-256(非 Cookie 本身) | 越权/非法标识 400 ✓ |
| SQLite 备份下载 | 路径注入、并发 | `VACUUM INTO` 受控路径(operator 配置 db 目录 + 固定文件名 + 转义单引号);一致性快照;无在线恢复端点 | 产出合法 SQLite ✓ |
| 批量操作 | 放大破坏、越权 | 条数限 1~100、action 白名单、逐条走原校验与审计 | 空/超限/非法 action 拒 ✓ |
| **公开状态页** | 数据泄露、枚举 | 默认关闭;24 位高熵 slug 门控 + 常量时间比较;**脱敏**(仅 name/grp/online/cpu/mem/disk,无 IP/主机名/备注/版本);关闭即时失效 | 错 slug 404、关闭后 404、字段脱敏 ✓ |
| Agent 进程/温度/IOPS/TCP 采集 | 敏感信息、命令面 | 纯只读 `/proc`;**进程名来自 agent 本地配置,服务端无法下发**;数值全 saturating + 清洗 | agent 仍 2.2MB,无命令面 ✓ |
| 升级引导 | 远程执行红线 | 仅**渲染文本命令**供人工执行;`upgrade.sh` 静态可审计、SHA-256 校验;server 绝不主动执行 | ✓ |

### A.2 红线复核(全部保持)
- **不下发远程命令**:`ServerToAgent` 仍仅 `UpdateConfig`;告警规则为 enum 白名单无任意表达式;升级仅输出文本。✓
- **不跳过 TLS 校验**:新增出站 Webhook 客户端用 webpki 根严格校验证书。✓
- **参数化 SQL**:新增全部查询仍用 `query!` 编译期校验;唯一例外 `VACUUM INTO` 用受控非用户路径。✓
- **认证覆盖**:新增管理端点均经 `SessionUser`;只读数据端点经 `ReadAuth`(会话或 API token);公开端点(状态页 JSON、注册、分发)为设计内公开且各有门控。✓
- CSRF:新增改状态端点经 Origin/CSRF 中间件(实测伪造 Origin 403)。✓

### A.3 依赖变更
- 新增:`hmac`+`sha1`(TOTP,RustCrypto,MIT/Apache)、`tokio-rustls`+`webpki-roots`(SSRF 加固出站,复用 ring)。
- `cargo tree` 依赖总数未增(261),新 crate 均为既有传递依赖或轻量;`cargo deny` licenses/sources 通过。

### A.4 本轮修复的真实缺陷
- **agent 独立编译缺 `tokio` 的 `sync` feature**:此前仅因与 server 同批构建时特性合并而侥幸通过;单独 `cargo build -p outpost-agent` 会失败。已在 agent 自身 `Cargo.toml` 补齐,恢复交付物自包含性。

### A.5 明确推迟项(带理由)
- **SSL 证书到期 / 端口可达性探测**:需向任意外部目标发起主动连接,实质扩大 agent/server 网络攻击面。按规范"扩大攻击面的功能应独立设计并单独安全评审"原则,推迟为独立模块,不在本轮合入。

## 附录 B:v1.1 部署工具安全审计(2026-07-03)

新增一键安装脚本、Docker、CLI/环境变量创建管理员,均**不新增网络攻击面**。

| 项 | 安全说明 | 验证 |
|---|---|---|
| `admin-create` 子命令 | 复用与网页 setup **完全相同**的用户名/密码校验与 argon2id 哈希;仅当无用户时原子插入(幂等);密码经环境变量/stdin,**不入 argv** | 合法/幂等/校验拒绝/stdin 均实测 ✓ |
| 首启环境变量引导 | 仅当库中无用户且 `OUTPOST_ADMIN_USER/PASSWORD` 均非空时创建;之后不再读取 | 内置 TLS 下引导+登录实测 ✓ |
| 一键安装脚本 | 全程 https + `--proto =https`;二进制**逐个 SHA-256 校验**;密码经 env 传给 admin-create 不入 argv;systemd 沿用全套加固(低端口才授予 `CAP_NET_BIND_SERVICE`);DB 归属非 root 的 outpost | 组件级实测 + 公开下载校验 ✓ |
| 内置 TLS(免 nginx) | rustls 直接终止 TLS,自签 CA + 服务端证书;agent 仍以 CA 指纹钉扎信任,严格校验不跳过 | 自签证书握手 + 登录实测 ✓ |
| Docker | 多阶段构建;运行时以 `gosu` 降权到 outpost;证书/配置持久化于卷(CA 指纹稳定);env 引导管理员;agent 二进制经 SHA-256 校验后落盘 | 运行时行为(TLS+引导)原生等价实测 ✓ |
| 配置解析 | 修复 `OUTPOST_ADMIN_*` 被 figment 误当配置字段的问题(与 `OUTPOST_CONFIG` 一并从配置解析中排除) | 实测 ✓ |
| 供应链 | 新增依赖仅 `hmac`/`sha1`(RustCrypto);无新增网络出站面;`cargo deny` 通过 | ✓ |

**红线复核**:安装/升级脚本仅在**用户本机主动执行**,server 端从不主动执行任何下发内容;`curl|sh` 已在文档提示"可先下载审阅"。TLS 校验无跳过分支。全部保持。

## 附录 C:v0.3 全面复审(2026-07-04,多代理并行 + 依赖审计)

范围:认证/会话/2FA/授权/CSRF、agent 上报通道 + 本轮新增(Backfill/systemd/top进程/TCP细分/SMTP/severity路由/silence)、前端 XSS/CSP/状态页/数据出口/容器部署/备份。三路独立代码审计结论一致:**【严重】0 项**。

### C.1 本轮修复的真实缺陷
| # | 级别 | 问题 | 修复 |
|---|---|---|---|
| 1 | 红线补齐 | 三 crate 缺 `#![forbid(unsafe_code)]`(仅注释无强制) | 三 crate 顶部加 `#![forbid(unsafe_code)]`,编译期强制零 unsafe(已通过编译) |
| 2 | 中 | WS 连接建立后对入站消息无消息级限流 → 已认证但被攻破节点可用 Backfill 洪水放大中心库 DB/CPU | conn_loop 增令牌桶(桶 120、补 8/s),Backfill 按点数计权;超速即断连(ws_agent.rs) |
| 3 | 中 | 开/关 2FA 不吊销其它设备既有会话 → 公共电脑旁路会话可绕过新开的 2FA | enable/disable 后 `DELETE FROM sessions WHERE user_id=? AND token_hash!=当前`(twofa.rs) |
| 4 | 中(部署卫生) | `docker-compose.yml` 硬编码示例弱口令,用户直接 up 即已知口令 | 入口脚本首启(DB 未建)且密码空/占位时**自动生成强随机并打印日志**;compose 默认留空(deploy/docker-entrypoint.sh) |
| 5 | 低(纵深) | `systemctl is-active` 单元名若以 `-` 开头会被当选项 | 加 `--` 选项终止符(collect.rs) |
| 6 | 低(纵深) | CSP 未显式 `object-src`(default-src 已覆盖) | CSP 增 `object-src 'none'`(middleware.rs) |

### C.2 审计确认的正确设计(误报澄清,非漏洞)
- **argon2**:`Argon2::default()` = Argon2id m=19MiB t=2 p=1(OWASP 合规)。
- **会话**:32B CSPRNG token、仅存 SHA-256、`__Host-` cookie、改密全失效、无会话固定。
- **限速**:per-IP 桶 + per-username 指数退避;`client_ip` 只信任配置代理,X-Real-IP 不可被直连伪造。
- **CSRF**:Origin 白名单精确匹配(含端口),缺 Origin 时要求自定义头(CORS 预检兜底)+ SameSite=Strict 双防线;`/api/agent/*` 无 cookie 认证,豁免正当。
- **授权**:所有写端点编译期强制 `SessionUser`;API token(`opk_`)仅授 3 个 GET 只读端点,无任何写权限;单管理员模型无跨租户 IDOR。
- **agent**:TLS 无跳过分支(红线);token 不落日志;systemd 子进程用 `Command::args` 不经 shell + 单元名 `[A-Za-z0-9@._-:]` 校验 + 仅 `is-active` + 本地配置来源(服务端不可下发)。
- **Backfill**:不更新 last_seen/不推实时/不触发告警,污染仅限自身节点图表(信任边界内)。
- **SSRF**:DNS 自解析后连已校验 IP(消除 rebinding)、不跟随重定向、IPv4/6 全覆盖含 v4-mapped。
- **SMTP**:邮箱/主题禁 CRLF、body 点填充、隐式 TLS 真校验证书、凭据不落日志。
- **前端**:全 `textContent`/`createElement` 渲染(零 innerHTML/eval);深链接 `?secs=` 白名单;桌面通知 body 纯文本。
- **数据出口**:CSV 公式注入防护(`csv_cell` 前缀 `'`)、Prometheus 标签转义。
- **容器**:非 root(gosu)、私钥 0600、systemd 全套沙箱、无 privileged/docker.sock、备份路径服务端派生无注入。

### C.3 依赖审计
- `cargo audit`:0 漏洞(261 依赖)。`cargo deny`:advisories/bans/licenses 全 ok。RUSTSEC-2023-0071(rsa)不在构建图,已豁免记录。

### C.4 剩余低危(可选,已评估影响可忽略)
TOTP 无重放计数(需先破 TLS)、限速/退避为内存态(重启重置,单实例可接受)、恢复码 40bit(受在线限速约束足够)、状态页 slug 48bit 熵(公开脱敏数据足够)、`/api/backup` 全库 VACUUM 可高频触发 I/O(受通用 API 限速约束)。

## 附录 D:v0.4 会话(2026-07-05)——动态对外地址、变化率告警、轻量 RBAC、Docker 容器监控

### D.1 本轮新增功能与安全设计

| 项目 | 主要风险 | 缓解设计 | 实测 |
|---|---|---|---|
| 待注册节点「一键安装」按钮 | 无新增攻击面 | 复用既有 `regen_key` 端点(一次性密钥 30 分钟有效、仅一次展示),命令按当前 `public_url` 实时渲染 | ✓ |
| **public_url/extra_origins 设置页动态化** | Origin/CSRF 白名单被弱配置绕过;运行时状态与磁盘配置不一致 | 校验逻辑与启动时完全一致(必须 https,`dev_local` 例外);运行时存于 `RwLock`(读多写少),写入需 `SessionAdmin`;改动立即生效并持久化到 `settings` 表(与 `report_interval_secs` 同表同治理);写操作过审计日志 | curl 实测:改 `public_url` 后旧 Origin 请求 403、新 Origin 放行、安装命令与状态页链接即时用新地址渲染,无需重启 ✓ |
| **变化率(roc)告警条件** | 新增历史值查询路径;越权读取他人节点历史 | 复用 `metrics` 表既有只读查询,`node_id` 由规则本身限定;指标限白名单(仅 cpu/mem/disk/swap 使用率与 1 分钟负载,禁 tcp_conns 等无独立列指标);窗口 30~86400s、阈值 >0 服务端强校验 | 单测(`roc_whitelist_and_message`)+ curl 边界校验(坏指标/坏窗口/零阈值均 400)✓ |
| **轻量 RBAC(admin / viewer)** | 本项目原为单账号模型,新增角色是迄今风险最高的一次改动——**漏一个写端点即越权** | 新增独立提取器 `SessionAdmin`(`session.rs`),`Deref` 到 `SessionUser` 使函数体几乎不变;逐一排查并替换约 30 个状态变更端点(节点增删改/批量、告警规则/渠道/静默/重复提醒、设置、状态页开关、账号管理);viewer 仅保留**自服务且已按 `user_id=自身` 限定**的端点(改密、2FA 开关、会话查看/撤销、退出);`/api/backup`(全库含哈希/密钥导出)与 API Token 管理**额外收紧为 admin-only 的 GET**(未套用"GET=只读=viewer 可见"的默认规则,因二者本质是凭据/全量数据管理而非监控数据);账号管理端点禁止删除/降级最后一个 admin、禁止删除自己;角色变更即时吊销该账号其它会话(与 2FA 变更一致的处理) | curl 端到端矩阵:只读端点(nodes/settings/alerts/audit 等)viewer 200,写端点(create/delete/toggle/settings POST/backup/apitokens)viewer 全 403;自服务端点(2fa/sessions/me)viewer 200;"最后一个 admin"保护(降级/删除均拒)、禁止自删、删除账号级联吊销其会话(401 验证)✓ |
| **Docker 容器监控**(可选,默认关闭) | 需 agent 运行账号加入 `docker` 组——**等效本机 root**,是对 agent 现有"零 socket 访问、最小权限"安全模型的实质性改变 | 用户明确选择"仅可选主机启用"后实现:默认关闭(`docker_stats=false`,本地配置项,服务端无法下发);零 docker CLI 子进程,自实现最简 HTTP/1.1-over-UNIX-socket 客户端且仅发 GET(list + stats,无任何写操作);响应体上限 4MB + 读写超时 800ms(防 daemon 异常挂起拖累采样循环);容器 ID 在拼 URL 前二次形态校验(即便来自 Docker 自身响应而非用户输入);采集结果与其余指标共用 `validate_and_clean_metrics` 清洗管线(字符串清洗截断、数值 clamp);任意环节失败(无 socket/无权限/格式异常)一律静默返回空列表,不影响其余指标上报;不在安装脚本中默认将 agent 账号加入 `docker` 组,需管理员自行 `usermod` 并知悉其权限含义(README 已加粗提示) | `cargo build/clippy/test` 全绿;人工代码复核确认全程只读(仅 `http_get`,无 PUT/POST/DELETE 构造) |

### D.2 遗留条目补记(此前会话新增功能,原定"待补充审计"现予确认)
- **Backfill 补传 / SMTP 通知渠道 / systemd 服务监控(P2-3)**:均已在附录 C 范围内逐项确认(不更新 last_seen/不推实时/不触发告警;CRLF 防护+隐式 TLS 校验+凭据不落日志;子进程 `Command::args` 不经 shell+单元名白名单+`--` 选项终止符)。
- **inode 使用率(P2-1)/ 每核 CPU(P2-2)**:纯数值只读采集,复用既有 `validate_and_clean_metrics` 清洗管线(截断/非负/`used ≤ total` clamp),无新增攻击面;此前遗漏单独列出,现予补记确认。
- **总览全局趋势图(P3-1)**:`GET /api/overview/trend` 为纯服务端聚合只读查询,经 `SessionUser` 会话认证,无新增写面;现予补记确认。

### D.3 依赖
本轮零新增第三方依赖(Docker 客户端用 std 库 `UnixStream` + 已有 `serde_json`;RBAC/roc/动态地址均为既有依赖内实现)。

### D.4 未变更红线
不下发远程命令、不跳过 TLS 校验、参数化 SQL(`query!` 编译期校验)、CSRF Origin 精确匹配——均保持;认证覆盖新增一条前提:**全部状态变更端点必须用 `SessionAdmin`**(而非仅 `SessionUser`),已逐一核对并记录于上表。

## 附录 E:UI/UX 一轮(2026-07-05 续)——服务器排序、进程排序、图表平滑、品牌重命名、流量统计

均为纯展示层改动或范围明确的服务端计算,无新增网络攻击面。

| 项目 | 说明 |
|---|---|
| 服务器列表/进程列表排序 | 纯前端排序,数据源不变,无新增端点 |
| 图表平滑/数据点展示选项 | 纯前端 canvas 渲染逻辑,localStorage 记忆偏好,无服务端交互 |
| 品牌重命名 + 页脚版本号 | 静态文案 + `env!("CARGO_PKG_VERSION")` 编译期常量替换,无用户输入参与 |
| **流量统计(累计 + 可选按月清零)** | 新增 `traffic_reset_enabled`/`traffic_reset_day` 仅限创建/编辑节点端点(均 `SessionAdmin`),`reset_day` 服务端强校验 1~28;累计值来自已清洗的 `net_rx_bps`/`net_tx_bps`(与其余指标同一清洗管线,非用户可直接控制的原始输入);月份边界计算为纯整数日历算法(自实现,零新增依赖,配 5 项单测覆盖闰年/世纪闰年例外/跨年/跨月边界);断线重连后单次上报的"计入时长"设上限(`max(interval×3, 30s)`),避免长时间离线重连时把整段离线时间乘以瞬时速率造成流量假象 |

进程列表"网速"列与 P2-4 一样经用户确认评估后**明确不做**:需 agent 具备跨用户读取 `/proc/[pid]/fd` 的权限(root 或 `CAP_SYS_PTRACE`+`CAP_DAC_READ_SEARCH`),会改变 agent 现有零特权模型,判定收益/风险比不划算,故只做了排序、未做该列。

## 附录 F:服务器管理批量远程升级 agent(2026-07-06)——正式记录规范 6.4 红线破例

用户在提出"服务器排序/分组下拉/进程排序细化/图表展示/品牌页脚"等一批 UI 需求的同时,
要求新增"选中多台服务器一键触发远程升级 agent"。这是本项目迄今唯一一次**主动打破**
既有安全红线的功能,记录如下,供后续审计与运维参考。

**被打破的既有原则(均在代码注释与本文件中原有明确表述):**
1. `crates/common/src/lib.rs` 模块文档 + `ServerToAgent` enum 文档:"规范 6.4 红线——
   下行(server→agent)消息严格白名单,不存在能承载命令/脚本的变体"。
2. `crates/agent/src/main.rs` 下行消息处理注释:"服务端也可能被攻破:严格解析,
   畸形一律忽略(规范 6.2.5)"——即 agent 的既有威胁模型显式假设 server 自身
   可能被攻破,下行通道因此被设计为即使被攻破的 server 也无法致使 agent 执行新代码。
3. `crates/agent/src/collect.rs` systemctl 只读探测注释:"绝不执行 start/stop/restart
   等控制命令"。

**决策过程**:本次改动前先向用户说明了两种实现方式的风险差异(批量生成手动命令 vs
服务端真正远程触发),用户明确选择后者;进一步展示了上述第 1 条红线的具体文字后,
再次征询确认,用户仍选择"确认破例,按真升级实现"。两轮确认均记录在会话历史中。

**采用的设计(在"必须破例"的前提下,尽量收窄新增攻击面)**:
- `ServerToAgent::Upgrade` 是零参数触发器,不携带 URL/路径/命令行任何可变内容;
  agent 收到后仍然只是"触发",走的是**本地已配置** server 地址的既有清单+SHA-256
  校验流程(与管理员手动执行 `upgrade.sh` 完全一致的信任边界),不引入
  "server 可指定任意下载源/任意命令"的新增能力。
- agent 进程本身**不提权**:通过 `install.sh` 预先写好的窄作用域 sudoers 规则
  (`outpost-agent ALL=(root) NOPASSWD: <systemctl> start outpost-agent-upgrade.service`,
  命令与单元名均固定、不接受外部输入),仅能启动一个**独立**的、不套用
  `outpost-agent.service` 沙箱(`ProtectSystem=strict` 等)的 oneshot 单元;
  真正的"下载校验+替换二进制+重启服务"逻辑在这个独立单元里以 root 执行,
  agent 侧进程本身自始至终是无权限账号。
- 为使 `sudo` 的 setuid 机制生效,被迫从 `outpost-agent.service` 移除了
  `NoNewPrivileges=true`(该 prctl 位会让 setuid 完全失效,是此前加固清单里
  专门为防提权而设的一项,现为支持这个明确授权的例外场景而移除;其余全部
  沙箱项——`ProtectSystem`/`ProtectHome`/`RestrictNamespaces`/`SystemCallFilter`
  等——原样保留)。
- `outpost-agent-upgrade-helper` 脚本本身零参数,server/CA 地址从本机
  `/etc/outpost-agent/config.toml` 读取(该文件 `root:outpost-agent 0640`,
  低权限 agent 账号只能读、不能写,无法反向篡改升级目标)。
- 服务端侧:`upgrade_tx`(node_id → 单发 mpsc sender)登记在线 WS 连接,
  批量触发端点(`POST /api/nodes/batch {action:"upgrade"}`,`SessionAdmin`)
  仅对当前有活跃连接的节点下发,离线节点原样跳过并在响应里显式列出
  (`offline: [...]`),避免"静默失败"造成误判已升级。全程无 ack 回执——
  触发成功只代表 WS 消息已送达,不代表 agent 侧升级最终成功,需管理员
  稍后自行核对 Agent 版本号。

**明确的遗留风险(用户已知悉并接受)**:
- 若 server 或某条已认证的管理员会话被攻破,攻击者现在**可以**让其管辖的全部
  在线 agent 拉取并安装该 server 提供的任意二进制——这与绝大多数软件自动更新
  机制默认承担的信任假设等价,但相对本项目此前"即使 server 被攻破也无法致使
  agent 执行新代码"的更严格默认值,是一次实质性放宽。
- 仅新装/重新执行过新版 `install.sh` 的节点才具备 sudoers + 独立 unit,老节点
  (如本轮之前已用旧版 install.sh 部署的 Hermes/PVE/Nas 等)不受影响,远程触发
  会因 sudo 权限不足而静默失败(agent 侧日志可见),需继续用 `upgrade.sh` 手动升级。
- 本机(macOS 开发机)无法验证 systemd sandboxing 下 `sudo`→D-Bus→独立 unit
  的实际逃逸行为,已完成的是代码编译 + clippy 全绿 + HTTP/WS 层逻辑的本地验证;
  **建议先在 cc(测试环境)新装一个节点跑通一次真实的远程升级触发,确认
  sudoers/oneshot unit 组合按预期工作后,再考虑推广到家庭服务器现网节点**。

### 补充修正(2026-07-06,同日):sudo 方案在真实环境实测失败,改用 systemd socket activation

上述"建议先实测"的顾虑应验了——用户在家庭服务器上对 Hermes 节点(agent 1.3.3,已经过
一次手动 `upgrade.sh` 升级,非首次接入)实际点击批量升级后无反应。排查
`journalctl -u outpost-agent`:

```
[warn] 收到服务端远程升级触发,请求启动升级单元
[error] 升级触发调用失败(可能未安装 sudoers 规则): No such file or directory (os error 2)
```

`os error 2`(ENOENT)不是"sudoers 规则未配置"那类权限错误,而是**`sudo` 这个可执行文件本身
在该机器上不存在**——`command -v sudo` 确认为空。这是设计时的疏漏:想当然假设了"目标 Linux
系统都装了 sudo",但相当一部分面向公众的精简云主机镜像(尤其海外 VPS 商提供的最小化
Debian/Ubuntu 镜像)默认只给 root 直接登录、不预装 sudo。这不是"配置缺失"能补救的,是更
底层的环境依赖假设错误。

**修正方案**:改用 **systemd socket activation** 代替 `sudo`:
- `install.sh` 新增 `outpost-agent-upgrade.socket` 单元,监听
  `/run/outpost-agent-upgrade.sock`,`SocketMode=0660` + `SocketUser=root` +
  `SocketGroup=outpost-agent`——只有 agent 自己的运行账号能连接。
- agent 侧把原来的 `sudo -n -- systemctl start ...` 换成
  `std::os::unix::net::UnixStream::connect(...)`:标准库自带能力,零新增依赖。
  只要连接成功(哪怕立即断开)systemd 就会自动拉起对应的 `outpost-agent-upgrade.service`
  oneshot 单元完成真正的下载校验+替换+重启,原理与手动 `sudo systemctl start` 完全一致,
  只是触发方式换成了内核/systemd 原生支持、100% 存在(agent/server 已强依赖 systemd)、
  不依赖任何可能缺失的外部工具的机制。
- 相应移除了 install.sh 里全部 sudoers 生成/校验逻辑,不再需要判断"是否装了 sudo"。
- 由于不再需要 `sudo` 的 setuid 机制,`outpost-agent.service` 的 `NoNewPrivileges=true`
  加固项**已恢复开启**(此前专门为容纳 sudo 而移除,现在的触发方式完全不需要这个例外)。
- 安全模型不变:agent 进程仍然自始至终不提权,socket 权限位保证只有它自己能触发,
  真正的特权操作依然发生在独立、沙箱外的 oneshot 单元里。

**遗留状态**:这次修正后,**仍然只有新装/重新执行过这版 install.sh 的节点才具备升级
socket**,家庭服务器现有节点(Hermes/PVE/Nas 等)仍需重装才能获得远程升级能力,这一点
和 sudo 方案时的限制一样,没有变得更差。

### 再次补充修正(2026-07-06,同日续):Accept=no 导致同一次触发被重复执行,打满启动频率限制

上一版修正部署后,在 Hermes 上用新版 `install.sh` 重装、实测了一次真实的端到端触发
(面板点击"升级 Agent",而非 cc 上那次原理性模拟)。第一次点击(审计日志确认全程只点了
一次,`node_batch upgrade x1 affected=1`)在 agent 侧成功触发(`已触发升级单元`,无报错),
但 `journalctl -u outpost-agent-upgrade.socket -u outpost-agent-upgrade.service` 显示
同一个连接在同一秒内把 oneshot 服务重复拉起了 **5 次**,随后触发 systemd 默认的
`start-limit-hit`,**把 socket 单元本身也一并拖成 `failed`**——第二次点击(20 秒后)
连接这个已经"死掉"的 socket,报 `Connection refused`(os error 111),而不是最初 sudo
方案那种 `No such file or directory`(os error 2)。

**根因**:`outpost-agent-upgrade.socket` 用的是 `Accept=no`(默认值)——这种模式下,
systemd 只负责监听、把连接扔进内核 backlog,**真正"取走"这个连接(`accept()`)是被拉起的
服务自己的责任**。但 `outpost-agent-upgrade-helper` 是个完全不了解 socket activation
协议的纯 shell 脚本,从未对传入的 fd 做任何 `accept`/读写/关闭操作。连接因此一直原封不动
留在 backlog 里没被排空,systemd 每次跑完这个 oneshot、重新检查该 socket 时,都会认为
"还有一个连接在等着处理",于是对**同一个从未被消费的连接**又一次拉起服务——如此循环,
直到把 `outpost-agent-upgrade.service` 自己的启动频率限制(systemd 默认
`StartLimitBurst=5`/`StartLimitIntervalSec=10s`)打满而进入 `failed`,连带它的触发方
socket 也失败退出监听。

**修正方案**:`Accept=no` 改成 **`Accept=yes`**——这是 systemd 官方文档里"纯触发/无需
实际数据交换"这类场景的标准做法:改成 `Accept=yes` 后,**systemd 自己**会对每个到达的
连接执行 `accept()`,backlog 被正确排空,不会重复触发;每个连接对应一个独立的服务实例,
因此关联的 service 单元必须改成模板单元(`outpost-agent-upgrade@.service`,注意文件名
里的 `@`),`install.sh` 相应做了改造(含删除旧的非模板 `.service` 文件,避免重装时新旧
两份单元同时存在造成混淆)。助手脚本本身完全不用改——它从来不需要读写这个 fd,只是被
动被 systemd 拉起执行既定的下载校验+替换+重启逻辑。

**这一次的教训**:cc 上那次"验证"只证明了机制原理(非特权用户能连上 socket、systemd
确实以 root 身份拉起了目标 unit),但**没有覆盖"服务不主动消费传入连接"这个 Accept=no
特有的坑**——因为 cc 那次手工搭的测试用例本身也是同样"不 accept 传入连接"的写法,原理
测试的局限性在于它和后来暴露问题的真实用法用的是**同一套有缺陷的配置**,不会自己暴露出
这个问题;真正靠得住的是这次在 Hermes 上走完整产品代码 + 真实面板点击的端到端测试。

**遗留状态**:同上,只有重新执行过这版 install.sh 的节点才具备修正后的 socket 配置;
Hermes 已经历两次 install.sh(sudo 版→初版 socket 版),即将进行第三次(Accept=yes 修正版)
以完成本次修正的实测验证。
