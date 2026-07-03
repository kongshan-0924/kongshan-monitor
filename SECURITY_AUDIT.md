# SECURITY_AUDIT — Outpost 哨站 最终安全审计报告

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
