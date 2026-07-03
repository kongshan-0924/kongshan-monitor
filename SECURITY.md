# SECURITY — Outpost 哨站 安全设计

本文档说明安全设计、威胁模型、部署加固建议与漏洞报告方式。实现级审计见
[SECURITY_AUDIT.md](SECURITY_AUDIT.md)。

## 设计总则

1. **安全 > 功能 > 性能 > 开发速度**;冲突时按此取舍。
2. **默认拒绝、最小权限、纵深防御**:每个入口默认关闭/最严格,需显式配置才放宽。
3. **不信任任何外部输入**:agent 上报(agent 可能被攻破)、前端请求、配置、环境变量一律校验。
4. **简单即安全**:依赖精简、代码可审计,全 workspace `#![forbid(unsafe_code)]`。

## 威胁模型

| 攻击面 | 主要威胁 | 缓解 |
|---|---|---|
| 公网入口(nginx 25510) | 暴力破解、DoS、越权、XSS/CSRF | 登录退避+限速、body/消息上限、会话鉴权全覆盖、CSP+Origin 校验、输出转义 |
| Agent 上报入口(WSS) | 伪造上报、被攻破 agent 投毒、重放 | 每 agent 唯一 token(常量时间比较+可即时吊销)、严格反序列化、数值/字符串清洗、时间戳偏移拒绝、消息大小限制 |
| 一次性注册通道 | 密钥被盗用/重放 | CSPRNG 生成、30 分钟时效、用后即焚(原子标记)、限速 |
| 安装分发 | 中间人篡改二进制 | 全程 HTTPS、私有 CA 指纹钉扎、二进制 SHA-256 校验 |
| 下行控制通道 | 面板下发任意命令(参考项目历史高危) | **红线:不存在此能力**;下行是无法承载命令的白名单枚举 |
| 本机 agent 提权 | agent 被利用后横向移动 | 非 root 专用用户、systemd 沙箱、token 0600、只读采集、`CapabilityBoundingSet=` 空 |
| 告警通知出站(Webhook/TG/Bark) | **SSRF**、凭据泄露 | 强制 https、自解析并校验目标 IP 非私网/回环/元数据、连已校验 IP 防 rebinding、禁重定向、渠道凭据脱敏 |
| 只读数据出口(API Token/Prometheus/导出) | 越权、注入 | `opk_` token 仅授 GET、只存哈希常量时间比较;Prometheus label 与 CSV 公式注入转义 |
| 账号(2FA/会话/备份) | 时序侧信道、IDOR | TOTP 常量时间 + 登录退避;会话撤销限定本人;备份 `VACUUM INTO` 受控路径 |
| 公开状态页 | 数据泄露、枚举 | 默认关闭、24 位高熵 slug、脱敏(无 IP/主机名/备注)、关闭即时失效 |

> 各新增功能的逐条威胁分析与实测见 [SECURITY_AUDIT.md 附录 A](SECURITY_AUDIT.md)。

## 认证与会话

- 首次运行强制创建管理员(argon2id),**无任何内置默认账号/密码**。
- 服务端会话:随机 token 仅存 SHA-256;Cookie `__Host-` 前缀 + `HttpOnly` + `Secure` + `SameSite=Strict`。可即时撤销;改密/登出全部会话即失效。
- 登录失败:同一账号 5 次后指数退避锁定(30s→上限 1h);登录/注册端点独立限速;用户名枚举时序均衡(哑哈希)。

## 通信

- 强制 WSS(TLS 1.2+,优先 1.3),无明文通道。
- Agent 严格校验服务端证书链与主机名;支持自定义 CA(自签场景)——**仍是校验,而非跳过**。代码中不存在任何 `danger_accept_invalid_certs` / 跳过分支。
- 上报带时间戳,偏移超阈值(默认 300s)拒绝;入库以服务端时间为准(抗重放/时钟漂移)。

## 输入与输出

- 所有请求体 serde 严格反序列化(`deny_unknown_fields`)+ 长度/范围/枚举校验;全局 body 上限 64KB,WS 单帧上限 256KB。
- 所有 SQL 走 sqlx `query!` 参数化 + 编译期校验,**零字符串拼接**。
- agent 上报的主机名/OS 等在入库前清洗(去控制字符、限长),前端**只用 `textContent`/`createElement` 渲染**,从不 `innerHTML` —— 存储型 XSS 双重防御。
- 严格 CSP(`default-src 'none'`,无 inline 脚本/样式)、`X-Frame-Options: DENY`、`nosniff`、`Referrer-Policy`、HSTS。

## 部署加固建议

- 保持服务端监听 `127.0.0.1`,由 nginx 终止 TLS;或启用内置 rustls。**切勿**非回环明文监听(配置会拒绝,除非显式 `allow_plain_nonloopback`)。
- 云安全组仅放行 25510;服务器已启用 fail2ban 与密钥登录。
- 定期 `cargo audit`;私有 CA 私钥(`/etc/outpost/pki/ca.key`)权限 0600 妥善保管。
- 数据保留期按需设置,自动清理防 SQLite 膨胀。

## 报告漏洞

请勿公开披露。通过私下渠道联系维护者并提供复现步骤;修复后再公开。
