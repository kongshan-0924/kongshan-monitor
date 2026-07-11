//! 配置加载(figment:TOML 文件 + `OUTPOST_` 环境变量覆盖)。
//! 默认值遵循"默认拒绝":仅监听 127.0.0.1、Cookie Secure、无明文对外。

use figment::providers::{Env, Format, Serialized, Toml};
use figment::Figment;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TlsCfg {
    /// 启用内置 rustls 直接终止 TLS(不经反代时使用)。
    pub enabled: bool,
    pub cert_path: String,
    pub key_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerCfg {
    /// 监听地址。默认仅回环(规范 6.1.13)。
    pub listen: String,
    /// 位于可信反向代理之后:为 true 时才采信可信代理的 X-Real-IP 作为客户端来源 IP;
    /// 为 false 时一律用 TCP 对端地址。默认 true。(Secure Cookie 由 `security.cookie_secure`
    /// 独立控制,与本开关无关。)注意:置于反代之后务必保持 true,否则限速/审计/登录退避会
    /// 把所有客户端塌缩为反代 IP,可能相互触发限流或账号锁。
    pub behind_proxy: bool,
    /// 可信代理地址列表(仅这些对端的 X-Real-IP 会被采信)。
    pub trusted_proxies: Vec<String>,
    /// 面板对外访问地址(用于 Origin 校验与安装命令渲染),必须 https。
    pub public_url: String,
    /// 额外允许的 Origin(如同时用域名+IP 访问)。
    pub extra_origins: Vec<String>,
    /// 显式确认允许"非回环 + 无 TLS"监听(默认禁止,红线 7)。
    pub allow_plain_nonloopback: bool,
    pub tls: TlsCfg,
}

impl Default for ServerCfg {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:25511".into(),
            behind_proxy: true,
            trusted_proxies: vec!["127.0.0.1".into(), "::1".into()],
            public_url: "https://127.0.0.1:25510".into(),
            extra_origins: vec![],
            allow_plain_nonloopback: false,
            tls: TlsCfg::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SecurityCfg {
    /// 会话 Cookie 加 Secure 标记(默认开;仅本机 http 调试时可关)。
    pub cookie_secure: bool,
    pub session_ttl_hours: u32,
    /// 响应带 HSTS(位于 TLS 之后时开启)。
    pub hsts: bool,
}

impl Default for SecurityCfg {
    fn default() -> Self {
        Self { cookie_secure: true, session_ttl_hours: 24, hsts: true }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct StorageCfg {
    pub db_path: String,
}

impl Default for StorageCfg {
    fn default() -> Self {
        Self { db_path: "/var/lib/outpost/outpost.db".into() }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct InstallCfg {
    /// pinned_ca:私有 CA + 指纹钉扎(无域名/自签场景);public_ca:公网可信证书。
    pub mode: String,
    /// 私有 CA 证书路径(pinned_ca 模式必填;会在 /ca.pem 提供下载并计算指纹)。
    pub ca_cert_path: String,
    /// agent 静态二进制目录(启动时计算 SHA-256 生成 manifest)。
    pub dist_dir: String,
}

impl Default for InstallCfg {
    fn default() -> Self {
        Self {
            mode: "pinned_ca".into(),
            ca_cert_path: String::new(),
            dist_dir: "/var/lib/outpost/dist".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct MetricsCfg {
    /// 单条 WS 消息上限(字节)。
    pub ws_max_message_bytes: usize,
    /// 允许的 agent 时钟偏移(秒),超出即拒绝该条上报(规范 6.3.6)。
    pub ts_skew_secs: i64,
}

impl Default for MetricsCfg {
    fn default() -> Self {
        Self { ws_max_message_bytes: outpost_common::MAX_WS_MESSAGE_BYTES, ts_skew_secs: 300 }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct NotifyCfg {
    /// 允许通知目标为私网/回环地址(默认拒绝以防 SSRF)。
    /// 仅在你确实要发往内网自建接收端时开启,并确保网络边界可信。
    pub allow_private_targets: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub server: ServerCfg,
    pub security: SecurityCfg,
    pub storage: StorageCfg,
    pub install: InstallCfg,
    pub metrics: MetricsCfg,
    pub notify: NotifyCfg,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("配置读取失败: {0}")]
    Load(String),
    #[error("配置无效: {0}")]
    Invalid(String),
}

impl Config {
    /// 加载并校验配置。
    ///
    /// # Errors
    /// 文件/环境变量解析失败或安全校验不通过时返回错误。
    pub fn load(path: &str) -> Result<Self, ConfigError> {
        // 这些 OUTPOST_ 变量是运行控制/引导用途,不是配置字段,需从配置解析中排除:
        // CONFIG=配置文件路径;ADMIN_USER/ADMIN_PASSWORD=首启管理员引导。
        let cfg: Config = Figment::from(Serialized::defaults(Config::default()))
            .merge(Toml::file(path))
            .merge(
                Env::prefixed("OUTPOST_")
                    .ignore(&["CONFIG", "ADMIN_USER", "ADMIN_PASSWORD"])
                    .split("__"),
            )
            .extract()
            .map_err(|e| ConfigError::Load(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let addr: SocketAddr = self
            .server
            .listen
            .parse()
            .map_err(|_| ConfigError::Invalid("server.listen 不是合法地址".into()))?;

        // 默认拒绝:非回环监听且未启用 TLS → 必须显式确认(且强烈不建议)
        if !addr.ip().is_loopback()
            && !self.server.tls.enabled
            && !self.server.allow_plain_nonloopback
        {
            return Err(ConfigError::Invalid(
                "拒绝在非回环地址上明文监听。请置于 TLS 反代之后监听 127.0.0.1,\
                 或启用 [server.tls],或(不建议)显式设置 allow_plain_nonloopback=true"
                    .into(),
            ));
        }

        // 本地开发例外:回环监听 + 关闭 Secure Cookie 时,允许 http:// 便于本机预览。
        // 生产(非回环或启用 Secure Cookie)不受影响,仍强制 https。
        let dev_local = addr.ip().is_loopback() && !self.security.cookie_secure;
        if !scheme_ok(&self.server.public_url, dev_local) {
            return Err(ConfigError::Invalid(
                "server.public_url 必须为 https://(本机回环预览可用 http:// 并关闭 security.cookie_secure)".into(),
            ));
        }
        for o in &self.server.extra_origins {
            if !scheme_ok(o, dev_local) {
                return Err(ConfigError::Invalid("extra_origins 必须为 https://(本机预览可 http://)".into()));
            }
        }
        if self.server.tls.enabled
            && (self.server.tls.cert_path.is_empty() || self.server.tls.key_path.is_empty())
        {
            return Err(ConfigError::Invalid("启用 TLS 需同时配置 cert_path/key_path".into()));
        }
        match self.install.mode.as_str() {
            "pinned_ca" | "public_ca" => {}
            _ => return Err(ConfigError::Invalid("install.mode 只能是 pinned_ca 或 public_ca".into())),
        }
        if !(1..=24 * 30).contains(&self.security.session_ttl_hours) {
            return Err(ConfigError::Invalid("session_ttl_hours 取值 1..=720".into()));
        }
        if !(60..=1_048_576).contains(&self.metrics.ws_max_message_bytes) {
            return Err(ConfigError::Invalid("ws_max_message_bytes 取值 60..=1048576".into()));
        }
        if !(5..=3600).contains(&self.metrics.ts_skew_secs) {
            return Err(ConfigError::Invalid("ts_skew_secs 取值 5..=3600".into()));
        }
        Ok(())
    }

    /// 解析后的监听地址(validate 已保证合法,此处兜底回环)。
    #[must_use]
    pub fn listen_addr(&self) -> SocketAddr {
        self.server
            .listen
            .parse()
            .unwrap_or_else(|_| SocketAddr::from(([127, 0, 0, 1], 25511)))
    }

    #[must_use]
    pub fn trusted_proxy_ips(&self) -> Vec<IpAddr> {
        // 未声明处于反代之后:一律不信任 X-Real-IP,只认 TCP 对端地址,
        // 防止同机/直连进程伪造头绕过限速与审计溯源(规范 6.1.9)。
        if !self.server.behind_proxy {
            return Vec::new();
        }
        self.server
            .trusted_proxies
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect()
    }

    /// 会话 Cookie 名(Secure 时用 __Host- 前缀获得浏览器级保护)。
    #[must_use]
    pub fn cookie_name(&self) -> &'static str {
        if self.security.cookie_secure {
            "__Host-op_session"
        } else {
            "op_session"
        }
    }

    /// 是否处于"本机回环 + 关闭 Secure Cookie"的开发预览例外(允许 http:// 的 public_url)。
    #[must_use]
    pub fn dev_local(&self) -> bool {
        self.listen_addr().ip().is_loopback() && !self.security.cookie_secure
    }
}

/// URL scheme 校验:必须 https://,`dev_local` 例外时也允许 http://(本机回环预览)。
/// 供启动时 config.toml 校验与运行时设置页动态修改校验共用。
#[must_use]
pub fn scheme_ok(url: &str, dev_local: bool) -> bool {
    url.starts_with("https://") || (dev_local && url.starts_with("http://"))
}

pub(crate) fn origin_of(url: &str) -> String {
    // 取 scheme://authority(保留 scheme;支持 https 与本机预览的 http)
    let (scheme, rest) = url.strip_prefix("https://").map_or_else(
        || url.strip_prefix("http://").map_or(("https", url), |r| ("http", r)),
        |r| ("https", r),
    );
    let end = rest.find('/').unwrap_or(rest.len());
    let auth = rest.get(..end).unwrap_or(rest);
    format!("{scheme}://{auth}")
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn default_config_is_safe_and_valid() {
        let c = Config::default();
        c.validate().unwrap();
        assert!(c.listen_addr().ip().is_loopback());
        assert!(c.security.cookie_secure);
        assert!(!c.server.tls.enabled);
    }

    #[test]
    fn refuses_plain_nonloopback() {
        let mut c = Config::default();
        c.server.listen = "0.0.0.0:8080".into();
        assert!(c.validate().is_err());
        c.server.allow_plain_nonloopback = true;
        c.validate().unwrap();
    }

    #[test]
    fn origin_extraction() {
        assert_eq!(origin_of("https://1.2.3.4:25510/some/path"), "https://1.2.3.4:25510");
    }

    #[test]
    fn rejects_http_public_url() {
        let mut c = Config::default();
        c.server.public_url = "http://1.2.3.4".into();
        assert!(c.validate().is_err());
    }
}
