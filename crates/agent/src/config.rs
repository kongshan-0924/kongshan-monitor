//! agent 配置:TOML,严格反序列化。不含任何跳过 TLS 校验的选项(红线 2)。

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    /// 服务端基础地址,必须为 https://(强制加密,无明文选项)。
    pub server: String,
    /// 自定义 CA 证书路径(自签场景)。设置后仅信任该 CA——仍是严格校验,不是跳过。
    #[serde(default)]
    pub ca_file: Option<String>,
    /// 长期 token 文件(权限应为 0600,由安装脚本写入)。
    pub token_file: String,
    /// 初始上报间隔(秒);连接后以服务端下发为准。
    #[serde(default = "default_interval")]
    pub report_interval_secs: u32,
    /// 要探测存活/资源占用的进程名列表(**本地配置,服务端无法下发**)。
    /// 按 /proc/[pid]/comm 精确匹配;最多 12 个。
    #[serde(default)]
    pub watch_processes: Vec<String>,
    /// 要探测 active 状态的 systemd 服务单元名(**本地配置,服务端无法下发**)。
    /// 仅只读查询 `systemctl is-active`,绝不执行控制命令;单元名严格校验。
    #[serde(default)]
    pub watch_services: Vec<String>,
}

/// systemd 单元名合法字符:字母数字与 `@ . _ - :`(禁止空格/斜杠/控制字符,防命令注入)。
#[must_use]
pub fn valid_unit_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'@' | b'.' | b'_' | b'-' | b':'))
}

fn default_interval() -> u32 {
    5
}

#[derive(Debug)]
pub enum ConfigError {
    Io(String),
    Parse(String),
    Invalid(&'static str),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "读取失败: {e}"),
            ConfigError::Parse(e) => write!(f, "解析失败: {e}"),
            ConfigError::Invalid(e) => write!(f, "配置无效: {e}"),
        }
    }
}

impl AgentConfig {
    /// 加载并校验。
    ///
    /// # Errors
    /// 文件不可读、TOML 非法或安全约束不满足。
    pub fn load(path: &str) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path).map_err(|e| ConfigError::Io(e.to_string()))?;
        let cfg: AgentConfig =
            toml::from_str(&raw).map_err(|e| ConfigError::Parse(e.to_string()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if !self.server.starts_with("https://") {
            return Err(ConfigError::Invalid("server 必须是 https://(禁止明文)"));
        }
        if self.server.len() > 512 {
            return Err(ConfigError::Invalid("server 过长"));
        }
        if self.token_file.is_empty() {
            return Err(ConfigError::Invalid("token_file 不能为空"));
        }
        if !(1..=3600).contains(&self.report_interval_secs) {
            return Err(ConfigError::Invalid("report_interval_secs 取值 1..=3600"));
        }
        if self.watch_processes.len() > outpost_common::MAX_WATCH_PROCS {
            return Err(ConfigError::Invalid("watch_processes 最多 12 个"));
        }
        if self.watch_processes.iter().any(|p| p.is_empty() || p.len() > 32) {
            return Err(ConfigError::Invalid("进程名长度需为 1..=32"));
        }
        if self.watch_services.len() > outpost_common::MAX_SERVICES {
            return Err(ConfigError::Invalid("watch_services 最多 20 个"));
        }
        if self.watch_services.iter().any(|s| !valid_unit_name(s)) {
            return Err(ConfigError::Invalid("systemd 单元名非法(仅限字母数字与 @._-:)"));
        }
        Ok(())
    }

    /// 派生 WSS 上报地址。
    #[must_use]
    pub fn ws_url(&self) -> String {
        let base = self.server.trim_end_matches('/');
        format!("wss://{}/ws/agent", base.trim_start_matches("https://"))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rejects_plain_http_and_unknown_fields() {
        let bad = r#"server = "http://1.2.3.4"
token_file = "/tmp/t""#;
        let parsed: Result<AgentConfig, _> = toml::from_str(bad);
        assert!(parsed.unwrap().validate().is_err());

        let unknown = r#"server = "https://1.2.3.4"
token_file = "/tmp/t"
skip_tls_verify = true"#;
        assert!(toml::from_str::<AgentConfig>(unknown).is_err()); // 不存在这种选项
    }

    #[test]
    fn ws_url_derivation() {
        let c: AgentConfig = toml::from_str(
            r#"server = "https://1.2.3.4:25510/"
token_file = "/var/lib/outpost-agent/token""#,
        )
        .unwrap();
        assert_eq!(c.ws_url(), "wss://1.2.3.4:25510/ws/agent");
    }
}
