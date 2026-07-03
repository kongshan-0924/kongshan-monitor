//! outpost-common:server 与 agent 共享的协议类型与校验逻辑。
//!
//! 安全考量:
//! - 所有入站消息类型均 `deny_unknown_fields`,强类型 enum,杜绝字段漂移与夹带。
//! - 下行(server → agent)消息是严格白名单 enum([`ServerToAgent`]),
//!   不存在能承载命令/脚本的变体(规范 6.4 红线)。
//! - 提供集中式清洗/校验([`validate_and_clean_metrics`]、[`clean_str`]),
//!   server 在入库前必须调用;字符串一律去控制字符并限长,数值一律限界。

use serde::{Deserialize, Serialize};

/// 协议版本(预留,升级时用于兼容判断)。
pub const PROTOCOL_VERSION: u32 = 1;

/// 单条 WS 消息大小上限(字节),两端共同遵守,防内存耗尽 DoS。
pub const MAX_WS_MESSAGE_BYTES: usize = 256 * 1024;

/// 限制值:挂载点 / 网卡数量上限。
pub const MAX_DISKS: usize = 16;
pub const MAX_NETS: usize = 16;

// ---------------------------------------------------------------------------
// 协议类型
// ---------------------------------------------------------------------------

/// 节点静态信息(注册及每次连接时上报,server 清洗后存库)。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostInfo {
    pub hostname: String,
    pub os: String,
    pub kernel: String,
    pub arch: String,
    pub cores: u32,
    pub mem_total: u64,
    pub agent_version: String,
}

/// 单个挂载点用量。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskUsage {
    pub mount: String,
    pub fs: String,
    pub total: u64,
    pub used: u64,
}

/// 单个网卡计数与速率。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetIf {
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_bps: u64,
    pub tx_bps: u64,
}

/// 受监控进程的探测结果(进程名来自 agent 本地配置,绝不由服务端下发)。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcInfo {
    pub name: String,
    pub running: bool,
    pub count: u32,
    pub cpu_pct: f64,
    pub rss: u64,
}

/// 受监控进程数量上限。
pub const MAX_WATCH_PROCS: usize = 12;

/// 一次采样的全部指标。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Metrics {
    /// agent 本地 Unix 秒;server 仅用于时钟偏移检查,入库以 server 时间为准(抗重放)。
    pub ts: i64,
    pub cpu_pct: f64,
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
    pub mem_total: u64,
    pub mem_used: u64,
    pub mem_available: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub disks: Vec<DiskUsage>,
    pub disk_read_bps: u64,
    pub disk_write_bps: u64,
    pub nets: Vec<NetIf>,
    pub uptime_secs: u64,
    pub procs: u32,
    // --- 进阶指标(新增,#[serde(default)] 保持跨版本兼容) ---
    /// CPU 温度(摄氏度);无传感器则 None。
    #[serde(default)]
    pub cpu_temp_c: Option<f64>,
    /// TCP 连接数;不可用则 None。
    #[serde(default)]
    pub tcp_conns: Option<u32>,
    /// 磁盘每秒读/写操作数(IOPS)。
    #[serde(default)]
    pub disk_read_iops: u64,
    #[serde(default)]
    pub disk_write_iops: u64,
    /// 受监控进程探测结果。
    #[serde(default)]
    pub procs_watch: Vec<ProcInfo>,
}

/// agent → server 上行消息(强类型、拒绝未知字段)。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum AgentToServer {
    /// 连接建立后首条消息:上报静态信息。
    Hello { host: HostInfo },
    /// 周期指标上报。
    Metrics { metrics: Metrics },
}

/// server → agent 下行消息:**严格白名单**。
///
/// 规范 6.4 红线:此 enum 永远不得加入任何能携带命令、脚本、路径、
/// 可执行内容的变体。新增变体必须经安全评审。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum ServerToAgent {
    /// 更新上报间隔(秒)。agent 端 clamp 到 [1, 3600]。
    UpdateConfig { report_interval_secs: u32 },
}

// ---------------------------------------------------------------------------
// 通用工具
// ---------------------------------------------------------------------------

/// 当前 Unix 秒。系统时钟早于 1970 时返回 0(不 panic)。
#[must_use]
pub fn unix_now() -> i64 {
    match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

/// 字节转小写 hex。
#[must_use]
pub fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        // 写入 String 不会失败;忽略 Result 以避免 unwrap
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// 是否全为小写十六进制字符。
#[must_use]
pub fn is_lower_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// 清洗字符串:去控制字符、去首尾空白、按字符数截断到 `max_chars`。
/// 用于所有来自 agent / 用户、将被存储或展示的字符串(存储型 XSS 纵深防御第一层;
/// 第二层是前端只用 textContent 渲染)。
#[must_use]
pub fn clean_str(s: &str, max_chars: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .take(max_chars)
        .collect::<String>()
        .trim()
        .to_string()
}

/// 校验节点名 / 用户名等短标识(1..=64 字符,无控制字符)。
#[must_use]
pub fn valid_short_name(s: &str) -> bool {
    let n = s.chars().count();
    (1..=64).contains(&n) && !s.chars().any(char::is_control)
}

const MAX_BYTES_VALUE: u64 = 1 << 60; // ~1 EiB,任何容量/用量字段上限
const MAX_BPS: u64 = 1 << 50; // ~1 PB/s,速率上限
const MAX_UPTIME: u64 = 60 * 60 * 24 * 366 * 50; // 50 年
const MAX_PROCS: u32 = 4_000_000;
const MAX_LOAD: f64 = 65535.0;

fn clamp_f(v: f64, lo: f64, hi: f64) -> Result<f64, &'static str> {
    if !v.is_finite() {
        return Err("non-finite float");
    }
    Ok(v.clamp(lo, hi))
}

/// 清洗 [`HostInfo`](入库前调用)。
#[must_use]
pub fn clean_host_info(h: &HostInfo) -> HostInfo {
    HostInfo {
        hostname: clean_str(&h.hostname, 64),
        os: clean_str(&h.os, 96),
        kernel: clean_str(&h.kernel, 64),
        arch: clean_str(&h.arch, 16),
        cores: h.cores.min(4096),
        mem_total: h.mem_total.min(MAX_BYTES_VALUE),
        agent_version: clean_str(&h.agent_version, 32),
    }
}

/// 校验并清洗一次指标上报(server 在入库前调用)。
///
/// - 数值越界 / 非有限浮点 → 报错拒绝(数据不可信,规范 6.1.4)
/// - 字符串 → 清洗(去控制字符、限长)
/// - 列表 → 截断到上限
/// - `mem_used > mem_total` 等矛盾 → 收敛(clamp),避免图表被污染
///
/// # Errors
/// 数值字段非法(非有限浮点 / 超出物理合理范围)时返回错误。
pub fn validate_and_clean_metrics(m: &mut Metrics) -> Result<(), &'static str> {
    m.cpu_pct = clamp_f(m.cpu_pct, 0.0, 100.0)?;
    m.load1 = clamp_f(m.load1, 0.0, MAX_LOAD)?;
    m.load5 = clamp_f(m.load5, 0.0, MAX_LOAD)?;
    m.load15 = clamp_f(m.load15, 0.0, MAX_LOAD)?;

    if m.mem_total > MAX_BYTES_VALUE || m.swap_total > MAX_BYTES_VALUE {
        return Err("memory size out of range");
    }
    m.mem_used = m.mem_used.min(m.mem_total);
    m.mem_available = m.mem_available.min(m.mem_total);
    m.swap_used = m.swap_used.min(m.swap_total);

    if m.disk_read_bps > MAX_BPS
        || m.disk_write_bps > MAX_BPS
        || m.uptime_secs > MAX_UPTIME
        || m.procs > MAX_PROCS
    {
        return Err("counter out of range");
    }

    m.disks.truncate(MAX_DISKS);
    for d in &mut m.disks {
        d.mount = clean_str(&d.mount, 128);
        d.fs = clean_str(&d.fs, 32);
        if d.total > MAX_BYTES_VALUE {
            return Err("disk size out of range");
        }
        d.used = d.used.min(d.total);
    }

    m.nets.truncate(MAX_NETS);
    for n in &mut m.nets {
        n.name = clean_str(&n.name, 32);
        if n.rx_bps > MAX_BPS || n.tx_bps > MAX_BPS {
            return Err("net rate out of range");
        }
    }

    // 进阶指标清洗
    if let Some(t) = m.cpu_temp_c {
        // 合理范围外(含 NaN)一律丢弃该项,不整条拒绝
        m.cpu_temp_c = (t.is_finite() && (-40.0..=150.0).contains(&t)).then_some(t);
    }
    if let Some(c) = m.tcp_conns {
        if c > 10_000_000 {
            m.tcp_conns = None;
        }
    }
    if m.disk_read_iops > MAX_BPS || m.disk_write_iops > MAX_BPS {
        return Err("iops out of range");
    }
    m.procs_watch.truncate(MAX_WATCH_PROCS);
    for p in &mut m.procs_watch {
        p.name = clean_str(&p.name, 32);
        p.cpu_pct = if p.cpu_pct.is_finite() { p.cpu_pct.clamp(0.0, 100.0) } else { 0.0 };
        p.rss = p.rss.min(MAX_BYTES_VALUE);
        p.count = p.count.min(1_000_000);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// 测试(含恶意输入)
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    fn sample_metrics() -> Metrics {
        Metrics {
            ts: 1_700_000_000,
            cpu_pct: 12.5,
            load1: 0.1,
            load5: 0.2,
            load15: 0.3,
            mem_total: 1024,
            mem_used: 512,
            mem_available: 512,
            swap_total: 0,
            swap_used: 0,
            disks: vec![],
            disk_read_bps: 0,
            disk_write_bps: 0,
            nets: vec![],
            uptime_secs: 100,
            procs: 42,
            cpu_temp_c: Some(45.0),
            tcp_conns: Some(30),
            disk_read_iops: 0,
            disk_write_iops: 0,
            procs_watch: vec![],
        }
    }

    #[test]
    fn clean_str_strips_control_and_truncates() {
        assert_eq!(clean_str("a\x00b\x1bc\r\n", 10), "abc");
        assert_eq!(clean_str("  héllo  ", 10), "héllo");
        assert_eq!(clean_str("<script>xss</script>", 8), "<script>"); // 转义交给输出层,此处仅限长
        assert_eq!(clean_str(&"x".repeat(500), 64).chars().count(), 64);
    }

    #[test]
    fn hex_roundtrip_and_check() {
        assert_eq!(to_hex(&[0x00, 0xff, 0x10]), "00ff10");
        assert!(is_lower_hex("00ffab"));
        assert!(!is_lower_hex("00FFAB"));
        assert!(!is_lower_hex(""));
        assert!(!is_lower_hex("zz"));
    }

    #[test]
    fn metrics_rejects_nonfinite_and_clamps() {
        let mut m = sample_metrics();
        m.cpu_pct = 250.0;
        m.mem_used = 4096; // > total
        validate_and_clean_metrics(&mut m).unwrap();
        assert_eq!(m.cpu_pct, 100.0);
        assert_eq!(m.mem_used, 1024);

        let mut m2 = sample_metrics();
        m2.load1 = f64::NAN;
        assert!(validate_and_clean_metrics(&mut m2).is_err());
    }

    #[test]
    fn metrics_rejects_absurd_counters_and_truncates_lists() {
        let mut m = sample_metrics();
        m.disk_read_bps = u64::MAX;
        assert!(validate_and_clean_metrics(&mut m).is_err());

        let mut m3 = sample_metrics();
        for i in 0..100 {
            m3.disks.push(DiskUsage {
                mount: format!("/m{i}\x07"),
                fs: "ext4".into(),
                total: 10,
                used: 20, // > total → clamp
            });
        }
        validate_and_clean_metrics(&mut m3).unwrap();
        assert_eq!(m3.disks.len(), MAX_DISKS);
        assert_eq!(m3.disks[0].mount, "/m0");
        assert_eq!(m3.disks[0].used, 10);
    }

    #[test]
    fn downlink_enum_is_whitelist_only() {
        // 未知字段 / 未知变体必须被拒绝(防止夹带指令)
        let bad = r#"{"type":"RunCommand","cmd":"rm -rf /"}"#;
        assert!(serde_json::from_str::<ServerToAgent>(bad).is_err());
        let sneaky = r#"{"type":"UpdateConfig","report_interval_secs":5,"cmd":"x"}"#;
        assert!(serde_json::from_str::<ServerToAgent>(sneaky).is_err());
        let ok = r#"{"type":"UpdateConfig","report_interval_secs":5}"#;
        assert!(serde_json::from_str::<ServerToAgent>(ok).is_ok());
    }

    #[test]
    fn uplink_rejects_unknown_fields() {
        let bad = r#"{"type":"Hello","host":{"hostname":"h","os":"o","kernel":"k","arch":"a","cores":1,"mem_total":1,"agent_version":"v","extra":"x"}}"#;
        assert!(serde_json::from_str::<AgentToServer>(bad).is_err());
    }

    #[test]
    fn host_info_cleaning() {
        let h = HostInfo {
            hostname: "evil\x00<img src=x onerror=alert(1)>".into(),
            os: "\x1b[31mDebian\x1b[0m".into(),
            kernel: "6.1".into(),
            arch: "x86_64".into(),
            cores: 999_999,
            mem_total: u64::MAX,
            agent_version: "0.1.0".into(),
        };
        let c = clean_host_info(&h);
        assert!(!c.hostname.contains('\x00'));
        assert_eq!(c.os, "[31mDebian[0m"); // 控制字符被剥离
        assert_eq!(c.cores, 4096);
    }
}
