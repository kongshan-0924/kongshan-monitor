#![forbid(unsafe_code)]
//! outpost-common:server 与 agent 共享的协议类型与校验逻辑。
//!
//! 安全考量:
//! - 所有入站消息类型均 `deny_unknown_fields`,强类型 enum,杜绝字段漂移与夹带。
//! - 下行(server → agent)消息是严格白名单 enum([`ServerToAgent`])。
//!   规范 6.4 红线原为"不存在能承载命令/脚本的变体";2026-07 经用户明确知情
//!   并二次确认后,为支持后台批量远程升级破例新增 [`ServerToAgent::Upgrade`]。
//!   该变体本身不携带任何参数(URL/路径/版本),agent 收到后仅使用其本地
//!   已配置的 server 地址走既有的"清单+SHA-256 校验"流程(等价于管理员手动跑
//!   upgrade.sh),不引入"服务端可指定任意下载源/任意命令"的新增攻击面;但
//!   确实将信任模型从"即使 server 被攻破,下行消息也无法致使 agent 执行新代码"
//!   放宽为"server 被攻破可致使其管理的全部 agent 拉取并安装其提供的二进制"
//!   ——与规范 6.2.5"假设 server 也可能被攻破"的既有威胁模型存在张力,
//!   等同于绝大多数软件自动更新机制默认承担的信任假设。执行侧仍要求 agent
//!   通过连接一个 root:outpost-agent 组可写的 systemd socket-activated unix
//!   socket 来触发固定路径、零参数的 root 助手脚本(不经 sudo/setuid——很多
//!   精简云主机镜像不预装 sudo,socket activation 只依赖 systemd 本身),
//!   不允许 agent 进程本身获得 root、也不允许下行消息携带任何可变参数。
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
/// 每核 CPU 上报核数上限(超出截断,防超大机器消息膨胀)。
pub const MAX_CORES: usize = 128;
/// 受监控服务数量上限。
pub const MAX_SERVICES: usize = 20;
/// Docker 容器上报数量上限(超出按 CPU 用量截断)。
pub const MAX_CONTAINERS: usize = 30;
/// 占用 Top 进程上报数量上限。
pub const MAX_TOP_PROCS: usize = 10;

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
    /// inode 总数 / 已用(0 表示该文件系统不适用或未知)。
    #[serde(default)]
    pub inodes_total: u64,
    #[serde(default)]
    pub inodes_used: u64,
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

/// systemd 服务状态(单元名来自 agent 本地配置,绝不由服务端下发)。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceStatus {
    pub name: String,
    pub active: bool,
}

/// Docker 容器状态(仅当 agent 显式开启 `docker_stats` 才采集;经本地 Docker
/// UNIX socket 只读查询,不执行任何写操作)。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContainerStat {
    pub name: String,
    /// running / exited / paused 等(Docker 原始状态字符串)。
    pub state: String,
    pub cpu_pct: f64,
    pub mem_used: u64,
    pub mem_limit: u64,
}

/// 占用最高的进程(按 CPU 排序取前 N)。名称来自 /proc/[pid]/comm。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopProc {
    pub name: String,
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
    /// 每核 CPU 使用率(%);核数超过上限时截断。
    #[serde(default)]
    pub cpu_per_core: Vec<f64>,
    /// 受监控 systemd 服务状态。
    #[serde(default)]
    pub services: Vec<ServiceStatus>,
    /// CPU 占用最高的若干进程。
    #[serde(default)]
    pub top_procs: Vec<TopProc>,
    /// TCP 连接分状态计数(可用时)。
    #[serde(default)]
    pub tcp_estab: Option<u32>,
    #[serde(default)]
    pub tcp_listen: Option<u32>,
    #[serde(default)]
    pub tcp_time_wait: Option<u32>,
    /// Docker 容器状态(默认关闭,见 [`ContainerStat`])。
    #[serde(default)]
    pub containers: Vec<ContainerStat>,
}

/// agent → server 上行消息(强类型、拒绝未知字段)。
/// 变体大小差异来自 `Metrics` 本身较大(可选指标字段较多);消息构造后立即
/// 序列化并丢弃,非热路径重复分配,不做装箱以免各处解构徒增复杂度。
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum AgentToServer {
    /// 连接建立后首条消息:上报静态信息。
    Hello { host: HostInfo },
    /// 周期指标上报。
    Metrics { metrics: Metrics },
    /// 断线期间缓冲点的补传(每点携带其原始 ts)。server 按时间窗校验并按
    /// (node_id, ts) 去重入库,不更新 last_seen、不推实时、不触发告警。
    Backfill { points: Vec<Metrics> },
}

/// server → agent 下行消息:**严格白名单**。
///
/// 规范 6.4 红线:新增变体必须经安全评审,不得携带可变参数(URL/路径/命令行)。
/// [`ServerToAgent::Upgrade`] 是该红线下唯一破例(见模块文档顶部说明与
/// SECURITY_AUDIT.md 附录 F):它是零参数触发器,agent 收到后仍只走本地
/// 已配置 server 的既有清单校验流程,新增变体本身不携带任何攻击者可控内容。
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum ServerToAgent {
    /// 更新上报间隔(秒)。agent 端 clamp 到 [1, 3600]。
    UpdateConfig { report_interval_secs: u32 },
    /// 触发一次 agent 自升级(零参数;agent 走本地已配置 server 的清单+SHA-256
    /// 校验流程,通过连接 systemd socket-activated unix socket 触发 root 助手
    /// 完成下载校验+替换+重启,agent 进程本身不提权、不经 sudo)。仅管理员可从
    /// 「服务器管理」批量触发。
    Upgrade,
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
        // inode 计数上限保护 + used ≤ total
        d.inodes_total = d.inodes_total.min(1u64 << 40);
        d.inodes_used = d.inodes_used.min(d.inodes_total);
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
    m.cpu_per_core.truncate(MAX_CORES);
    for c in &mut m.cpu_per_core {
        *c = if c.is_finite() { c.clamp(0.0, 100.0) } else { 0.0 };
    }
    m.services.truncate(MAX_SERVICES);
    for s in &mut m.services {
        s.name = clean_str(&s.name, 64);
    }
    m.top_procs.truncate(MAX_TOP_PROCS);
    for p in &mut m.top_procs {
        p.name = clean_str(&p.name, 32);
        p.cpu_pct = if p.cpu_pct.is_finite() { p.cpu_pct.clamp(0.0, 100.0) } else { 0.0 };
        p.rss = p.rss.min(MAX_BYTES_VALUE);
    }
    for v in [&mut m.tcp_estab, &mut m.tcp_listen, &mut m.tcp_time_wait] {
        if v.is_some_and(|c| c > 10_000_000) {
            *v = None;
        }
    }
    m.containers.truncate(MAX_CONTAINERS);
    for c in &mut m.containers {
        c.name = clean_str(&c.name, 64);
        c.state = clean_str(&c.state, 32);
        c.cpu_pct = if c.cpu_pct.is_finite() { c.cpu_pct.clamp(0.0, 100_000.0) } else { 0.0 };
        c.mem_used = c.mem_used.min(MAX_BYTES_VALUE);
        c.mem_limit = c.mem_limit.min(MAX_BYTES_VALUE);
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
            cpu_per_core: vec![],
            services: vec![],
            top_procs: vec![],
            tcp_estab: None,
            tcp_listen: None,
            tcp_time_wait: None,
            containers: vec![],
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
                inodes_total: 100,
                inodes_used: 200, // > total → clamp
            });
        }
        validate_and_clean_metrics(&mut m3).unwrap();
        assert_eq!(m3.disks.len(), MAX_DISKS);
        assert_eq!(m3.disks[0].mount, "/m0");
        assert_eq!(m3.disks[0].used, 10);
    }

    #[test]
    fn container_stats_cleaned_and_truncated() {
        let mut m = sample_metrics();
        for i in 0..40 {
            m.containers.push(ContainerStat {
                name: format!("c{i}\x07"),
                state: "running".into(),
                cpu_pct: f64::NAN,
                mem_used: u64::MAX,
                mem_limit: u64::MAX,
            });
        }
        validate_and_clean_metrics(&mut m).unwrap();
        assert_eq!(m.containers.len(), MAX_CONTAINERS);
        assert_eq!(m.containers[0].name, "c0");
        assert_eq!(m.containers[0].cpu_pct, 0.0); // NaN → 0
        assert!(m.containers[0].mem_used <= MAX_BYTES_VALUE);
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
