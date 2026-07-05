//! 指标采集:读取 /proc、/sys 与 statvfs(经 rustix 安全封装,无 unsafe)。
//! 单项失败降级为默认值,整次采样永不失败(规范第 5 节)。

use crate::parsers::{
    cpu_percent, parse_cpu_per_core, parse_cpu_total, parse_diskstats, parse_loadavg,
    parse_meminfo, parse_mounts, parse_netdev, parse_os_release, parse_pid_comm, parse_pid_stat,
    parse_tcp_count, parse_tcp_states, parse_thermal_millideg, parse_uptime, rate_bps, CpuTimes,
    DiskStats,
};
use outpost_common::{DiskUsage, HostInfo, Metrics, NetIf, ProcInfo, ServiceStatus, TopProc};
use std::cmp::Ordering;
use std::collections::HashMap;
use std::time::Instant;

const MAX_PROC_READ: u64 = 256 * 1024;

/// 限长读取(/proc 文件都很小;上限防异常膨胀)。
fn read_file(path: &str) -> Option<String> {
    use std::io::Read;
    let f = std::fs::File::open(path).ok()?;
    let mut buf = String::new();
    let mut handle = f.take(MAX_PROC_READ);
    handle.read_to_string(&mut buf).ok()?;
    Some(buf)
}

/// 上次采样快照(增量速率基线)。
struct Prev {
    at: Instant,
    cpu: CpuTimes,
    net: HashMap<String, (u64, u64)>,
    disk: DiskStats,
    /// 上次全局 CPU jiffies(用于进程 CPU% 归一化)。
    cpu_total: u64,
    /// 受监控进程名 -> 上次累计 CPU jiffies。
    proc_jiffies: HashMap<String, u64>,
    /// 上次每核 CPU 时间(用于每核使用率)。
    cpu_cores: Vec<CpuTimes>,
}

pub struct Sampler {
    prev: Option<Prev>,
    watch: Vec<String>,
    watch_services: Vec<String>,
    docker_stats: bool,
    /// 上次各 pid 累计 CPU jiffies(用于 Top 进程 CPU%)。
    prev_pids: HashMap<u32, u64>,
}

impl Sampler {
    #[must_use]
    pub fn new() -> Self {
        Self {
            prev: None,
            watch: Vec::new(),
            watch_services: Vec::new(),
            docker_stats: false,
            prev_pids: HashMap::new(),
        }
    }

    /// 设置受监控进程列表(来自 agent 本地配置)。
    pub fn set_watch(&mut self, watch: Vec<String>) {
        self.watch = watch.into_iter().take(outpost_common::MAX_WATCH_PROCS).collect();
    }

    /// 设置受监控 systemd 服务列表(来自 agent 本地配置)。
    pub fn set_watch_services(&mut self, services: Vec<String>) {
        self.watch_services = services.into_iter().take(outpost_common::MAX_SERVICES).collect();
    }

    /// 设置是否采集 Docker 容器状态(来自 agent 本地配置,默认关闭)。
    pub fn set_docker_stats(&mut self, enabled: bool) {
        self.docker_stats = enabled;
    }

    /// 只读采集容器状态;未开启时不发起任何 socket 连接。
    fn scan_containers(&self) -> Vec<outpost_common::ContainerStat> {
        if !self.docker_stats {
            return Vec::new();
        }
        crate::docker::scan_containers()
    }

    /// 只读查询各服务 active 状态:单次 `systemctl is-active <单元…>`(一行一状态)。
    /// 绝不执行 start/stop/restart 等控制命令。单元名已在配置层严格校验。
    fn scan_services(&self) -> Vec<ServiceStatus> {
        if self.watch_services.is_empty() {
            return Vec::new();
        }
        let output = std::process::Command::new("systemctl")
            .arg("is-active")
            .arg("--") // 选项终止符:防单元名以 '-' 开头被当作选项(纵深防御)
            .args(&self.watch_services)
            .output();
        let states: Vec<String> = match &output {
            Ok(o) => String::from_utf8_lossy(&o.stdout).lines().map(str::trim).map(str::to_string).collect(),
            Err(_) => Vec::new(), // systemctl 不可用:按未知(非 active)上报
        };
        self.watch_services
            .iter()
            .enumerate()
            .map(|(i, n)| ServiceStatus {
                name: n.clone(),
                active: states.get(i).map(String::as_str) == Some("active"),
            })
            .collect()
    }

    /// 扫描全部进程,按 CPU 占用取前 N(附 RSS)。返回 (top 列表, 各 pid 当前 jiffies)。
    fn scan_top_processes(&self, cpu_total_delta: u64) -> (Vec<TopProc>, HashMap<u32, u64>) {
        let mut cur: HashMap<u32, u64> = HashMap::new();
        let mut procs: Vec<TopProc> = Vec::new();
        let Ok(dir) = std::fs::read_dir("/proc") else { return (procs, cur) };
        for entry in dir.flatten() {
            let fname = entry.file_name();
            let Some(name) = fname.to_str() else { continue };
            let Ok(pid) = name.parse::<u32>() else { continue };
            let Some(stat) = read_file(&format!("/proc/{pid}/stat")) else { continue };
            let Some(comm) = parse_pid_comm(&stat) else { continue };
            let Some((jiffies, rss_pages)) = parse_pid_stat(&stat) else { continue };
            cur.insert(pid, jiffies);
            let prev_j = self.prev_pids.get(&pid).copied().unwrap_or(jiffies);
            procs.push(TopProc {
                name: comm,
                cpu_pct: proc_cpu_pct(jiffies.saturating_sub(prev_j), cpu_total_delta),
                rss: rss_pages.saturating_mul(PAGE_SIZE),
            });
        }
        procs.sort_by(|a, b| {
            b.cpu_pct.partial_cmp(&a.cpu_pct).unwrap_or(Ordering::Equal).then(b.rss.cmp(&a.rss))
        });
        procs.truncate(outpost_common::MAX_TOP_PROCS);
        (procs, cur)
    }

    /// 静态主机信息。
    #[must_use]
    pub fn host_info(&self) -> HostInfo {
        let hostname = read_file("/proc/sys/kernel/hostname")
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let kernel = read_file("/proc/sys/kernel/osrelease")
            .map(|s| s.trim().to_string())
            .unwrap_or_default();
        let os = read_file("/etc/os-release")
            .and_then(|s| parse_os_release(&s))
            .unwrap_or_else(|| "Linux".to_string());
        let cores = std::thread::available_parallelism().map_or(0, |n| {
            u32::try_from(n.get()).unwrap_or(u32::MAX)
        });
        let mem_total = read_file("/proc/meminfo").map_or(0, |s| parse_meminfo(&s).total);
        HostInfo {
            hostname,
            os,
            kernel,
            arch: std::env::consts::ARCH.to_string(),
            cores,
            mem_total,
            agent_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }

    /// 采样一次。首次调用建立基线(速率为 0),之后按差值计算。
    #[must_use]
    pub fn sample(&mut self) -> Metrics {
        let now = Instant::now();
        let stat = read_file("/proc/stat");
        let cpu_now = stat.as_deref().and_then(parse_cpu_total);
        let cpu_cores_now = stat.as_deref().map(parse_cpu_per_core).unwrap_or_default();
        let mem = read_file("/proc/meminfo").map(|s| parse_meminfo(&s)).unwrap_or_default();
        let load = read_file("/proc/loadavg").and_then(|s| parse_loadavg(&s));
        let uptime = read_file("/proc/uptime").map_or(0, |s| parse_uptime(&s));
        let net_now: HashMap<String, (u64, u64)> = read_file("/proc/net/dev")
            .map(|s| parse_netdev(&s).into_iter().map(|(n, r, t)| (n, (r, t))).collect())
            .unwrap_or_default();
        let disk_now = read_file("/proc/diskstats").map(|s| parse_diskstats(&s)).unwrap_or_default();
        let cpu_total_now = cpu_now.map_or(0, |c| c.total);
        let proc_now = self.scan_processes();
        // Top 进程 CPU% 需要与上次全局 CPU jiffies 的差
        let cpu_delta_top = self.prev.as_ref().map_or(0, |p| cpu_total_now.saturating_sub(p.cpu_total));
        let (top_procs, cur_pids) = self.scan_top_processes(cpu_delta_top);
        self.prev_pids = cur_pids;
        let (tcp_estab, tcp_listen, tcp_time_wait) = read_tcp_states();

        let (cpu_pct, nets, disk_read_bps, disk_write_bps, disk_read_iops, disk_write_iops, procs_watch, cpu_per_core) =
            match (&self.prev, cpu_now) {
                (Some(p), Some(c)) => {
                    let dt = now.duration_since(p.at).as_secs_f64();
                    // 每核使用率:核数一致才计算(热插拔时跳过本轮)
                    let per_core: Vec<f64> = if !cpu_cores_now.is_empty()
                        && p.cpu_cores.len() == cpu_cores_now.len()
                    {
                        p.cpu_cores
                            .iter()
                            .zip(&cpu_cores_now)
                            .map(|(pc, cc)| cpu_percent(*pc, *cc))
                            .collect()
                    } else {
                        Vec::new()
                    };
                    let mut ifs: Vec<NetIf> = net_now
                        .iter()
                        .map(|(name, &(rx, tx))| {
                            let (prx, ptx) = p.net.get(name).copied().unwrap_or((rx, tx));
                            NetIf {
                                name: name.clone(),
                                rx_bytes: rx,
                                tx_bytes: tx,
                                rx_bps: rate_bps(prx, rx, dt),
                                tx_bps: rate_bps(ptx, tx, dt),
                            }
                        })
                        .collect();
                    ifs.sort_by(|a, b| {
                        (b.rx_bytes.saturating_add(b.tx_bytes))
                            .cmp(&a.rx_bytes.saturating_add(a.tx_bytes))
                    });
                    ifs.truncate(outpost_common::MAX_NETS);
                    let cpu_total_delta = cpu_total_now.saturating_sub(p.cpu_total);
                    let procs_w = proc_now
                        .iter()
                        .map(|(name, cur)| {
                            let prev_j = p.proc_jiffies.get(name).copied().unwrap_or(cur.jiffies);
                            ProcInfo {
                                name: name.clone(),
                                running: cur.count > 0,
                                count: cur.count,
                                cpu_pct: proc_cpu_pct(cur.jiffies.saturating_sub(prev_j), cpu_total_delta),
                                rss: cur.rss,
                            }
                        })
                        .collect();
                    (
                        cpu_percent(p.cpu, c),
                        ifs,
                        rate_bps(p.disk.read_bytes, disk_now.read_bytes, dt),
                        rate_bps(p.disk.write_bytes, disk_now.write_bytes, dt),
                        rate_bps(p.disk.read_ops, disk_now.read_ops, dt),
                        rate_bps(p.disk.write_ops, disk_now.write_ops, dt),
                        procs_w,
                        per_core,
                    )
                }
                _ => (0.0, Vec::new(), 0, 0, 0, 0, Vec::new(), Vec::new()),
            };

        if let Some(c) = cpu_now {
            let proc_jiffies = proc_now.iter().map(|(n, s)| (n.clone(), s.jiffies)).collect();
            self.prev = Some(Prev {
                at: now,
                cpu: c,
                net: net_now,
                disk: disk_now,
                cpu_total: cpu_total_now,
                proc_jiffies,
                cpu_cores: cpu_cores_now,
            });
        }

        let (l1, l5, l15, procs) = load.unwrap_or((0.0, 0.0, 0.0, 0));
        Metrics {
            ts: outpost_common::unix_now(),
            cpu_pct,
            load1: l1,
            load5: l5,
            load15: l15,
            mem_total: mem.total,
            mem_used: mem.total.saturating_sub(mem.available),
            mem_available: mem.available,
            swap_total: mem.swap_total,
            swap_used: mem.swap_used,
            disks: collect_disks(),
            disk_read_bps,
            disk_write_bps,
            nets,
            uptime_secs: uptime,
            procs,
            cpu_temp_c: read_cpu_temp(),
            tcp_conns: read_tcp_conns(),
            disk_read_iops,
            disk_write_iops,
            procs_watch,
            cpu_per_core,
            services: self.scan_services(),
            top_procs,
            tcp_estab,
            tcp_listen,
            tcp_time_wait,
            containers: self.scan_containers(),
        }
    }

    /// 扫描 /proc,聚合受监控进程名的 (jiffies, rss, count)。
    fn scan_processes(&self) -> Vec<(String, ProcAgg)> {
        if self.watch.is_empty() {
            return Vec::new();
        }
        let mut agg: HashMap<String, ProcAgg> = self
            .watch
            .iter()
            .map(|n| (n.clone(), ProcAgg::default()))
            .collect();
        let Ok(dir) = std::fs::read_dir("/proc") else {
            return agg.into_iter().collect();
        };
        for entry in dir.flatten() {
            let fname = entry.file_name();
            let Some(name) = fname.to_str() else { continue };
            if !name.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let Some(stat) = read_file(&format!("/proc/{name}/stat")) else { continue };
            let Some(comm) = parse_pid_comm(&stat) else { continue };
            let Some(slot) = agg.get_mut(&comm) else { continue };
            if let Some((jiffies, rss_pages)) = parse_pid_stat(&stat) {
                slot.jiffies = slot.jiffies.saturating_add(jiffies);
                slot.rss = slot.rss.saturating_add(rss_pages.saturating_mul(PAGE_SIZE));
                slot.count = slot.count.saturating_add(1);
            }
        }
        agg.into_iter().collect()
    }
}

#[derive(Default, Clone, Copy)]
struct ProcAgg {
    jiffies: u64,
    rss: u64,
    count: u32,
}

/// 进程 CPU 占总容量百分比(0..=100)。
fn proc_cpu_pct(proc_delta: u64, total_delta: u64) -> f64 {
    if total_delta == 0 {
        return 0.0;
    }
    #[allow(clippy::cast_precision_loss)]
    let pct = 100.0 * proc_delta as f64 / total_delta as f64;
    pct.clamp(0.0, 100.0)
}

/// 页大小(字节)。sysconf 不便,常见 4KiB;仅用于 RSS 估算。
const PAGE_SIZE: u64 = 4096;

/// 读取 CPU 温度:扫描 thermal_zone*,优先 cpu/pkg/core 类型,否则取首个有效值。
fn read_cpu_temp() -> Option<f64> {
    let mut fallback = None;
    for i in 0..16 {
        let Some(temp) = read_file(&format!("/sys/class/thermal/thermal_zone{i}/temp")) else {
            continue;
        };
        let Some(c) = parse_thermal_millideg(&temp) else { continue };
        let ty = read_file(&format!("/sys/class/thermal/thermal_zone{i}/type")).unwrap_or_default();
        let ty = ty.to_lowercase();
        if ty.contains("cpu") || ty.contains("pkg") || ty.contains("core") || ty.contains("soc") {
            return Some(c);
        }
        fallback.get_or_insert(c);
    }
    fallback
}

/// TCP 连接数:/proc/net/tcp + tcp6。
fn read_tcp_conns() -> Option<u32> {
    let v4 = read_file("/proc/net/tcp").map(|s| parse_tcp_count(&s));
    let v6 = read_file("/proc/net/tcp6").map(|s| parse_tcp_count(&s));
    match (v4, v6) {
        (None, None) => None,
        (a, b) => Some(a.unwrap_or(0).saturating_add(b.unwrap_or(0))),
    }
}

/// TCP 分状态计数(v4+v6 合计):(ESTABLISHED, LISTEN, TIME_WAIT)。
fn read_tcp_states() -> (Option<u32>, Option<u32>, Option<u32>) {
    let (mut e, mut l, mut t) = (0u32, 0u32, 0u32);
    let mut got = false;
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Some(s) = read_file(path) {
            got = true;
            let (pe, pl, pt) = parse_tcp_states(&s);
            e = e.saturating_add(pe);
            l = l.saturating_add(pl);
            t = t.saturating_add(pt);
        }
    }
    if got {
        (Some(e), Some(l), Some(t))
    } else {
        (None, None, None)
    }
}

impl Default for Sampler {
    fn default() -> Self {
        Self::new()
    }
}

/// 各挂载点用量(statvfs;仅本地文件系统白名单,防远程挂载阻塞)。
fn collect_disks() -> Vec<DiskUsage> {
    let Some(mounts) = read_file("/proc/mounts") else { return Vec::new() };
    let mut out = Vec::new();
    for (_dev, mnt, fs) in parse_mounts(&mounts) {
        if let Ok(sv) = rustix::fs::statvfs(mnt.as_str()) {
            let frsize = sv.f_frsize;
            let total = sv.f_blocks.saturating_mul(frsize);
            let free = sv.f_bfree.saturating_mul(frsize);
            if total == 0 {
                continue;
            }
            // inode:f_files 总数,f_ffree 空闲(部分文件系统如 tmpfs 可能为 0)
            let inodes_total = sv.f_files;
            let inodes_used = inodes_total.saturating_sub(sv.f_ffree);
            out.push(DiskUsage {
                mount: mnt,
                fs,
                total,
                used: total.saturating_sub(free),
                inodes_total,
                inodes_used,
            });
        }
        if out.len() >= outpost_common::MAX_DISKS {
            break;
        }
    }
    out
}
