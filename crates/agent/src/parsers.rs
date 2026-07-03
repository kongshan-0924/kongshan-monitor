//! /proc 文本解析器:全部为**纯函数**(&str 入参),便于跨平台单测与恶意输入测试。
//! 约束(规范第 5 节):任何单项解析失败只降级为 None,绝不 panic;
//! 所有差值/速率计算使用 saturating/checked,处理计数器回绕。

/// CPU 累计时间(jiffies)。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuTimes {
    pub idle: u64,
    pub total: u64,
}

/// 解析 /proc/stat 首行 `cpu  user nice system idle iowait irq softirq steal ...`。
#[must_use]
pub fn parse_cpu_total(stat: &str) -> Option<CpuTimes> {
    let line = stat.lines().find(|l| l.starts_with("cpu "))?;
    let mut fields = line.split_whitespace().skip(1);
    let mut vals = [0u64; 8];
    for v in &mut vals {
        *v = fields.next()?.parse().ok()?;
    }
    let idle = vals.get(3)?.saturating_add(*vals.get(4)?); // idle + iowait
    let total = vals.iter().fold(0u64, |a, b| a.saturating_add(*b));
    Some(CpuTimes { idle, total })
}

/// 内存信息(bytes)。
#[derive(Debug, Default, Clone, Copy)]
pub struct MemInfo {
    pub total: u64,
    pub available: u64,
    pub swap_total: u64,
    pub swap_used: u64,
}

/// 解析 /proc/meminfo(kB 单位 → bytes,乘法用 saturating)。
#[must_use]
pub fn parse_meminfo(s: &str) -> MemInfo {
    let mut total = 0u64;
    let mut avail = 0u64;
    let mut free = 0u64;
    let mut buffers = 0u64;
    let mut cached = 0u64;
    let mut swap_total = 0u64;
    let mut swap_free = 0u64;
    for line in s.lines() {
        let mut it = line.split_whitespace();
        let key = it.next().unwrap_or("");
        let val: u64 = it.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        let bytes = val.saturating_mul(1024);
        match key {
            "MemTotal:" => total = bytes,
            "MemAvailable:" => avail = bytes,
            "MemFree:" => free = bytes,
            "Buffers:" => buffers = bytes,
            "Cached:" => cached = bytes,
            "SwapTotal:" => swap_total = bytes,
            "SwapFree:" => swap_free = bytes,
            _ => {}
        }
    }
    if avail == 0 {
        // 老内核无 MemAvailable:粗略估算
        avail = free.saturating_add(buffers).saturating_add(cached);
    }
    MemInfo {
        total,
        available: avail.min(total),
        swap_total,
        swap_used: swap_total.saturating_sub(swap_free),
    }
}

/// 解析 /proc/loadavg:`0.00 0.01 0.05 1/123 456` → (l1,l5,l15,总进程数)。
#[must_use]
pub fn parse_loadavg(s: &str) -> Option<(f64, f64, f64, u32)> {
    let mut it = s.split_whitespace();
    let l1: f64 = it.next()?.parse().ok()?;
    let l5: f64 = it.next()?.parse().ok()?;
    let l15: f64 = it.next()?.parse().ok()?;
    let procs = it
        .next()
        .and_then(|f| f.split('/').nth(1))
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    if !(l1.is_finite() && l5.is_finite() && l15.is_finite()) {
        return None;
    }
    Some((l1.max(0.0), l5.max(0.0), l15.max(0.0), procs))
}

/// 解析 /proc/uptime 首字段(秒)。
#[must_use]
pub fn parse_uptime(s: &str) -> u64 {
    s.split_whitespace()
        .next()
        .and_then(|v| v.split('.').next())
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
}

/// 解析 /proc/net/dev → Vec<(iface, rx_bytes, tx_bytes)>,跳过 lo。
#[must_use]
pub fn parse_netdev(s: &str) -> Vec<(String, u64, u64)> {
    let mut out = Vec::new();
    for line in s.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else { continue };
        let name = name.trim();
        if name.is_empty() || name == "lo" || name.len() > 32 {
            continue;
        }
        let mut it = rest.split_whitespace();
        let rx: u64 = it.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        let tx: u64 = it.nth(7).and_then(|v| v.parse().ok()).unwrap_or(0);
        out.push((name.to_string(), rx, tx));
        if out.len() >= 32 {
            break;
        }
    }
    out
}

/// 物理整盘判定(排除分区),用于 /proc/diskstats 汇总。
#[must_use]
pub fn is_physical_disk(name: &str) -> bool {
    if name.len() > 24 {
        return false;
    }
    // sdX / vdX / xvdX / hdX:前缀 + 纯字母
    for p in ["sd", "vd", "xvd", "hd"] {
        if let Some(rest) = name.strip_prefix(p) {
            return !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_lowercase());
        }
    }
    // nvmeXnY(不含 p 分区后缀)
    if let Some(rest) = name.strip_prefix("nvme") {
        let ok_shape = rest.bytes().all(|b| b.is_ascii_digit() || b == b'n');
        return ok_shape && rest.contains('n') && !rest.is_empty();
    }
    // mmcblkX(不含 pY)
    if let Some(rest) = name.strip_prefix("mmcblk") {
        return !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit());
    }
    false
}

/// /proc/diskstats 汇总:读字节、写字节、读操作数、写操作数(全部物理盘累计)。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DiskStats {
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_ops: u64,
    pub write_ops: u64,
}

/// 解析 /proc/diskstats(字段:major minor name reads_completed reads_merged
/// sectors_read ms_reading writes_completed ...)。
#[must_use]
pub fn parse_diskstats(s: &str) -> DiskStats {
    let mut d = DiskStats::default();
    for line in s.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        // 需要至少到 sectors_written(索引 9)
        let (Some(name), Some(rc), Some(sr), Some(wc), Some(sw)) =
            (f.get(2), f.get(3), f.get(5), f.get(7), f.get(9))
        else {
            continue;
        };
        if !is_physical_disk(name) {
            continue;
        }
        let rc: u64 = rc.parse().unwrap_or(0);
        let sr: u64 = sr.parse().unwrap_or(0);
        let wc: u64 = wc.parse().unwrap_or(0);
        let sw: u64 = sw.parse().unwrap_or(0);
        d.read_bytes = d.read_bytes.saturating_add(sr.saturating_mul(512));
        d.write_bytes = d.write_bytes.saturating_add(sw.saturating_mul(512));
        d.read_ops = d.read_ops.saturating_add(rc);
        d.write_ops = d.write_ops.saturating_add(wc);
    }
    d
}

/// 统计 /proc/net/tcp[6] 中的连接条目数(去表头)。
#[must_use]
pub fn parse_tcp_count(s: &str) -> u32 {
    let n = s.lines().skip(1).filter(|l| l.contains(':')).count();
    u32::try_from(n).unwrap_or(u32::MAX)
}

/// 统计 /proc/net/tcp[6] 分状态计数:(ESTABLISHED 01, LISTEN 0A, TIME_WAIT 06)。
/// 状态码为每行第 4 列(sl local rem st …)。
#[must_use]
pub fn parse_tcp_states(s: &str) -> (u32, u32, u32) {
    let (mut estab, mut listen, mut tw) = (0u32, 0u32, 0u32);
    for line in s.lines().skip(1) {
        match line.split_whitespace().nth(3) {
            Some("01") => estab = estab.saturating_add(1),
            Some("0A") => listen = listen.saturating_add(1),
            Some("06") => tw = tw.saturating_add(1),
            _ => {}
        }
    }
    (estab, listen, tw)
}

/// 解析热区温度文件(毫摄氏度 → 摄氏度)。范围外返回 None。
#[must_use]
pub fn parse_thermal_millideg(s: &str) -> Option<f64> {
    let v: i64 = s.trim().parse().ok()?;
    #[allow(clippy::cast_precision_loss)]
    let c = v as f64 / 1000.0;
    (-40.0..=150.0).contains(&c).then_some(c)
}

/// 解析 /proc/[pid]/stat 的 utime+stime(jiffies)与 rss(页数)。
/// 注意 comm 字段可能含空格/括号,需从末尾的 ')' 之后开始切分。
#[must_use]
pub fn parse_pid_stat(s: &str) -> Option<(u64, u64)> {
    let rparen = s.rfind(')')?;
    let rest = s.get(rparen + 2..)?; // 跳过 ") "
    let f: Vec<&str> = rest.split_whitespace().collect();
    // 从 state(索引0=第3字段)起:utime=第14字段→索引11,stime→索引12,rss→索引21
    let utime: u64 = f.get(11)?.parse().ok()?;
    let stime: u64 = f.get(12)?.parse().ok()?;
    let rss_pages: u64 = f.get(21)?.parse().ok()?;
    Some((utime.saturating_add(stime), rss_pages))
}

/// 从 /proc/[pid]/stat 提取 comm(括号内进程名)。
#[must_use]
pub fn parse_pid_comm(s: &str) -> Option<String> {
    let l = s.find('(')?;
    let r = s.rfind(')')?;
    if r > l {
        s.get(l + 1..r).map(str::to_string)
    } else {
        None
    }
}

/// 解析 /etc/os-release 的 PRETTY_NAME。
#[must_use]
pub fn parse_os_release(s: &str) -> Option<String> {
    for line in s.lines() {
        if let Some(v) = line.strip_prefix("PRETTY_NAME=") {
            let v = v.trim().trim_matches('"');
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// 解析 /proc/mounts → Vec<(device, mountpoint, fstype)>,仅保留本地常见文件系统
/// (排除网络/虚拟 fs,避免 statvfs 在挂死的远程挂载上阻塞)。
#[must_use]
pub fn parse_mounts(s: &str) -> Vec<(String, String, String)> {
    const ALLOWED: &[&str] =
        &["ext2", "ext3", "ext4", "xfs", "btrfs", "f2fs", "vfat", "exfat", "zfs"];
    let mut out: Vec<(String, String, String)> = Vec::new();
    for line in s.lines() {
        let mut it = line.split_whitespace();
        let (Some(dev), Some(mnt), Some(fs)) = (it.next(), it.next(), it.next()) else {
            continue;
        };
        if !ALLOWED.contains(&fs) || mnt.len() > 128 {
            continue;
        }
        // 同一设备多个挂载点:保留最短路径
        if let Some(e) = out.iter_mut().find(|e| e.0 == dev) {
            if mnt.len() < e.1.len() {
                e.1 = mnt.to_string();
            }
            continue;
        }
        out.push((dev.to_string(), mnt.to_string(), fs.to_string()));
        if out.len() >= 16 {
            break;
        }
    }
    out
}

/// 速率:两次采样差 / dt,处理回绕(cur < prev → 0)。
#[must_use]
pub fn rate_bps(prev: u64, cur: u64, dt_secs: f64) -> u64 {
    if dt_secs < 0.2 || cur < prev {
        return 0;
    }
    let delta = cur.saturating_sub(prev);
    #[allow(clippy::cast_precision_loss, clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let bps = (delta as f64 / dt_secs) as u64;
    bps
}

/// 解析每核 CPU 时间(`cpu0`, `cpu1`, …),按核序返回;排除聚合行 `cpu `。
#[must_use]
pub fn parse_cpu_per_core(stat: &str) -> Vec<CpuTimes> {
    let mut out = Vec::new();
    for line in stat.lines() {
        let Some(rest) = line.strip_prefix("cpu") else { continue };
        // 仅接受 "cpuN"(N 为数字);聚合行 "cpu " 的 rest 以空格开头,跳过
        if !rest.as_bytes().first().is_some_and(u8::is_ascii_digit) {
            continue;
        }
        let mut fields = rest.split_whitespace().skip(1); // 跳过核号
        let mut vals = [0u64; 8];
        let mut ok = true;
        for v in &mut vals {
            match fields.next().and_then(|s| s.parse().ok()) {
                Some(x) => *v = x,
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if !ok {
            continue;
        }
        let idle = vals.get(3).copied().unwrap_or(0).saturating_add(vals.get(4).copied().unwrap_or(0));
        let total = vals.iter().fold(0u64, |a, b| a.saturating_add(*b));
        out.push(CpuTimes { idle, total });
    }
    out
}

/// CPU 使用率(%):两次 jiffies 快照差。
#[must_use]
pub fn cpu_percent(prev: CpuTimes, cur: CpuTimes) -> f64 {
    let total_d = cur.total.saturating_sub(prev.total);
    let idle_d = cur.idle.saturating_sub(prev.idle);
    if total_d == 0 {
        return 0.0;
    }
    #[allow(clippy::cast_precision_loss)]
    let pct = 100.0 * (1.0 - idle_d as f64 / total_d as f64);
    pct.clamp(0.0, 100.0)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn cpu_parse_and_percent() {
        let a = parse_cpu_total("cpu  100 0 100 700 100 0 0 0 0 0\ncpu0 1 2 3 4 5 6 7 8\n").unwrap();
        assert_eq!(a.idle, 800);
        assert_eq!(a.total, 1000);
        let b = CpuTimes { idle: 880, total: 1100 };
        let pct = cpu_percent(a, b);
        assert!((pct - 20.0).abs() < 0.01);
        // 回绕 → 0,不 panic
        assert_eq!(cpu_percent(b, a), 0.0);
        // 畸形输入
        assert!(parse_cpu_total("garbage").is_none());
        assert!(parse_cpu_total("cpu  1 2 notanumber 4 5 6 7 8").is_none());
    }

    #[test]
    fn meminfo_parse() {
        let m = parse_meminfo(
            "MemTotal:       1000 kB\nMemAvailable:    400 kB\nSwapTotal:  200 kB\nSwapFree:  150 kB\n",
        );
        assert_eq!(m.total, 1_024_000);
        assert_eq!(m.available, 409_600);
        assert_eq!(m.swap_used, 51_200);
        // 溢出输入不 panic
        let big = parse_meminfo("MemTotal: 99999999999999999999 kB\n");
        assert_eq!(big.total, 0); // parse 失败 → 0,降级
    }

    #[test]
    fn loadavg_and_uptime() {
        let (l1, _, _, procs) = parse_loadavg("0.52 0.58 0.59 2/467 12345\n").unwrap();
        assert!((l1 - 0.52).abs() < 1e-9);
        assert_eq!(procs, 467);
        assert!(parse_loadavg("").is_none());
        assert_eq!(parse_uptime("88888.77 12345.66\n"), 88888);
        assert_eq!(parse_uptime("bad"), 0);
    }

    #[test]
    fn netdev_parse_skips_lo() {
        let s = "Inter-|Receive\n face |bytes packets errs\n  lo: 100 1 0 0 0 0 0 0 200 2 0 0 0 0 0 0\n  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n";
        let v = parse_netdev(s);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0], ("eth0".to_string(), 1000, 2000));
    }

    #[test]
    fn disk_name_filter() {
        assert!(is_physical_disk("sda"));
        assert!(is_physical_disk("vdb"));
        assert!(is_physical_disk("nvme0n1"));
        assert!(is_physical_disk("mmcblk0"));
        assert!(!is_physical_disk("sda1"));
        assert!(!is_physical_disk("nvme0n1p2"));
        assert!(!is_physical_disk("mmcblk0p1"));
        assert!(!is_physical_disk("loop0"));
        assert!(!is_physical_disk("dm-0"));
        assert!(!is_physical_disk(&"x".repeat(100)));
    }

    #[test]
    fn diskstats_parse() {
        //                          reads rm  sect  ms  writes wm  sect  ms
        let s = "   8   0 sda 100 0 2048 50 200 0 4096 80 0 0 0\n   8   1 sda1 1 0 10 1 1 0 10 1 0 0 0\n";
        let d = parse_diskstats(s);
        assert_eq!(d.read_bytes, 2048 * 512);
        assert_eq!(d.write_bytes, 4096 * 512);
        assert_eq!(d.read_ops, 100);
        assert_eq!(d.write_ops, 200);
    }

    #[test]
    fn tcp_count_and_thermal() {
        let tcp = "  sl local rem st\n   0: 0100007F:1F90 00000000:0000 0A\n   1: 0100007F:0035 00000000:0000 0A\n";
        assert_eq!(parse_tcp_count(tcp), 2);
        assert_eq!(parse_tcp_count("header only\n"), 0);
        assert_eq!(parse_thermal_millideg("45000\n"), Some(45.0));
        assert_eq!(parse_thermal_millideg("999000"), None); // 超范围
        assert_eq!(parse_thermal_millideg("x"), None);
    }

    #[test]
    fn pid_stat_handles_comm_with_spaces() {
        // comm 含空格与括号,须从末尾 ')' 之后切分。
        // rest 从 state(字段3)起:index11=utime, index12=stime, index21=rss。
        let rest = "S 1 0 0 0 -1 0 0 0 0 0 500 250 0 0 0 0 0 0 0 0 1000 x";
        let s = format!("1234 (my (weird) proc) {rest}");
        let (cpu, rss) = parse_pid_stat(&s).unwrap();
        assert_eq!(cpu, 750); // utime 500 + stime 250
        assert_eq!(rss, 1000);
        assert_eq!(parse_pid_comm(&s).as_deref(), Some("my (weird) proc"));
    }

    #[test]
    fn mounts_whitelist_and_dedupe() {
        let s = "/dev/vda1 / ext4 rw 0 0\n/dev/vda1 /var/lib ext4 rw 0 0\nproc /proc proc rw 0 0\n1.2.3.4:/share /mnt/nfs nfs4 rw 0 0\n";
        let v = parse_mounts(s);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].1, "/"); // 最短挂载点
    }

    #[test]
    fn rate_handles_wrap_and_small_dt() {
        assert_eq!(rate_bps(1000, 2000, 1.0), 1000);
        assert_eq!(rate_bps(2000, 1000, 1.0), 0); // 回绕
        assert_eq!(rate_bps(0, 10_000, 0.01), 0); // dt 过小
    }

    #[test]
    fn os_release_parse() {
        assert_eq!(
            parse_os_release("NAME=Debian\nPRETTY_NAME=\"Debian GNU/Linux 13\"\n").as_deref(),
            Some("Debian GNU/Linux 13")
        );
        assert!(parse_os_release("").is_none());
    }
}
