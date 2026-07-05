//! Docker 容器状态只读采集:经本地 UNIX socket(/var/run/docker.sock)直接访问
//! Docker Engine API,不使用 docker CLI(零子进程)、全程只发 GET、不执行任何写操作。
//!
//! 默认关闭:仅当配置显式打开 `docker_stats` 才会被调用(见 [`crate::config::AgentConfig`])。
//! 需要 agent 运行账号在 `docker` 组(等效本机 root),这是 Docker 自身的访问模型决定的,
//! 不存在更低权限的只读方式;由用户自行评估后开启,不在安装脚本里默认配置该组成员关系。
//!
//! 任何环节失败(socket 不存在、无权限、格式异常等)一律静默返回空列表,不影响其余指标。

use outpost_common::ContainerStat;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

const SOCK_PATH: &str = "/var/run/docker.sock";
/// 单次 IO 超时:本机 UNIX socket 正常应为毫秒级;设短超时防 daemon 异常时拖住采样循环。
const IO_TIMEOUT: Duration = Duration::from_millis(800);
/// 单个响应体上限,防异常/恶意 daemon 响应造成内存膨胀。
const MAX_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

// 以下类型解析 Docker Engine API 的原始响应(外部数据,只挑我们需要的字段)。
// 故意不加 deny_unknown_fields:Docker 响应字段远多于此处建模的子集,忽略多余字段是预期行为。
#[derive(serde::Deserialize)]
struct ContainerSummary {
    #[serde(rename = "Id", default)]
    id: String,
    #[serde(rename = "Names", default)]
    names: Vec<String>,
    #[serde(rename = "State", default)]
    state: String,
}

#[derive(serde::Deserialize, Default)]
struct CpuUsage {
    #[serde(default)]
    total_usage: u64,
    #[serde(default)]
    percpu_usage: Vec<u64>,
}
#[derive(serde::Deserialize, Default)]
struct CpuStats {
    #[serde(default)]
    cpu_usage: CpuUsage,
    #[serde(default)]
    system_cpu_usage: u64,
    #[serde(default)]
    online_cpus: u64,
}
#[derive(serde::Deserialize, Default)]
struct MemDetail {
    #[serde(default)]
    cache: u64,
}
#[derive(serde::Deserialize, Default)]
struct MemStats {
    #[serde(default)]
    usage: u64,
    #[serde(default)]
    limit: u64,
    #[serde(default)]
    stats: MemDetail,
}
#[derive(serde::Deserialize, Default)]
struct StatsResp {
    #[serde(default)]
    cpu_stats: CpuStats,
    #[serde(default)]
    precpu_stats: CpuStats,
    #[serde(default)]
    memory_stats: MemStats,
}

/// 响应体 header/body 分界(`\r\n\r\n` 之后的偏移量)。
fn header_body_split(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|i| i + 4)
}

/// 提取 Content-Length(若存在),用于判断何时读够、无需等待对端关闭连接。
fn content_length(buf: &[u8], body_start: usize) -> Option<usize> {
    let headers = std::str::from_utf8(buf.get(..body_start)?).ok()?;
    headers.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.trim().eq_ignore_ascii_case("content-length").then(|| v.trim().parse().ok()).flatten()
    })
}

/// 状态行是否 2xx。
fn status_ok(buf: &[u8]) -> bool {
    let end = buf.iter().position(|&b| b == b'\n').unwrap_or(0);
    buf.get(..end).is_some_and(|s| std::str::from_utf8(s).is_ok_and(|l| l.contains(" 2")))
}

/// 最简 HTTP/1.1 GET(经 UNIX socket),返回响应体字节;任何失败均为 None。
fn http_get(path: &str) -> Option<Vec<u8>> {
    let mut sock = UnixStream::connect(SOCK_PATH).ok()?;
    sock.set_read_timeout(Some(IO_TIMEOUT)).ok()?;
    sock.set_write_timeout(Some(IO_TIMEOUT)).ok()?;
    let req =
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nAccept: application/json\r\nConnection: close\r\n\r\n");
    sock.write_all(req.as_bytes()).ok()?;

    let mut buf = Vec::with_capacity(4096);
    let mut chunk = [0u8; 4096];
    loop {
        let n = sock.read(&mut chunk).ok()?;
        if n == 0 {
            break;
        }
        buf.extend_from_slice(chunk.get(..n)?);
        if buf.len() > MAX_RESPONSE_BYTES {
            return None;
        }
        if let Some(body_start) = header_body_split(&buf) {
            if let Some(len) = content_length(&buf, body_start) {
                if buf.len() >= body_start + len {
                    break;
                }
            }
        }
    }
    if !status_ok(&buf) {
        return None;
    }
    let body_start = header_body_split(&buf)?;
    Some(buf.get(body_start..)?.to_vec())
}

/// 容器 ID 形态校验(防御性:即便来自 Docker 自身响应而非用户输入,拼 URL 前仍校验)。
fn valid_container_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 128 && id.bytes().all(|b| b.is_ascii_alphanumeric())
}

#[allow(clippy::cast_precision_loss)]
fn stats_for(id: &str) -> Option<(f64, u64, u64)> {
    if !valid_container_id(id) {
        return None;
    }
    let body = http_get(&format!("/containers/{id}/stats?stream=false"))?;
    let s: StatsResp = serde_json::from_slice(&body).ok()?;
    let cpu_delta = s.cpu_stats.cpu_usage.total_usage.saturating_sub(s.precpu_stats.cpu_usage.total_usage);
    let sys_delta = s.cpu_stats.system_cpu_usage.saturating_sub(s.precpu_stats.system_cpu_usage);
    let online = if s.cpu_stats.online_cpus > 0 {
        s.cpu_stats.online_cpus
    } else {
        (s.cpu_stats.cpu_usage.percpu_usage.len() as u64).max(1)
    };
    let cpu_pct =
        if sys_delta > 0 && cpu_delta > 0 { (cpu_delta as f64 / sys_delta as f64) * (online as f64) * 100.0 } else { 0.0 };
    let mem_used = s.memory_stats.usage.saturating_sub(s.memory_stats.stats.cache);
    Some((cpu_pct, mem_used, s.memory_stats.limit))
}

/// 采集本机运行中的容器状态(list + 逐容器 stats)。静默降级:任何一步失败都返回空列表。
#[must_use]
pub fn scan_containers() -> Vec<ContainerStat> {
    let Some(body) = http_get("/containers/json") else { return Vec::new() };
    let Ok(list) = serde_json::from_slice::<Vec<ContainerSummary>>(&body) else { return Vec::new() };

    list.into_iter()
        .take(outpost_common::MAX_CONTAINERS)
        .map(|c| {
            let name = c
                .names
                .first()
                .map(|n| n.trim_start_matches('/').to_string())
                .filter(|n| !n.is_empty())
                .unwrap_or_else(|| c.id.get(..12).unwrap_or(&c.id).to_string());
            let (cpu_pct, mem_used, mem_limit) = stats_for(&c.id).unwrap_or((0.0, 0, 0));
            ContainerStat { name, state: c.state, cpu_pct, mem_used, mem_limit }
        })
        .collect()
}
