//! 出站通知客户端:向用户配置的 Webhook 发送 JSON。
//!
//! 安全设计(SSRF 纵深防御,规范"不信任外部输入"):
//! - 仅允许 https,禁止明文。
//! - **自行解析 DNS 并逐个校验目标 IP**:默认拒绝回环/私网/链路本地/CGNAT/
//!   文档/保留/组播等非全局地址(除非配置显式 `allow_private_targets`)。
//! - **连接到已校验的具体 IP**(而非再次解析域名),消除 DNS-rebinding / TOCTOU。
//! - 不跟随任何重定向(手写 HTTP/1.1,只发一个请求)。
//! - 连接/读写超时;响应读取限长;请求体限长。
//! - 通过 rustls 校验服务端证书(webpki 根),SNI 用原始主机名。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::{ClientConfig, RootCertStore};
use tokio_rustls::TlsConnector;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(8);
const IO_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_BODY: usize = 16 * 1024;
const MAX_RESP: usize = 16 * 1024;

/// 判断 IPv4 是否为可安全外联的全局地址。
fn ipv4_global(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    !(ip.is_loopback()            // 127/8
        || ip.is_private()        // 10/8, 172.16/12, 192.168/16
        || ip.is_link_local()     // 169.254/16
        || ip.is_broadcast()      // 255.255.255.255
        || ip.is_documentation()  // 192.0.2/24, 198.51.100/24, 203.0.113/24
        || ip.is_unspecified()    // 0.0.0.0
        || o[0] == 0              // 0/8
        || (o[0] == 100 && (o[1] & 0xc0) == 64) // 100.64/10 CGNAT
        || (o[0] == 198 && (o[1] & 0xfe) == 18) // 198.18/15 benchmarking
        || (o[0] == 192 && o[1] == 0 && o[2] == 0) // 192.0.0/24
        || o[0] >= 240            // 240/4 reserved + 255
        || ip.is_multicast())     // 224/4
}

/// 判断 IPv6 是否为可安全外联的全局地址。
fn ipv6_global(ip: Ipv6Addr) -> bool {
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    let s = ip.segments();
    // 链路本地 fe80::/10
    if (s[0] & 0xffc0) == 0xfe80 {
        return false;
    }
    // 唯一本地 fc00::/7
    if (s[0] & 0xfe00) == 0xfc00 {
        return false;
    }
    // 文档 2001:db8::/32
    if s[0] == 0x2001 && s[1] == 0x0db8 {
        return false;
    }
    // IPv4-mapped / -compatible:按其内嵌 v4 规则判断(通常应拒绝)
    if let Some(v4) = ip.to_ipv4_mapped() {
        return ipv4_global(v4);
    }
    if let Some(v4) = ip.to_ipv4() {
        return ipv4_global(v4);
    }
    true
}

fn ip_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => ipv4_global(v),
        IpAddr::V6(v) => ipv6_global(v),
    }
}

/// 解析 URL:必须 https;返回 (host, port, path_and_query)。不引入 url 依赖。
fn parse_https(url: &str) -> Result<(String, u16, String), &'static str> {
    let rest = url.strip_prefix("https://").ok_or("仅允许 https:// 的 Webhook")?;
    if rest.is_empty() || url.len() > 2048 {
        return Err("URL 非法或过长");
    }
    let (authority, path) = match rest.find('/') {
        Some(i) => (rest.get(..i).unwrap_or(rest), rest.get(i..).unwrap_or("/")),
        None => (rest, "/"),
    };
    // 去掉可能的用户信息(user@host)——一律拒绝,避免歧义
    if authority.contains('@') {
        return Err("URL 不得包含用户信息");
    }
    let (host, port) = if let Some(h) = authority.strip_prefix('[') {
        // IPv6 字面量 [::1]:443
        let end = h.find(']').ok_or("IPv6 地址格式错误")?;
        let host = h.get(..end).unwrap_or("");
        let port = h.get(end + 1..).and_then(|p| p.strip_prefix(':')).and_then(|p| p.parse().ok()).unwrap_or(443);
        (host.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().map_err(|_| "端口非法")?),
            None => (authority.to_string(), 443u16),
        }
    };
    if host.is_empty() || host.len() > 255 {
        return Err("主机名非法");
    }
    // 路径中控制字符会破坏请求行(CRLF 注入),拒绝
    if path.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("路径含非法字符");
    }
    Ok((host, port, path.to_string()))
}

/// 选出一个通过 SSRF 校验的目标地址。
pub(crate) async fn resolve_checked(host: &str, port: u16, allow_private: bool) -> Result<SocketAddr, String> {
    // 主机名本身是 IP 字面量?直接校验,不做 DNS
    if let Ok(ip) = host.parse::<IpAddr>() {
        if !allow_private && !ip_global(ip) {
            return Err("目标为非公网地址,已拒绝(SSRF 防护)".into());
        }
        return Ok(SocketAddr::new(ip, port));
    }
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| "DNS 解析失败".to_string())?;
    for addr in addrs {
        if allow_private || ip_global(addr.ip()) {
            return Ok(addr);
        }
    }
    Err("目标解析到非公网地址,已拒绝(SSRF 防护)".into())
}

pub(crate) fn tls_config() -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(ClientConfig::builder().with_root_certificates(roots).with_no_client_auth())
}

/// POST 一段 JSON 到 Webhook。成功返回 HTTP 状态码。
///
/// # Errors
/// URL 非法、SSRF 校验失败、连接/TLS/超时失败、响应异常。
pub async fn post_json(url: &str, body: &str, allow_private: bool) -> Result<u16, String> {
    if body.len() > MAX_BODY {
        return Err("通知内容过大".into());
    }
    let (host, port, path) = parse_https(url).map_err(str::to_string)?;
    let addr = resolve_checked(&host, port, allow_private).await?;

    let server_name = ServerName::try_from(host.clone()).map_err(|_| "主机名不是合法 SNI".to_string())?;
    let connector = TlsConnector::from(tls_config());

    let fut = async {
        let tcp = TcpStream::connect(addr).await.map_err(|e| format!("连接失败: {e}"))?;
        tcp.set_nodelay(true).ok();
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| format!("TLS 握手失败: {e}"))?;

        let req = format!(
            "POST {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: outpost/0.1\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        tls.write_all(req.as_bytes()).await.map_err(|e| format!("发送失败: {e}"))?;
        tls.flush().await.ok();

        // 只读首部足够解析状态行;限长防止大响应耗内存
        let mut buf = Vec::with_capacity(1024);
        let mut chunk = [0u8; 1024];
        loop {
            let n = tls.read(&mut chunk).await.map_err(|e| format!("读取失败: {e}"))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
            if buf.len() >= MAX_RESP || buf.windows(4).any(|w| w == b"\r\n\r\n") {
                break;
            }
        }
        let head = String::from_utf8_lossy(&buf);
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse::<u16>().ok())
            .ok_or_else(|| "响应无有效状态行".to_string())?;
        Ok::<u16, String>(status)
    };

    let connect_capped = tokio::time::timeout(CONNECT_TIMEOUT.saturating_add(IO_TIMEOUT), fut)
        .await
        .map_err(|_| "请求超时".to_string())??;
    Ok(connect_capped)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn rejects_non_global_ipv4() {
        for s in ["127.0.0.1", "10.0.0.5", "172.16.3.4", "192.168.1.1", "169.254.1.1", "100.64.0.1", "0.0.0.0", "198.18.0.1", "192.0.0.1", "240.0.0.1"] {
            let ip: Ipv4Addr = s.parse().unwrap();
            assert!(!ipv4_global(ip), "{s} 应被拒绝");
        }
        for s in ["1.1.1.1", "8.8.8.8", "203.0.114.1", "93.184.216.34"] {
            let ip: Ipv4Addr = s.parse().unwrap();
            assert!(ipv4_global(ip), "{s} 应允许");
        }
    }

    #[test]
    fn rejects_non_global_ipv6() {
        for s in ["::1", "::", "fe80::1", "fc00::1", "fd12::1", "2001:db8::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1"] {
            let ip: Ipv6Addr = s.parse().unwrap();
            assert!(!ipv6_global(ip), "{s} 应被拒绝");
        }
        assert!(ipv6_global("2606:4700:4700::1111".parse().unwrap()));
    }

    #[test]
    fn parse_https_variants() {
        assert_eq!(parse_https("https://a.com/x").unwrap(), ("a.com".into(), 443, "/x".into()));
        assert_eq!(parse_https("https://a.com:8443/x?y=1").unwrap(), ("a.com".into(), 8443, "/x?y=1".into()));
        assert_eq!(parse_https("https://a.com").unwrap().2, "/");
        assert!(parse_https("http://a.com").is_err()); // 明文
        assert!(parse_https("https://user@a.com/").is_err()); // 用户信息
        assert!(parse_https("https://a.com/x\r\nHost: evil").is_err()); // CRLF 注入
        assert!(parse_https("ftp://a.com").is_err());
    }
}
