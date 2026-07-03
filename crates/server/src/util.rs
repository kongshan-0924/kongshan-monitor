//! 通用小工具:哈希、常量时间比较、CSPRNG token、Cookie 解析、客户端 IP 提取。

use axum::http::{header, HeaderMap};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use subtle::ConstantTimeEq;

pub use outpost_common::{to_hex, unix_now};

/// SHA-256 → 小写 hex。
pub fn sha256_hex(data: &[u8]) -> String {
    to_hex(&Sha256::digest(data))
}

/// 常量时间字符串比较(先长度检查——长度不是秘密;内容用 `subtle`)。
/// 用于所有 token / 密钥哈希比对(规范 6.3.4)。
pub fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// 生成 32 字节 CSPRNG 随机值的 hex(64 字符)。
/// 使用 OS 熵源(规范第 7 节:token 必须用 CSPRNG)。
///
/// # Errors
/// 操作系统熵源不可用时返回错误(不 panic)。
pub fn gen_token_hex() -> Result<String, &'static str> {
    let mut buf = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut buf)
        .map_err(|_| "os rng unavailable")?;
    Ok(to_hex(&buf))
}

/// 从 Cookie 头中提取指定名称的值(精确匹配名称)。
pub fn cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    let raw = headers.get(header::COOKIE)?.to_str().ok()?;
    for part in raw.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix(name) {
            if let Some(v) = rest.strip_prefix('=') {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

/// 解析客户端真实 IP。
///
/// 仅当对端地址在 `trusted_proxies` 中时才信任 `X-Real-IP`
/// (由我们自己的 nginx 设置),否则一律用 TCP 对端地址,
/// 防止伪造头绕过限速(规范 6.1.9)。
pub fn client_ip(
    peer: SocketAddr,
    headers: &HeaderMap,
    trusted_proxies: &[IpAddr],
) -> IpAddr {
    if trusted_proxies.contains(&peer.ip()) {
        if let Some(v) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
            if let Ok(ip) = v.trim().parse::<IpAddr>() {
                return ip;
            }
        }
    }
    peer.ip()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use outpost_common::is_lower_hex;

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq("abc", "abc"));
        assert!(!ct_eq("abc", "abd"));
        assert!(!ct_eq("abc", "ab"));
        assert!(!ct_eq("", "a"));
    }

    #[test]
    fn cookie_parse_exact_name() {
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            HeaderValue::from_static("foo=1; op_session=abcd; xop_session=evil"),
        );
        assert_eq!(cookie_value(&h, "op_session").as_deref(), Some("abcd"));
        assert_eq!(cookie_value(&h, "missing"), None);
    }

    #[test]
    fn client_ip_only_trusts_configured_proxy() {
        let mut h = HeaderMap::new();
        h.insert("x-real-ip", HeaderValue::from_static("9.9.9.9"));
        let peer: SocketAddr = "8.8.8.8:1".parse().unwrap();
        let lo: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let trusted: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap()];
        // 不可信对端伪造头 → 忽略
        assert_eq!(client_ip(peer, &h, &trusted).to_string(), "8.8.8.8");
        // 可信代理 → 采用
        assert_eq!(client_ip(lo, &h, &trusted).to_string(), "9.9.9.9");
        // 可信代理但头非法 → 回退对端
        let mut h2 = HeaderMap::new();
        h2.insert("x-real-ip", HeaderValue::from_static("not-an-ip"));
        assert_eq!(client_ip(lo, &h2, &trusted).to_string(), "127.0.0.1");
    }

    #[test]
    fn token_gen_is_hex64() {
        let t = gen_token_hex().unwrap();
        assert_eq!(t.len(), 64);
        assert!(is_lower_hex(&t));
    }
}
