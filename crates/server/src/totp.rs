//! TOTP(RFC 6238,HMAC-SHA1,6 位,30 秒步长)与 base32 编解码,零外部 TOTP 依赖。
//! 校验采用常量时间比较并允许 ±1 时间窗容忍时钟漂移。

use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

const STEP: u64 = 30;
const DIGITS: u32 = 6;
const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// 将字节编码为无填充 base32(RFC 4648)。
#[must_use]
pub fn base32_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for &b in data {
        buffer = (buffer << 8) | u32::from(b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            let idx = ((buffer >> bits) & 0x1f) as usize;
            out.push(char::from(*ALPHABET.get(idx).unwrap_or(&b'A')));
        }
    }
    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(char::from(*ALPHABET.get(idx).unwrap_or(&b'A')));
    }
    out
}

/// 解码无填充 base32(忽略大小写与空格);非法字符返回 None。
#[must_use]
pub fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::new();
    for c in s.chars() {
        if c == ' ' || c == '=' {
            continue;
        }
        let up = c.to_ascii_uppercase();
        let val = ALPHABET.iter().position(|&a| char::from(a) == up)? as u32;
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    Some(out)
}

/// 生成给定计数器的 HOTP 6 位码。
fn hotp(secret: &[u8], counter: u64) -> Option<u32> {
    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(secret).ok()?;
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (*digest.last()? & 0x0f) as usize;
    let b0 = u32::from(*digest.get(offset)?) & 0x7f;
    let b1 = u32::from(*digest.get(offset + 1)?);
    let b2 = u32::from(*digest.get(offset + 2)?);
    let b3 = u32::from(*digest.get(offset + 3)?);
    let bin = (b0 << 24) | (b1 << 16) | (b2 << 8) | b3;
    Some(bin % 10u32.pow(DIGITS))
}

/// 校验 6 位 TOTP;`now` 为 Unix 秒。允许 ±1 步窗口。常量时间比较。
#[must_use]
pub fn verify(secret_b32: &str, code: &str, now: i64) -> bool {
    let code = code.trim();
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let Some(secret) = base32_decode(secret_b32) else {
        return false;
    };
    if secret.len() < 10 {
        return false;
    }
    let t = if now < 0 { 0u64 } else { now as u64 } / STEP;
    for delta in [-1i64, 0, 1] {
        let counter = if delta < 0 { t.wrapping_sub(1) } else { t.wrapping_add(delta as u64) };
        if let Some(expect) = hotp(&secret, counter) {
            let exp_str = format!("{expect:0width$}", width = DIGITS as usize);
            if exp_str.as_bytes().ct_eq(code.as_bytes()).into() {
                return true;
            }
        }
    }
    false
}

/// 构造 otpauth:// URI(供认证器扫码/手动录入)。
#[must_use]
pub fn provisioning_uri(secret_b32: &str, account: &str, issuer: &str) -> String {
    let enc = |s: &str| {
        let mut o = String::new();
        for b in s.bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                o.push(char::from(b));
            } else {
                o.push_str(&format!("%{b:02X}"));
            }
        }
        o
    };
    format!(
        "otpauth://totp/{}:{}?secret={}&issuer={}&digits=6&period=30",
        enc(issuer),
        enc(account),
        secret_b32,
        enc(issuer)
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn base32_roundtrip() {
        for data in [&b"hello!"[..], &b"12345678901234567890"[..], &[0u8, 255, 16]] {
            let enc = base32_encode(data);
            assert_eq!(base32_decode(&enc).as_deref(), Some(data));
        }
        assert!(base32_decode("!@#").is_none());
    }

    #[test]
    fn rfc6238_known_vector() {
        // RFC 6238 测试密钥 "12345678901234567890"(ASCII)→ base32
        let secret = base32_encode(b"12345678901234567890");
        // T=59 → counter 1 → 期望 287082(RFC 附录 SHA1 向量)
        assert!(verify(&secret, "287082", 59));
        // 错误码不通过
        assert!(!verify(&secret, "000000", 59));
        // 窗口:T=59 的相邻步(30~89 秒)counter 相同,±1 允许 29 与 90 附近
        assert!(verify(&secret, "287082", 89));
    }

    #[test]
    fn rejects_malformed() {
        let secret = base32_encode(b"12345678901234567890");
        assert!(!verify(&secret, "12345", 59)); // 位数不对
        assert!(!verify(&secret, "abcdef", 59)); // 非数字
        assert!(!verify("!!!", "287082", 59)); // 密钥非法
    }

    #[test]
    fn uri_encodes_specials() {
        let u = provisioning_uri("ABC234", "admin user", "Outpost 哨站");
        assert!(u.contains("secret=ABC234"));
        assert!(u.contains("admin%20user"));
        assert!(!u.contains(' '));
    }
}
