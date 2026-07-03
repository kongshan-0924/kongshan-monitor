//! 最小 SMTP 通知客户端(隐式 TLS / SMTPS,默认端口 465)。
//!
//! 安全设计:
//! - 复用 [`crate::notify`] 的 SSRF 校验解析目标 IP(默认拒绝私网/回环);
//! - rustls 校验服务端证书,SNI 用原始主机名;
//! - 邮件地址/主题禁止 CR/LF(防 SMTP 头注入),正文按规范做点填充;
//! - 凭据仅用于 AUTH,不落日志;整条会话带超时。
//!
//! 不引入第三方 SMTP 依赖(手写最小对话),保持依赖面与审计面最小。

use crate::notify::{resolve_checked, tls_config};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

const IO_TIMEOUT: Duration = Duration::from_secs(15);
const SESSION_TIMEOUT: Duration = Duration::from_secs(30);

/// SMTP 渠道配置(存于 `notify_channels.extra` 的 JSON)。
#[derive(serde::Deserialize)]
pub struct SmtpCfg {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    pub username: String,
    pub password: String,
    pub from: String,
    pub to: String,
}
fn default_port() -> u16 {
    465
}

/// 邮箱形态校验:禁控制字符/CRLF、需含 `@` 与含点的域名、全 ASCII 可见字符。
#[must_use]
pub fn valid_email(s: &str) -> bool {
    let s = s.trim();
    if s.len() < 3 || s.len() > 254 {
        return false;
    }
    if !s.bytes().all(|b| b.is_ascii_graphic()) {
        return false;
    }
    match s.split_once('@') {
        Some((l, r)) => {
            !l.is_empty()
                && !r.is_empty()
                && !r.contains('@')
                && r.contains('.')
                && !r.starts_with('.')
                && !r.ends_with('.')
        }
        None => false,
    }
}

/// 标准 base64 编码(AUTH LOGIN / 主题 encoded-word 用)。
fn b64(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let sym = |v: u32| char::from(T.get((v & 63) as usize).copied().unwrap_or(b'A'));
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for c in input.chunks(3) {
        let b0 = u32::from(c.first().copied().unwrap_or(0));
        let b1 = u32::from(c.get(1).copied().unwrap_or(0));
        let b2 = u32::from(c.get(2).copied().unwrap_or(0));
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(sym(n >> 18));
        out.push(sym(n >> 12));
        out.push(if c.len() > 1 { sym(n >> 6) } else { '=' });
        out.push(if c.len() > 2 { sym(n) } else { '=' });
    }
    out
}

/// 从 SMTP 响应缓冲提取最终三位状态码(多行以 `NNN-` 续行,`NNN ` 结束)。
fn final_code(buf: &[u8]) -> Option<u16> {
    if !buf.ends_with(b"\r\n") {
        return None;
    }
    let s = std::str::from_utf8(buf).ok()?;
    let last = s.trim_end_matches("\r\n").rsplit("\r\n").next()?;
    let b = last.as_bytes();
    if b.len() >= 4 && b.get(..3).is_some_and(|d| d.iter().all(u8::is_ascii_digit)) && b.get(3) == Some(&b' ') {
        return last.get(..3).and_then(|c| c.parse().ok());
    }
    None
}

async fn read_reply<S: AsyncReadExt + Unpin>(s: &mut S, buf: &mut Vec<u8>) -> Result<u16, String> {
    buf.clear();
    loop {
        if let Some(code) = final_code(buf) {
            return Ok(code);
        }
        let mut chunk = [0u8; 512];
        let n = tokio::time::timeout(IO_TIMEOUT, s.read(&mut chunk))
            .await
            .map_err(|_| "读取超时".to_string())?
            .map_err(|e| format!("读取失败: {e}"))?;
        if n == 0 {
            return Err("连接被关闭".into());
        }
        buf.extend_from_slice(chunk.get(..n).unwrap_or(&[]));
        if buf.len() > 16384 {
            return Err("SMTP 响应过大".into());
        }
    }
}

async fn write_line<S: AsyncWriteExt + Unpin>(s: &mut S, data: &[u8]) -> Result<(), String> {
    s.write_all(data).await.map_err(|e| format!("发送失败: {e}"))?;
    s.flush().await.ok();
    Ok(())
}

/// 发一条命令并校验期望状态码。
async fn cmd<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    s: &mut S,
    buf: &mut Vec<u8>,
    line: &str,
    want: u16,
) -> Result<(), String> {
    write_line(s, format!("{line}\r\n").as_bytes()).await?;
    let code = read_reply(s, buf).await?;
    if code != want {
        return Err(format!("SMTP 返回 {code}(期望 {want})"));
    }
    Ok(())
}

/// RFC5322 UTC 日期头(Howard Hinnant civil 算法),避免引入时间库依赖。
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss, clippy::cast_possible_wrap)]
fn rfc5322_date(secs: i64) -> String {
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let wd = (days + 4).rem_euclid(7); // 1970-01-01 = 周四
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    if m <= 2 {
        y += 1;
    }
    const WD: [&str; 7] = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
    const MO: [&str; 12] =
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    let wdn = WD.get(wd as usize).copied().unwrap_or("Mon");
    let mon = MO.get((m - 1) as usize).copied().unwrap_or("Jan");
    format!("{wdn}, {d:02} {mon} {y} {h:02}:{mi:02}:{s:02} +0000")
}

/// 正文点填充 + CRLF 规范化(SMTP DATA 要求)。
fn dot_stuff(body: &str) -> String {
    let mut out = String::with_capacity(body.len() + 16);
    for line in body.split('\n') {
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.starts_with('.') {
            out.push('.');
        }
        out.push_str(line);
        out.push_str("\r\n");
    }
    out
}

fn build_message(from: &str, to: &str, subj: &str, body: &str, date: &str) -> String {
    // 主题用 MIME encoded-word 承载 UTF-8;正文 8bit UTF-8;结尾单独一行 "."
    format!(
        "From: <{from}>\r\nTo: <{to}>\r\nSubject: =?UTF-8?B?{}?=\r\nDate: {date}\r\n\
         MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\
         Content-Transfer-Encoding: 8bit\r\n\r\n{}.\r\n",
        b64(subj.as_bytes()),
        dot_stuff(body)
    )
}

/// 通过 SMTPS 发送一封告警邮件。成功返回 250。
///
/// # Errors
/// 配置/邮箱非法、SSRF 校验失败、连接/TLS/认证/超时失败。
pub async fn send(cfg: &SmtpCfg, subject: &str, body: &str, allow_private: bool, now: i64) -> Result<u16, String> {
    if cfg.host.is_empty() || cfg.host.len() > 255 {
        return Err("SMTP 主机非法".into());
    }
    if !valid_email(&cfg.from) || !valid_email(&cfg.to) {
        return Err("发件/收件邮箱格式非法".into());
    }
    if cfg.username.len() > 320 || cfg.password.len() > 256 || cfg.username.is_empty() {
        return Err("SMTP 凭据非法".into());
    }
    let subj: String = subject.chars().filter(|c| *c != '\r' && *c != '\n').take(200).collect();

    let addr = resolve_checked(&cfg.host, cfg.port, allow_private).await?;
    let server_name = ServerName::try_from(cfg.host.clone()).map_err(|_| "主机名不是合法 SNI".to_string())?;
    let connector = TlsConnector::from(tls_config());

    let fut = async {
        let tcp = TcpStream::connect(addr).await.map_err(|e| format!("连接失败: {e}"))?;
        tcp.set_nodelay(true).ok();
        let mut tls = connector
            .connect(server_name, tcp)
            .await
            .map_err(|e| format!("TLS 握手失败: {e}"))?;
        let mut buf = Vec::with_capacity(1024);

        // 服务器问候
        if read_reply(&mut tls, &mut buf).await? != 220 {
            return Err("SMTP 服务器问候异常".to_string());
        }
        cmd(&mut tls, &mut buf, "EHLO outpost", 250).await?;
        cmd(&mut tls, &mut buf, "AUTH LOGIN", 334).await?;
        cmd(&mut tls, &mut buf, &b64(cfg.username.as_bytes()), 334).await?;
        cmd(&mut tls, &mut buf, &b64(cfg.password.as_bytes()), 235).await?;
        cmd(&mut tls, &mut buf, &format!("MAIL FROM:<{}>", cfg.from), 250).await?;
        cmd(&mut tls, &mut buf, &format!("RCPT TO:<{}>", cfg.to), 250).await?;
        cmd(&mut tls, &mut buf, "DATA", 354).await?;

        let msg = build_message(&cfg.from, &cfg.to, &subj, body, &rfc5322_date(now));
        write_line(&mut tls, msg.as_bytes()).await?;
        let code = read_reply(&mut tls, &mut buf).await?;
        if code != 250 {
            return Err(format!("邮件提交返回 {code}"));
        }
        let _ = write_line(&mut tls, b"QUIT\r\n").await;
        Ok::<u16, String>(250)
    };
    tokio::time::timeout(SESSION_TIMEOUT, fut).await.map_err(|_| "SMTP 会话超时".to_string())?
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn b64_known_vectors() {
        assert_eq!(b64(b""), "");
        assert_eq!(b64(b"f"), "Zg==");
        assert_eq!(b64(b"fo"), "Zm8=");
        assert_eq!(b64(b"foo"), "Zm9v");
        assert_eq!(b64(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn email_validation() {
        assert!(valid_email("a@b.com"));
        assert!(valid_email("ops.team@example.co.uk"));
        assert!(!valid_email("no-at-sign"));
        assert!(!valid_email("a@b"));
        assert!(!valid_email("a@@b.com"));
        assert!(!valid_email("a@b.com\r\nRCPT TO:<evil@x>")); // 头注入
        assert!(!valid_email("@b.com"));
        assert!(!valid_email("中文@b.com")); // 非 ASCII
    }

    #[test]
    fn dot_stuffing_and_date() {
        assert_eq!(dot_stuff(".hidden\nnormal"), "..hidden\r\nnormal\r\n");
        // 1970-01-01 00:00:00 UTC = 周四
        assert_eq!(rfc5322_date(0), "Thu, 01 Jan 1970 00:00:00 +0000");
        // 2021-01-01 00:00:00 UTC = 周五
        assert_eq!(rfc5322_date(1_609_459_200), "Fri, 01 Jan 2021 00:00:00 +0000");
    }
}
