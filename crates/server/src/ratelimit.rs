//! 内存态限速:令牌桶(按 IP × 端点类别)+ 登录退避锁(按用户名)。
//! 手写实现,零依赖,便于审计(规范 6.1.9)。

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::Instant;

/// 端点类别 → (桶容量, 每秒补充速率)。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    /// 登录 / 首次引导:10 次/分钟
    Login,
    /// agent 注册:12 次/分钟
    Register,
    /// 常规 API:240 次/分钟
    Api,
    /// WS 握手:30 次/分钟
    Ws,
}

impl Class {
    fn params(self) -> (f64, f64) {
        match self {
            Class::Login => (10.0, 10.0 / 60.0),
            Class::Register => (12.0, 12.0 / 60.0),
            Class::Api => (240.0, 4.0),
            Class::Ws => (30.0, 0.5),
        }
    }
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// IP 级令牌桶。条目超限时清理过期项,防止内存被打爆。
pub struct RateLimiter {
    inner: Mutex<HashMap<(IpAddr, Class), Bucket>>,
}

const MAX_ENTRIES: usize = 10_000;

impl RateLimiter {
    #[must_use]
    pub fn new() -> Self {
        Self { inner: Mutex::new(HashMap::new()) }
    }

    /// 尝试消费一个令牌;false = 应拒绝(429)。
    pub fn check(&self, ip: IpAddr, class: Class) -> bool {
        let (cap, refill) = class.params();
        let now = Instant::now();
        let Ok(mut map) = self.inner.lock() else {
            // 锁中毒(不可能发生 panic 已被 lint 禁止):保守放行并记录
            tracing::warn!("rate limiter mutex poisoned");
            return true;
        };
        if map.len() > MAX_ENTRIES {
            map.retain(|_, b| now.duration_since(b.last).as_secs() < 600);
            if map.len() > MAX_ENTRIES {
                map.clear(); // 极端泛洪下的兜底,文档化的取舍
            }
        }
        let b = map.entry((ip, class)).or_insert(Bucket { tokens: cap, last: now });
        let dt = now.duration_since(b.last).as_secs_f64();
        b.last = now;
        b.tokens = (b.tokens + dt * refill).min(cap);
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// 登录失败退避:同一 (来源 IP × 账号) 5 次失败后指数锁定(30s 起,封顶 1h)。
///
/// 按 (IP, 账号) 而非仅账号计键:否则任何知道管理员用户名的攻击者只需连续输错
/// 即可把该账号从**所有** IP 锁死,形成拒绝服务。按来源 IP 分桶后,攻击者只能
/// 锁住自己那个 IP,合法用户从别的 IP 仍可正常登录;跨 IP 泛洪另有 IP 级令牌桶兜底。
pub struct LoginGuard {
    inner: Mutex<HashMap<(IpAddr, String), (u32, i64)>>, // (ip, username) -> (fail_count, locked_until)
}

const GUARD_MAX: usize = 4096;

impl LoginGuard {
    #[must_use]
    pub fn new() -> Self {
        Self { inner: Mutex::new(HashMap::new()) }
    }

    /// 是否处于锁定期。
    pub fn is_locked(&self, ip: IpAddr, username: &str, now: i64) -> bool {
        let Ok(map) = self.inner.lock() else { return false };
        map.get(&(ip, username.to_string())).is_some_and(|&(_, until)| until > now)
    }

    /// 记一次失败;达到阈值则锁定并返回锁定秒数。
    pub fn record_fail(&self, ip: IpAddr, username: &str, now: i64) -> Option<i64> {
        let Ok(mut map) = self.inner.lock() else { return None };
        if map.len() > GUARD_MAX {
            map.retain(|_, &mut (_, until)| until > now);
        }
        let e = map.entry((ip, username.to_string())).or_insert((0, 0));
        e.0 = e.0.saturating_add(1);
        if e.0 >= 5 {
            let exp = e.0.saturating_sub(5).min(7); // 30 * 2^n, 封顶 3840s→再夹到 3600
            let lock = 30i64.saturating_mul(1i64 << exp).min(3600);
            e.1 = now.saturating_add(lock);
            Some(lock)
        } else {
            None
        }
    }

    pub fn reset(&self, ip: IpAddr, username: &str) {
        if let Ok(mut map) = self.inner.lock() {
            map.remove(&(ip, username.to_string()));
        }
    }
}

impl Default for LoginGuard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn bucket_blocks_after_capacity() {
        let rl = RateLimiter::new();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let mut allowed = 0;
        for _ in 0..30 {
            if rl.check(ip, Class::Login) {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 10); // Login 容量 10
        // 其他 IP 不受影响
        assert!(rl.check("5.6.7.8".parse().unwrap(), Class::Login));
    }

    #[test]
    fn login_guard_locks_after_5_and_backs_off() {
        let g = LoginGuard::new();
        let now = 1000;
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        for _ in 0..4 {
            assert!(g.record_fail(ip, "admin", now).is_none());
        }
        assert!(!g.is_locked(ip, "admin", now));
        let lock1 = g.record_fail(ip, "admin", now).unwrap();
        assert_eq!(lock1, 30);
        assert!(g.is_locked(ip, "admin", now));
        let lock2 = g.record_fail(ip, "admin", now).unwrap();
        assert_eq!(lock2, 60); // 指数递增
        // 另一 IP 对同一账号不受锁定影响(防单点锁死 DoS)
        assert!(!g.is_locked("5.6.7.8".parse().unwrap(), "admin", now));
        g.reset(ip, "admin");
        assert!(!g.is_locked(ip, "admin", now));
    }
}
