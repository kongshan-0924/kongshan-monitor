//! 全局应用状态。

use crate::config::Config;
use crate::ratelimit::{LoginGuard, RateLimiter};
use sqlx::SqlitePool;
use std::sync::Arc;
use tokio::sync::{broadcast, watch};

/// agent 分发产物(启动时扫描 dist 目录并计算 SHA-256)。
#[derive(Debug, Clone)]
pub struct Artifact {
    pub target: String,   // 如 x86_64-unknown-linux-musl
    pub filename: String, // 白名单文件名
    pub sha256: String,
}

pub struct Inner {
    pub db: SqlitePool,
    pub cfg: Config,
    pub limiter: RateLimiter,
    pub login_guard: LoginGuard,
    /// UI 实时推送通道(已清洗的 JSON 文本)。
    pub live_tx: broadcast::Sender<String>,
    /// 全局上报间隔,变更时推送给在线 agent(白名单下行)。
    pub interval_tx: watch::Sender<u32>,
    /// 登录时序均衡用的哑哈希(用户不存在时也做一次 argon2 校验)。
    pub dummy_hash: String,
    /// 私有 CA PEM(pinned_ca 模式;serve /ca.pem 用)与其 SHA-256 指纹。
    pub ca_pem: Option<Vec<u8>>,
    pub ca_fingerprint: Option<String>,
    /// agent 二进制清单。
    pub artifacts: Vec<Artifact>,
    /// 告警运行态消抖状态(内存)。
    pub alert_rt: crate::alerts::AlertRuntime,
    /// 通知去重节流:(channel_id, text_hash) -> 上次发送时刻。
    pub notify_throttle: std::sync::Mutex<std::collections::HashMap<(i64, u64), i64>>,
}

pub type AppState = Arc<Inner>;
