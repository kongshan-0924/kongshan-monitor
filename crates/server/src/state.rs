//! 全局应用状态。

use crate::config::Config;
use crate::ratelimit::{LoginGuard, RateLimiter};
use sqlx::SqlitePool;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use tokio::sync::{broadcast, mpsc, watch};

/// 运行时可变的对外访问地址(设置页可修改,立即生效,无需重启)。
/// 初值取自 `settings` 表(不存在则播种 config.toml 的 `server.public_url`/`extra_origins`)。
#[derive(Debug, Clone)]
pub struct NetCfg {
    pub public_url: String,
    pub extra_origins: Vec<String>,
}

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
    /// 对外访问地址(动态,见 [`NetCfg`])。
    pub net: RwLock<NetCfg>,
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
    /// 告警规则缓存(启用中的全部规则,含 node_id 归属)。规则极少变更却每条上报都要匹配,
    /// 故常驻内存;增删改后由 handlers 调 [`crate::alerts::reload_rules`] 刷新(P1-4/P1-5)。
    pub rule_cache: RwLock<Arc<Vec<crate::alerts::RuleLite>>>,
    /// 通知去重节流:(channel_id, text_hash) -> 上次发送时刻。
    pub notify_throttle: std::sync::Mutex<std::collections::HashMap<(i64, u64), i64>>,
    /// 在线 agent 的升级触发通道(node_id -> sender);仅用于按需下发零参数的
    /// [`outpost_common::ServerToAgent::Upgrade`],不承载任何可变内容。
    pub upgrade_tx: Mutex<HashMap<i64, mpsc::UnboundedSender<()>>>,
    /// 升级补发窗口(node_id -> 截止 unix 秒)。向触发瞬间恰无活跃连接的节点下发升级时,
    /// 记入本表;该节点在窗口内(见 `UPGRADE_RESEND_SECS`)重连即自动补发一次,消除
    /// "面板显示在线、点升级却报离线"的竞态假象。纯内存 + 短 TTL,不做持久排队。
    pub pending_upgrade: Mutex<HashMap<i64, i64>>,
}

/// 升级补发窗口时长(秒):节点在此窗口内重连将自动补发一次升级触发。
pub const UPGRADE_RESEND_SECS: i64 = 30;

pub type AppState = Arc<Inner>;

impl Inner {
    /// 当前对外访问地址(用于 Origin 校验、安装命令、状态页链接渲染)。
    #[must_use]
    pub fn public_url(&self) -> String {
        self.net.read().unwrap_or_else(std::sync::PoisonError::into_inner).public_url.clone()
    }

    /// 当前额外允许的 Origin 列表(原始 URL 形式,未裁剪为 origin)。
    #[must_use]
    pub fn extra_origins(&self) -> Vec<String> {
        self.net.read().unwrap_or_else(std::sync::PoisonError::into_inner).extra_origins.clone()
    }

    /// `public_url` 的 Origin 形式(scheme://host[:port])。
    #[must_use]
    pub fn public_origin(&self) -> String {
        crate::config::origin_of(&self.public_url())
    }

    /// 全部允许的 Origin(public_url + extra_origins,均裁剪为 origin 形式)。
    #[must_use]
    pub fn allowed_origins(&self) -> Vec<String> {
        let mut v = vec![self.public_origin()];
        for o in &self.extra_origins() {
            v.push(crate::config::origin_of(o));
        }
        v
    }
}
