#![forbid(unsafe_code)]
// serde_json 的 json! 宏按字段数展开,大对象字面量(如节点概览 JSON)容易超出默认递归限制。
#![recursion_limit = "256"]
//! outpost-server:安全优先的私有化服务器监控面板。

mod alerts;
mod apiauth;
mod audit;
mod config;
mod notify;
mod db;
mod errors;
mod handlers;
mod middleware;
mod notify_smtp;
mod ratelimit;
mod retention;
mod session;
mod state;
mod totp;
mod traffic;
mod util;

use crate::config::Config;
use crate::state::{AppState, Artifact, Inner};
use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
use argon2::Argon2;
use axum::extract::DefaultBodyLimit;
use axum::routing::{get, post};
use axum::Router;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::process::ExitCode;
use std::sync::Arc;
use tokio::sync::{broadcast, watch};

fn init_tracing() {
    use tracing_subscriber::EnvFilter;
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,sqlx=warn"));
    tracing_subscriber::fmt().with_env_filter(filter).with_target(false).init();
}

/// 扫描 dist 目录,登记白名单二进制并计算 SHA-256(供 manifest / 下载)。
async fn scan_artifacts(dir: &str) -> Vec<Artifact> {
    const KNOWN: &[(&str, &str)] = &[
        ("x86_64-unknown-linux-musl", "outpost-agent-x86_64-unknown-linux-musl"),
        ("aarch64-unknown-linux-musl", "outpost-agent-aarch64-unknown-linux-musl"),
    ];
    let mut out = Vec::new();
    for (target, fname) in KNOWN {
        let path = std::path::Path::new(dir).join(fname);
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                let sha = outpost_common::to_hex(&Sha256::digest(&bytes));
                tracing::info!(target, file = fname, sha256 = %sha, "agent 分发产物已登记");
                out.push(Artifact {
                    target: (*target).to_string(),
                    filename: (*fname).to_string(),
                    sha256: sha,
                });
            }
            Err(_) => {
                tracing::warn!(target, file = fname, "分发产物缺失(该架构不可一键安装)");
            }
        }
    }
    out
}

async fn build_state(cfg: Config) -> Result<AppState, String> {
    let pool = db::open(&cfg.storage.db_path)
        .await
        .map_err(|e| format!("数据库打开失败: {e}"))?;

    // 首启种子设置
    let interval = db::setting_i64(&pool, "report_interval_secs", 5, 1, 3600).await;
    let _ = db::set_setting(&pool, "report_interval_secs", &interval.to_string()).await;
    let retention = db::setting_i64(&pool, "retention_days", 30, 1, 3650).await;
    let _ = db::set_setting(&pool, "retention_days", &retention.to_string()).await;

    // 对外访问地址(设置页可动态改;首启种子取 config.toml,之后设置表优先)
    let seeded_url = db::setting_str(&pool, "public_url").await;
    let public_url =
        if seeded_url.is_empty() { cfg.server.public_url.clone() } else { seeded_url };
    let _ = db::set_setting(&pool, "public_url", &public_url).await;
    let seeded_origins = db::setting_str(&pool, "extra_origins").await;
    let extra_origins: Vec<String> = if seeded_origins.is_empty() {
        cfg.server.extra_origins.clone()
    } else {
        serde_json::from_str(&seeded_origins).unwrap_or_default()
    };
    let _ = db::set_setting(
        &pool,
        "extra_origins",
        &serde_json::to_string(&extra_origins).unwrap_or_else(|_| "[]".into()),
    )
    .await;

    // 登录时序均衡哑哈希
    let salt = SaltString::generate(&mut OsRng);
    let dummy = Argon2::default()
        .hash_password(b"outpost-timing-dummy", &salt)
        .map(|h| h.to_string())
        .map_err(|e| format!("argon2 初始化失败: {e}"))?;

    // 私有 CA(pinned_ca 模式)
    let (ca_pem, ca_fingerprint) = if cfg.install.mode == "pinned_ca"
        && !cfg.install.ca_cert_path.is_empty()
    {
        match tokio::fs::read(&cfg.install.ca_cert_path).await {
            Ok(pem) => {
                let fpr = outpost_common::to_hex(&Sha256::digest(&pem));
                tracing::info!(fingerprint = %fpr, "CA 证书已装载(安装命令将钉扎此指纹)");
                (Some(pem), Some(fpr))
            }
            Err(e) => {
                tracing::warn!(error = %e, "CA 证书读取失败,安装命令将退化为 public_ca 形式");
                (None, None)
            }
        }
    } else {
        (None, None)
    };

    let artifacts = scan_artifacts(&cfg.install.dist_dir).await;
    let (live_tx, _) = broadcast::channel(256);
    let interval_u32 = u32::try_from(interval).unwrap_or(5);
    let (interval_tx, _) = watch::channel(interval_u32);

    let users =
        sqlx::query_scalar!(r#"SELECT COUNT(*) as "c!: i64" FROM users"#).fetch_one(&pool).await;
    if matches!(users, Ok(0)) {
        // Docker/环境变量引导:提供 OUTPOST_ADMIN_USER/PASSWORD 时首启自动创建管理员
        match (std::env::var("OUTPOST_ADMIN_USER"), std::env::var("OUTPOST_ADMIN_PASSWORD")) {
            (Ok(u), Ok(p)) if !u.is_empty() && !p.is_empty() => {
                match handlers::auth::create_admin(&pool, &u, &p).await {
                    Ok(true) => tracing::info!(user = %u, "已从环境变量创建管理员"),
                    Ok(false) => {}
                    Err(e) => tracing::error!(error = %e, "环境变量创建管理员失败"),
                }
            }
            _ => tracing::warn!("尚未初始化:请访问 {}/setup 创建管理员账户", cfg.server.public_url),
        }
    }

    Ok(Arc::new(Inner {
        db: pool,
        cfg,
        net: std::sync::RwLock::new(state::NetCfg { public_url, extra_origins }),
        limiter: ratelimit::RateLimiter::new(),
        login_guard: ratelimit::LoginGuard::new(),
        live_tx,
        interval_tx,
        dummy_hash: dummy,
        ca_pem,
        ca_fingerprint,
        artifacts,
        alert_rt: alerts::AlertRuntime::default(),
        notify_throttle: std::sync::Mutex::new(std::collections::HashMap::new()),
        upgrade_tx: std::sync::Mutex::new(std::collections::HashMap::new()),
    }))
}

fn build_router(st: AppState) -> Router {
    // 认证边界说明(端点清单详见 SECURITY_AUDIT.md):
    // - 公开:healthz、登录/引导页与其 API、agent 注册、分发/CA/脚本、静态资源
    // - 会话保护(SessionUser,admin+viewer 均可):只读查询类 API 与页面、/ws/ui
    // - 会话保护(SessionAdmin,仅 admin):全部状态变更端点(轻量 RBAC,漏加即编译不过)
    // - token 保护:/ws/agent(Bearer,升级前校验)
    let api = Router::new()
        .route("/api/setup", get(handlers::auth::setup_status).post(handlers::auth::setup))
        .route("/api/login", post(handlers::auth::login))
        .route("/api/logout", post(handlers::auth::logout))
        .route("/api/logout_all", post(handlers::auth::logout_all))
        .route("/api/password", post(handlers::auth::change_password))
        .route("/api/me", get(handlers::auth::me))
        .route("/api/users", get(handlers::users::list).post(handlers::users::create))
        .route("/api/users/{id}", axum::routing::delete(handlers::users::delete))
        .route("/api/users/{id}/role", post(handlers::users::set_role))
        .route("/api/nodes", get(handlers::nodes::list).post(handlers::nodes::create))
        .route("/api/nodes/batch", post(handlers::nodes::batch))
        .route("/api/nodes/reorder", post(handlers::nodes::reorder))
        .route("/api/nodes/{id}", get(handlers::nodes::detail).delete(handlers::nodes::delete))
        .route("/api/nodes/{id}/metrics", get(handlers::nodes::history))
        .route("/api/overview/trend", get(handlers::nodes::overview_trend))
        .route("/api/nodes/{id}/rename", post(handlers::nodes::rename))
        .route("/api/nodes/{id}/revoke", post(handlers::nodes::revoke))
        .route("/api/nodes/{id}/regen_key", post(handlers::nodes::regen_key))
        .route("/api/settings", get(handlers::settings::get).post(handlers::settings::set))
        .route("/api/audit", get(handlers::settings::audit_list))
        .route("/api/audit/export", get(handlers::settings::audit_export))
        .route("/api/upgrade_command", get(handlers::nodes::upgrade_command))
        .route("/api/status/enable", post(handlers::status::enable))
        .route("/api/status/disable", post(handlers::status::disable))
        .route("/api/status/{slug}", get(handlers::status::public_json))
        .route("/api/alerts/rules", get(handlers::alerts::list_rules).post(handlers::alerts::create_rule))
        .route("/api/alerts/rules/{id}", axum::routing::delete(handlers::alerts::delete_rule))
        .route("/api/alerts/rules/{id}/toggle", post(handlers::alerts::toggle_rule))
        .route("/api/alerts/events", get(handlers::alerts::list_events))
        .route("/api/alerts/channels", get(handlers::alerts::list_channels).post(handlers::alerts::create_channel))
        .route("/api/alerts/channels/{id}", axum::routing::delete(handlers::alerts::delete_channel))
        .route("/api/alerts/channels/{id}/test", post(handlers::alerts::test_channel))
        .route("/api/alerts/silences", get(handlers::alerts::list_silences).post(handlers::alerts::create_silence))
        .route("/api/alerts/silences/{id}", axum::routing::delete(handlers::alerts::delete_silence))
        .route("/api/alerts/renotify", get(handlers::alerts::get_renotify).post(handlers::alerts::set_renotify))
        .route("/api/apitokens", get(handlers::apitokens::list).post(handlers::apitokens::create))
        .route("/api/apitokens/{id}", axum::routing::delete(handlers::apitokens::delete))
        .route("/api/2fa/status", get(handlers::twofa::status))
        .route("/api/2fa/setup", post(handlers::twofa::setup))
        .route("/api/2fa/enable", post(handlers::twofa::enable))
        .route("/api/2fa/disable", post(handlers::twofa::disable))
        .route("/api/sessions", get(handlers::account::list_sessions))
        .route("/api/sessions/{token_hash}", axum::routing::delete(handlers::account::revoke_session))
        .route("/api/backup", get(handlers::account::backup))
        .route("/metrics", get(handlers::dataout::prometheus))
        .route("/api/v1/nodes", get(handlers::dataout::v1_nodes))
        .route("/api/v1/nodes/{id}/export", get(handlers::dataout::export))
        .route("/api/agent/register", post(handlers::agent_api::register))
        .route("/api/agent/manifest", get(handlers::agent_api::manifest))
        .layer(axum::middleware::from_fn_with_state(st.clone(), middleware::api_rate_limit));

    Router::new()
        .merge(api)
        .route("/", get(handlers::pages::index))
        .route("/login", get(handlers::pages::login_page))
        .route("/setup", get(handlers::pages::setup_page))
        .route("/settings", get(handlers::pages::settings_page))
        .route("/servers", get(handlers::pages::servers_page))
        .route("/alerts", get(handlers::pages::alerts_page))
        .route("/nodes/{id}", get(handlers::pages::node_page))
        .route("/static/{file}", get(handlers::pages::asset))
        .route("/favicon.svg", get(handlers::pages::favicon))
        .route("/healthz", get(handlers::agent_api::healthz))
        .route("/ca.pem", get(handlers::agent_api::ca_pem))
        .route("/install.sh", get(handlers::agent_api::install_sh))
        .route("/uninstall.sh", get(handlers::agent_api::uninstall_sh))
        .route("/upgrade.sh", get(handlers::agent_api::upgrade_sh))
        .route("/compare", get(handlers::pages::compare_page))
        .route("/status/{slug}", get(handlers::pages::status_page))
        .route("/download/{name}", get(handlers::agent_api::download))
        .route("/ws/agent", get(handlers::ws_agent::upgrade))
        .route("/ws/ui", get(handlers::ws_ui::upgrade))
        // 全局:请求体上限 64KB(无上传场景;防内存 DoS)
        .layer(DefaultBodyLimit::max(64 * 1024))
        .layer(axum::middleware::from_fn_with_state(st.clone(), middleware::csrf_origin_check))
        .layer(axum::middleware::from_fn_with_state(st.clone(), middleware::security_headers))
        .with_state(st)
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = term => {},
    }
    tracing::info!("收到停止信号,优雅退出");
}

/// `admin-create` 子命令:创建管理员(用户名取 --username 或 OUTPOST_ADMIN_USER;
/// 密码取 OUTPOST_ADMIN_PASSWORD 或 stdin 一行)。仅当系统尚无用户时生效(幂等)。
async fn run_admin_create(cfg: &Config, args: &[String]) -> ExitCode {
    let username = args
        .iter()
        .position(|a| a == "--username")
        .and_then(|i| args.get(i + 1).cloned())
        .or_else(|| std::env::var("OUTPOST_ADMIN_USER").ok())
        .unwrap_or_default();
    if username.is_empty() {
        eprintln!("需要 --username <名> 或环境变量 OUTPOST_ADMIN_USER");
        return ExitCode::FAILURE;
    }
    let password = std::env::var("OUTPOST_ADMIN_PASSWORD").ok().or_else(|| {
        let mut line = String::new();
        // 从 stdin 读一行(密码不回显由调用方/终端负责)
        match std::io::stdin().read_line(&mut line) {
            Ok(n) if n > 0 => Some(line.trim_end_matches(['\n', '\r']).to_string()),
            _ => None,
        }
    });
    let Some(password) = password.filter(|p| !p.is_empty()) else {
        eprintln!("需要环境变量 OUTPOST_ADMIN_PASSWORD 或从 stdin 提供密码");
        return ExitCode::FAILURE;
    };

    let pool = match db::open(&cfg.storage.db_path).await {
        Ok(p) => p,
        Err(e) => {
            eprintln!("数据库打开失败: {e}");
            return ExitCode::FAILURE;
        }
    };
    match handlers::auth::create_admin(&pool, &username, &password).await {
        Ok(true) => {
            println!("管理员 {username} 已创建");
            ExitCode::SUCCESS
        }
        Ok(false) => {
            println!("已存在管理员,跳过创建(幂等)");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("创建管理员失败: {e}");
            ExitCode::FAILURE
        }
    }
}

fn main() -> ExitCode {
    init_tracing();

    // rustls 进程级 provider(ring,纯 Rust 生态)
    if rustls::crypto::ring::default_provider().install_default().is_err() {
        tracing::error!("rustls provider 安装失败");
        return ExitCode::FAILURE;
    }

    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("--version" | "-V") => {
            println!("outpost-server {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Some("--help" | "-h") => {
            println!(
                "outpost-server [admin-create --username <名>]\n  \
                 无子命令: 按 OUTPOST_CONFIG(默认 /etc/outpost/config.toml)启动服务\n  \
                 admin-create: 创建管理员(密码取 OUTPOST_ADMIN_PASSWORD 或 stdin;仅当无用户时)"
            );
            return ExitCode::SUCCESS;
        }
        _ => {}
    }

    let cfg_path = std::env::var("OUTPOST_CONFIG")
        .unwrap_or_else(|_| "/etc/outpost/config.toml".to_string());
    let cfg = match Config::load(&cfg_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, path = %cfg_path, "配置加载失败");
            return ExitCode::FAILURE;
        }
    };

    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "运行时启动失败");
            return ExitCode::FAILURE;
        }
    };

    // 子命令:创建管理员后退出
    if args.get(1).map(String::as_str) == Some("admin-create") {
        return rt.block_on(run_admin_create(&cfg, &args));
    }

    rt.block_on(async move {
        let addr = cfg.listen_addr();
        let tls_enabled = cfg.server.tls.enabled;
        let cert = cfg.server.tls.cert_path.clone();
        let key = cfg.server.tls.key_path.clone();

        let st = match build_state(cfg).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!(error = %e, "初始化失败");
                return ExitCode::FAILURE;
            }
        };
        alerts::reconcile_on_startup(&st).await;
        tokio::spawn(retention::run(st.clone()));
        tokio::spawn(alerts::patrol(st.clone()));
        let app = build_router(st);

        tracing::info!(%addr, tls = tls_enabled, "outpost-server 启动");
        if tls_enabled {
            // 内置 rustls 直接终止 TLS(不经反代部署形态)
            let rustls_cfg =
                match axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key).await {
                    Ok(c) => c,
                    Err(e) => {
                        tracing::error!(error = %e, "TLS 证书加载失败");
                        return ExitCode::FAILURE;
                    }
                };
            let handle = axum_server::Handle::new();
            let h2 = handle.clone();
            tokio::spawn(async move {
                shutdown_signal().await;
                h2.graceful_shutdown(Some(std::time::Duration::from_secs(5)));
            });
            let srv = axum_server::bind_rustls(addr, rustls_cfg)
                .handle(handle)
                .serve(app.into_make_service_with_connect_info::<SocketAddr>());
            if let Err(e) = srv.await {
                tracing::error!(error = %e, "服务异常退出");
                return ExitCode::FAILURE;
            }
        } else {
            let listener = match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!(error = %e, %addr, "端口绑定失败");
                    return ExitCode::FAILURE;
                }
            };
            let srv = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(shutdown_signal());
            if let Err(e) = srv.await {
                tracing::error!(error = %e, "服务异常退出");
                return ExitCode::FAILURE;
            }
        }
        ExitCode::SUCCESS
    })
}
