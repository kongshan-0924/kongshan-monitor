//! 认证:首次引导建号、登录(限速+退避)、登出、改密。

use crate::audit;
use crate::errors::AppError;
use crate::ratelimit::Class;
use crate::session::{clear_cookie, create_session, SessionUser};
use crate::state::AppState;
use crate::util::{client_ip, unix_now};
use argon2::password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::Argon2;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use std::net::SocketAddr;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetupReq {
    username: String,
    password: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LoginReq {
    username: String,
    password: String,
    /// 两步验证码或恢复码(未开启 2FA 时留空)。
    #[serde(default)]
    code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PasswordReq {
    old_password: String,
    new_password: String,
}

pub(crate) fn valid_username(u: &str) -> bool {
    (3..=32).contains(&u.len())
        && u.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-')
}

pub(crate) fn check_password_strength(p: &str) -> Result<(), AppError> {
    if !(10..=128).contains(&p.chars().count()) {
        return Err(AppError::bad("密码长度需在 10~128 字符之间"));
    }
    let has_alpha = p.chars().any(|c| c.is_alphabetic());
    let has_digit = p.chars().any(|c| c.is_ascii_digit());
    if !(has_alpha && has_digit) {
        return Err(AppError::bad("密码需同时包含字母和数字"));
    }
    Ok(())
}

pub(crate) fn hash_password(p: &str) -> Result<String, AppError> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(p.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| AppError::Internal)
}

fn verify_password(stored: &str, p: &str) -> bool {
    PasswordHash::new(stored)
        .map(|h| Argon2::default().verify_password(p.as_bytes(), &h).is_ok())
        .unwrap_or(false)
}

/// 创建管理员(**仅当系统尚无任何用户**,原子条件插入,幂等)。
/// 供命令行 `admin-create` 与首启环境变量引导复用;校验与哈希与网页 setup 完全一致。
///
/// 返回 `Ok(true)`=已创建,`Ok(false)`=已存在(未改动)。
///
/// # Errors
/// 用户名/密码不合规或数据库写入失败。
pub async fn create_admin(
    pool: &sqlx::SqlitePool,
    username: &str,
    password: &str,
) -> Result<bool, String> {
    if !valid_username(username) {
        return Err("用户名需 3~32 位,仅限字母数字与 _.-".to_string());
    }
    check_password_strength(password).map_err(|e| e.to_string())?;
    let hash = hash_password(password).map_err(|_| "argon2 哈希失败".to_string())?;
    let now = unix_now();
    let res = sqlx::query!(
        "INSERT INTO users(username, pass_hash, created_at)
         SELECT ?1, ?2, ?3 WHERE NOT EXISTS(SELECT 1 FROM users)",
        username,
        hash,
        now
    )
    .execute(pool)
    .await
    .map_err(|e| format!("数据库写入失败: {e}"))?;
    Ok(res.rows_affected() == 1)
}

/// 是否已完成初始化(存在用户)。
pub async fn setup_done(st: &AppState) -> Result<bool, AppError> {
    let n = sqlx::query_scalar!(r#"SELECT COUNT(*) as "c!: i64" FROM users"#)
        .fetch_one(&st.db)
        .await?;
    Ok(n > 0)
}

/// GET /api/setup — 前端据此决定跳转引导页还是登录页。
pub async fn setup_status(State(st): State<AppState>) -> Result<Json<serde_json::Value>, AppError> {
    Ok(Json(serde_json::json!({ "initialized": setup_done(&st).await? })))
}

/// POST /api/setup — 仅当系统内没有任何用户时可用(无默认账号,规范 4.1)。
pub async fn setup(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<SetupReq>,
) -> Result<Response, AppError> {
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    if !st.limiter.check(ip, Class::Login) {
        return Err(AppError::TooManyRequests);
    }
    if !valid_username(&req.username) {
        return Err(AppError::bad("用户名需 3~32 位,仅限字母数字与 _.-"));
    }
    check_password_strength(&req.password)?;

    let hash = hash_password(&req.password)?;
    let now = unix_now();
    // 原子防竞态:仅当 users 为空才插入
    let res = sqlx::query!(
        "INSERT INTO users(username, pass_hash, created_at)
         SELECT ?1, ?2, ?3 WHERE NOT EXISTS(SELECT 1 FROM users)",
        req.username,
        hash,
        now
    )
    .execute(&st.db)
    .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::Forbidden); // 已初始化,拒绝
    }
    audit::log(&st.db, &req.username, &ip.to_string(), "setup_admin", "创建管理员").await;
    tracing::info!("管理员账户已创建,首次引导关闭");
    Ok(StatusCode::NO_CONTENT.into_response())
}

/// POST /api/login
pub async fn login(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<LoginReq>,
) -> Result<Response, AppError> {
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    if !st.limiter.check(ip, Class::Login) {
        return Err(AppError::TooManyRequests);
    }
    let uname = outpost_common::clean_str(&req.username, 64);
    let now = unix_now();
    if st.login_guard.is_locked(ip, &uname, now) {
        audit::log(&st.db, &uname, &ip.to_string(), "login_locked", "退避锁定中").await;
        return Err(AppError::TooManyRequests);
    }

    let row = sqlx::query!(
        r#"SELECT id as "id!", pass_hash as "pass_hash!",
                  totp_secret as "totp_secret!", totp_enabled as "totp_enabled!: i64"
           FROM users WHERE username = ?1"#,
        uname
    )
    .fetch_optional(&st.db)
    .await?;

    // 用户不存在时对哑哈希做校验,均衡时序,防用户名枚举
    let ok = match &row {
        Some(r) => verify_password(&r.pass_hash, &req.password),
        None => {
            let _ = verify_password(&st.dummy_hash, &req.password);
            false
        }
    };

    let Some(r) = row.filter(|_| ok) else {
        let locked = st.login_guard.record_fail(ip, &uname, now);
        audit::log(&st.db, &uname, &ip.to_string(), "login_fail", "").await;
        if locked.is_some() {
            return Err(AppError::TooManyRequests);
        }
        // 统一错误文案,不区分"用户不存在/密码错误"
        return Err(AppError::bad("用户名或密码错误"));
    };

    // 两步验证(密码已正确)
    if r.totp_enabled != 0 {
        let code = req.code.trim();
        if code.is_empty() {
            // 密码正确、缺验证码:不计失败,提示前端补充(前端据此展示验证码输入)
            return Err(AppError::bad("需要两步验证码"));
        }
        let code_ok = crate::totp::verify(&r.totp_secret, code, now)
            || crate::handlers::twofa::consume_recovery(&st, r.id, code).await;
        if !code_ok {
            let locked = st.login_guard.record_fail(ip, &uname, now);
            audit::log(&st.db, &uname, &ip.to_string(), "login_2fa_fail", "").await;
            if locked.is_some() {
                return Err(AppError::TooManyRequests);
            }
            return Err(AppError::bad("两步验证码不正确"));
        }
    }

    st.login_guard.reset(ip, &uname);
    let ua = headers
        .get(header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let ip_str = ip.to_string();

    // 新设备/新 IP 登录通知(纯出站,不含敏感数据)
    let seen_before = sqlx::query_scalar!(
        r#"SELECT COUNT(*) as "c!: i64" FROM sessions WHERE user_id = ?1 AND ip = ?2"#,
        r.id,
        ip_str
    )
    .fetch_one(&st.db)
    .await
    .unwrap_or(0);

    let cookie = create_session(&st, r.id, &ip_str, ua).await?;
    audit::log(&st.db, &uname, &ip_str, "login_ok", "").await;

    if seen_before == 0 {
        let st2 = st.clone();
        let text = format!("🔑 新设备登录:用户 {uname} 首次从 IP {ip_str} 登录 Outpost 面板");
        tokio::spawn(async move {
            crate::alerts::notify_all(&st2, &text, "info").await;
        });
    }

    let mut res = StatusCode::NO_CONTENT.into_response();
    if let Ok(v) = header::HeaderValue::from_str(&cookie) {
        res.headers_mut().insert(header::SET_COOKIE, v);
    }
    Ok(res)
}

/// POST /api/logout
pub async fn logout(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionUser,
) -> Result<Response, AppError> {
    sqlx::query!("DELETE FROM sessions WHERE token_hash = ?1", user.token_hash)
        .execute(&st.db)
        .await?;
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "logout", "").await;
    let mut res = StatusCode::NO_CONTENT.into_response();
    if let Ok(v) = header::HeaderValue::from_str(&clear_cookie(&st)) {
        res.headers_mut().insert(header::SET_COOKIE, v);
    }
    Ok(res)
}

/// POST /api/logout_all — 使全部会话失效。
pub async fn logout_all(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionUser,
) -> Result<Response, AppError> {
    sqlx::query!("DELETE FROM sessions WHERE user_id = ?1", user.user_id)
        .execute(&st.db)
        .await?;
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "logout_all", "全部会话失效").await;
    let mut res = StatusCode::NO_CONTENT.into_response();
    if let Ok(v) = header::HeaderValue::from_str(&clear_cookie(&st)) {
        res.headers_mut().insert(header::SET_COOKIE, v);
    }
    Ok(res)
}

/// POST /api/password — 改密后所有会话失效(需重新登录)。
pub async fn change_password(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionUser,
    Json(req): Json<PasswordReq>,
) -> Result<Response, AppError> {
    check_password_strength(&req.new_password)?;
    let row = sqlx::query!(
        r#"SELECT pass_hash as "pass_hash!" FROM users WHERE id = ?1"#,
        user.user_id
    )
    .fetch_optional(&st.db)
    .await?
    .ok_or(AppError::Unauthorized)?;
    if !verify_password(&row.pass_hash, &req.old_password) {
        return Err(AppError::bad("原密码不正确"));
    }
    let hash = hash_password(&req.new_password)?;
    sqlx::query!("UPDATE users SET pass_hash = ?1 WHERE id = ?2", hash, user.user_id)
        .execute(&st.db)
        .await?;
    sqlx::query!("DELETE FROM sessions WHERE user_id = ?1", user.user_id)
        .execute(&st.db)
        .await?;
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "password_change", "全部会话已失效").await;
    let mut res = StatusCode::NO_CONTENT.into_response();
    if let Ok(v) = header::HeaderValue::from_str(&clear_cookie(&st)) {
        res.headers_mut().insert(header::SET_COOKIE, v);
    }
    Ok(res)
}

/// GET /api/me
pub async fn me(user: SessionUser) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "username": user.username, "role": user.role }))
}
