//! 两步验证(TOTP)启用/停用 + 一次性恢复码。全部需会话认证。

use crate::audit;
use crate::errors::AppError;
use crate::session::SessionUser;
use crate::state::AppState;
use crate::util::{client_ip, gen_token_hex, sha256_hex, unix_now};
use argon2::password_hash::{PasswordHash, PasswordVerifier};
use argon2::Argon2;
use axum::extract::{ConnectInfo, State};
use axum::http::HeaderMap;
use axum::Json;
use rand::RngCore;
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodeReq {
    code: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisableReq {
    password: String,
    code: String,
}

/// GET /api/2fa/status
pub async fn status(State(st): State<AppState>, user: SessionUser) -> Result<Json<Value>, AppError> {
    let enabled = sqlx::query_scalar!(
        r#"SELECT totp_enabled as "e!: i64" FROM users WHERE id = ?1"#,
        user.user_id
    )
    .fetch_optional(&st.db)
    .await?
    .unwrap_or(0);
    Ok(Json(json!({ "enabled": enabled != 0 })))
}

/// POST /api/2fa/setup — 生成待启用密钥(尚未开启)。返回密钥与 otpauth URI。
pub async fn setup(State(st): State<AppState>, user: SessionUser) -> Result<Json<Value>, AppError> {
    let enabled = sqlx::query_scalar!(
        r#"SELECT totp_enabled as "e!: i64" FROM users WHERE id = ?1"#,
        user.user_id
    )
    .fetch_one(&st.db)
    .await?;
    if enabled != 0 {
        return Err(AppError::bad("两步验证已启用,请先停用再重新设置"));
    }
    // 20 字节 CSPRNG → base32
    let mut raw = [0u8; 20];
    rand::rngs::OsRng.try_fill_bytes(&mut raw).map_err(|_| AppError::Internal)?;
    let secret = crate::totp::base32_encode(&raw);
    sqlx::query!("UPDATE users SET totp_secret = ?1 WHERE id = ?2", secret, user.user_id)
        .execute(&st.db)
        .await?;
    let uri = crate::totp::provisioning_uri(&secret, &user.username, "Outpost");
    Ok(Json(json!({ "secret": secret, "uri": uri })))
}

/// POST /api/2fa/enable — 校验一次性码后启用,返回 10 个恢复码(仅此一次)。
pub async fn enable(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionUser,
    Json(req): Json<CodeReq>,
) -> Result<Json<Value>, AppError> {
    let row = sqlx::query!(
        r#"SELECT totp_secret as "s!", totp_enabled as "e!: i64" FROM users WHERE id = ?1"#,
        user.user_id
    )
    .fetch_one(&st.db)
    .await?;
    if row.e != 0 {
        return Err(AppError::bad("两步验证已启用"));
    }
    if row.s.is_empty() || !crate::totp::verify(&row.s, &req.code, unix_now()) {
        return Err(AppError::bad("验证码不正确,请重试"));
    }
    // 生成恢复码
    let mut codes = Vec::with_capacity(10);
    for _ in 0..10 {
        let c = gen_token_hex().map_err(|_| AppError::Internal)?;
        codes.push(c.get(..10).unwrap_or("").to_string());
    }
    // 事务:启用 + 清旧恢复码 + 插新
    let mut tx = st.db.begin().await?;
    sqlx::query!("UPDATE users SET totp_enabled = 1 WHERE id = ?1", user.user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query!("DELETE FROM recovery_codes WHERE user_id = ?1", user.user_id)
        .execute(&mut *tx)
        .await?;
    for c in &codes {
        let h = sha256_hex(c.as_bytes());
        sqlx::query!("INSERT INTO recovery_codes(user_id, code_hash) VALUES(?1, ?2)", user.user_id, h)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;

    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "2fa_enable", "").await;
    Ok(Json(json!({ "recovery_codes": codes })))
}

/// POST /api/2fa/disable — 需密码 + (TOTP 或恢复码)。
pub async fn disable(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionUser,
    Json(req): Json<DisableReq>,
) -> Result<Json<Value>, AppError> {
    let row = sqlx::query!(
        r#"SELECT pass_hash as "p!", totp_secret as "s!", totp_enabled as "e!: i64"
           FROM users WHERE id = ?1"#,
        user.user_id
    )
    .fetch_one(&st.db)
    .await?;
    if row.e == 0 {
        return Err(AppError::bad("两步验证未启用"));
    }
    let pass_ok = PasswordHash::new(&row.p)
        .map(|h| Argon2::default().verify_password(req.password.as_bytes(), &h).is_ok())
        .unwrap_or(false);
    if !pass_ok {
        return Err(AppError::bad("密码不正确"));
    }
    let code_ok = crate::totp::verify(&row.s, &req.code, unix_now())
        || consume_recovery(&st, user.user_id, &req.code).await;
    if !code_ok {
        return Err(AppError::bad("验证码或恢复码不正确"));
    }
    let mut tx = st.db.begin().await?;
    sqlx::query!("UPDATE users SET totp_enabled = 0, totp_secret = '' WHERE id = ?1", user.user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query!("DELETE FROM recovery_codes WHERE user_id = ?1", user.user_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "2fa_disable", "").await;
    Ok(Json(json!({ "ok": true })))
}

/// 校验并消费一个恢复码(一次性)。返回是否成功。
pub async fn consume_recovery(st: &AppState, user_id: i64, code: &str) -> bool {
    let code = code.trim();
    if code.len() != 10 || !outpost_common::is_lower_hex(code) {
        return false;
    }
    let h = sha256_hex(code.as_bytes());
    let now = unix_now();
    matches!(
        sqlx::query!(
            "UPDATE recovery_codes SET used_at = ?1
             WHERE user_id = ?2 AND code_hash = ?3 AND used_at IS NULL",
            now,
            user_id,
            h
        )
        .execute(&st.db)
        .await,
        Ok(r) if r.rows_affected() == 1
    )
}
