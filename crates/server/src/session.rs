//! 服务端会话:随机 token → 仅存 SHA-256;Cookie HttpOnly + SameSite=Strict (+Secure)。
//! 选择服务端会话而非 JWT:可即时撤销(规范 4.1 推荐)。

use crate::errors::AppError;
use crate::state::AppState;
use crate::util::{cookie_value, ct_eq, gen_token_hex, sha256_hex, unix_now};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::HeaderMap;

/// 已认证用户(认证中间件的产物;所有受保护端点以它为参数,漏加即编译不过)。
#[derive(Debug, Clone)]
pub struct SessionUser {
    pub user_id: i64,
    pub username: String,
    pub token_hash: String,
    /// admin | viewer(轻量 RBAC;既有账号迁移后一律 admin)。
    pub role: String,
}

impl SessionUser {
    #[must_use]
    pub fn is_admin(&self) -> bool {
        self.role == "admin"
    }
}

/// 尝试从请求头恢复会话。
pub async fn try_session(st: &AppState, headers: &HeaderMap) -> Option<SessionUser> {
    let tok = cookie_value(headers, st.cfg.cookie_name())?;
    if tok.len() != 64 || !outpost_common::is_lower_hex(&tok) {
        return None;
    }
    let h = sha256_hex(tok.as_bytes());
    let row = sqlx::query!(
        r#"SELECT s.token_hash as "token_hash!", s.expires_at as "expires_at!",
                  u.id as "uid!", u.username as "username!", u.role as "role!"
           FROM sessions s JOIN users u ON u.id = s.user_id
           WHERE s.token_hash = ?1"#,
        h
    )
    .fetch_optional(&st.db)
    .await
    .ok()??;

    // 纵深防御:查库命中后再做常量时间比较
    if !ct_eq(&row.token_hash, &h) {
        return None;
    }
    if row.expires_at < unix_now() {
        let _ = sqlx::query!("DELETE FROM sessions WHERE token_hash = ?1", h)
            .execute(&st.db)
            .await;
        return None;
    }
    Some(SessionUser { user_id: row.uid, username: row.username, token_hash: h, role: row.role })
}

impl FromRequestParts<AppState> for SessionUser {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, AppError> {
        try_session(st, &parts.headers).await.ok_or(AppError::Unauthorized)
    }
}

/// 要求 admin 角色的提取器(轻量 RBAC):全部状态变更端点用它替代 [`SessionUser`],
/// viewer 会话会被拒绝(403)。`Deref` 到 `SessionUser`,处理函数体内字段访问方式不变。
#[derive(Debug, Clone)]
pub struct SessionAdmin(pub SessionUser);

impl std::ops::Deref for SessionAdmin {
    type Target = SessionUser;
    fn deref(&self) -> &SessionUser {
        &self.0
    }
}

impl FromRequestParts<AppState> for SessionAdmin {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, AppError> {
        let user = try_session(st, &parts.headers).await.ok_or(AppError::Unauthorized)?;
        if !user.is_admin() {
            return Err(AppError::Forbidden);
        }
        Ok(SessionAdmin(user))
    }
}

/// 新建会话,返回应下发的 Set-Cookie 值。
///
/// # Errors
/// 熵源不可用或数据库失败。
pub async fn create_session(
    st: &AppState,
    user_id: i64,
    ip: &str,
    user_agent: &str,
) -> Result<String, AppError> {
    let tok = gen_token_hex().map_err(|_| AppError::Internal)?;
    let h = sha256_hex(tok.as_bytes());
    let now = unix_now();
    let ttl = i64::from(st.cfg.security.session_ttl_hours) * 3600;
    let exp = now.saturating_add(ttl);
    let ua = outpost_common::clean_str(user_agent, 200);
    sqlx::query!(
        "INSERT INTO sessions(token_hash, user_id, created_at, expires_at, ip, user_agent)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        h,
        user_id,
        now,
        exp,
        ip,
        ua
    )
    .execute(&st.db)
    .await?;
    Ok(build_cookie(st, &tok, ttl))
}

/// 构造会话 Cookie 字符串。
fn build_cookie(st: &AppState, value: &str, max_age: i64) -> String {
    let name = st.cfg.cookie_name();
    let secure = if st.cfg.security.cookie_secure { "; Secure" } else { "" };
    format!("{name}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}{secure}")
}

/// 注销 Cookie(Max-Age=0)。
pub fn clear_cookie(st: &AppState) -> String {
    build_cookie(st, "", 0)
}
