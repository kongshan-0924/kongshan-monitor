//! 只读访问鉴权:接受【会话 Cookie】或【只读 API Token(Bearer)】其一。
//! 仅用于 GET 只读端点(Prometheus、v1 查询、导出),不授予任何写权限。

use crate::errors::AppError;
use crate::session::try_session;
use crate::state::AppState;
use crate::util::{ct_eq, sha256_hex, unix_now};
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{header, HeaderMap};

/// API Token 前缀,区别于节点 token(纯 64-hex)。
pub const TOKEN_PREFIX: &str = "opk_";

/// 只读鉴权证明。存在即表示请求已被授权只读访问。
pub struct ReadAuth;

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.trim().to_string())
}

/// 校验 API Token:格式 `opk_<64 hex>`;命中且常量时间比较通过则更新 last_used。
async fn check_api_token(st: &AppState, token: &str) -> bool {
    let Some(hex) = token.strip_prefix(TOKEN_PREFIX) else {
        return false;
    };
    if hex.len() != 64 || !outpost_common::is_lower_hex(hex) {
        return false;
    }
    let h = sha256_hex(token.as_bytes());
    let Ok(Some(row)) =
        sqlx::query!(r#"SELECT id as "id!", token_hash as "token_hash!" FROM api_tokens WHERE token_hash = ?1"#, h)
            .fetch_optional(&st.db)
            .await
    else {
        return false;
    };
    if !ct_eq(&row.token_hash, &h) {
        return false;
    }
    let now = unix_now();
    let _ = sqlx::query!("UPDATE api_tokens SET last_used = ?1 WHERE id = ?2", now, row.id)
        .execute(&st.db)
        .await;
    true
}

impl FromRequestParts<AppState> for ReadAuth {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, st: &AppState) -> Result<Self, AppError> {
        if try_session(st, &parts.headers).await.is_some() {
            return Ok(ReadAuth);
        }
        if let Some(tok) = bearer(&parts.headers) {
            if check_api_token(st, &tok).await {
                return Ok(ReadAuth);
            }
        }
        Err(AppError::Unauthorized)
    }
}
