//! 只读 API Token 管理(会话认证)。创建时明文仅返回一次,服务端只存哈希。

use crate::apiauth::TOKEN_PREFIX;
use crate::audit;
use crate::errors::AppError;
use crate::session::SessionAdmin;
use crate::state::AppState;
use crate::util::{client_ip, gen_token_hex, sha256_hex, unix_now};
use axum::extract::{ConnectInfo, Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;

const MAX_TOKENS: i64 = 50;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateReq {
    name: String,
}

/// GET /api/apitokens
pub async fn list(State(st): State<AppState>, _u: SessionAdmin) -> Result<Json<Value>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT id as "id!", name as "name!", created_at as "created_at!", last_used
           FROM api_tokens ORDER BY id DESC"#
    )
    .fetch_all(&st.db)
    .await?;
    let items: Vec<Value> = rows
        .into_iter()
        .map(|r| json!({ "id": r.id, "name": r.name, "created_at": r.created_at, "last_used": r.last_used }))
        .collect();
    Ok(Json(json!({ "items": items })))
}

/// POST /api/apitokens — 返回明文 token(仅此一次)。
pub async fn create(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionAdmin,
    Json(req): Json<CreateReq>,
) -> Result<Json<Value>, AppError> {
    let name = outpost_common::clean_str(&req.name, 64);
    if !outpost_common::valid_short_name(&name) {
        return Err(AppError::bad("名称需为 1~64 个可见字符"));
    }
    let cnt = sqlx::query_scalar!(r#"SELECT COUNT(*) as "c!: i64" FROM api_tokens"#)
        .fetch_one(&st.db)
        .await?;
    if cnt >= MAX_TOKENS {
        return Err(AppError::bad("API Token 数量已达上限"));
    }
    let token = format!("{TOKEN_PREFIX}{}", gen_token_hex().map_err(|_| AppError::Internal)?);
    let h = sha256_hex(token.as_bytes());
    let now = unix_now();
    let r = sqlx::query!(
        "INSERT INTO api_tokens(name, token_hash, created_at) VALUES(?1, ?2, ?3)",
        name,
        h,
        now
    )
    .execute(&st.db)
    .await?;
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "apitoken_create", &name).await;
    // 明文只此一次返回
    Ok(Json(json!({ "id": r.last_insert_rowid(), "token": token })))
}

/// DELETE /api/apitokens/{id}
pub async fn delete(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionAdmin,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    let r = sqlx::query!("DELETE FROM api_tokens WHERE id = ?1", id).execute(&st.db).await?;
    if r.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "apitoken_delete", &format!("#{id}")).await;
    Ok(Json(json!({ "ok": true })))
}
