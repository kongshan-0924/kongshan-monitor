//! 会话/设备管理 + SQLite 一致性备份。会话认证。

use crate::audit;
use crate::errors::AppError;
use crate::session::{SessionAdmin, SessionUser};
use crate::state::AppState;
use crate::util::{client_ip, unix_now};
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use std::net::SocketAddr;

/// GET /api/sessions — 当前用户的活跃会话列表。
/// 暴露 token_hash(SHA-256,不可逆,非 Cookie 本身),用作管理标识。
pub async fn list_sessions(
    State(st): State<AppState>,
    user: SessionUser,
) -> Result<Json<Value>, AppError> {
    let now = unix_now();
    let rows = sqlx::query!(
        r#"SELECT token_hash as "token_hash!", created_at as "created_at!",
                  expires_at as "expires_at!", ip as "ip!", user_agent as "user_agent!"
           FROM sessions WHERE user_id = ?1 AND expires_at > ?2 ORDER BY created_at DESC"#,
        user.user_id,
        now
    )
    .fetch_all(&st.db)
    .await?;
    let items: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                // 短标识仅用于展示;撤销用完整 hash
                "sid": r.token_hash.get(..16).unwrap_or(""),
                "token_hash": r.token_hash,
                "current": r.token_hash == user.token_hash,
                "created_at": r.created_at,
                "expires_at": r.expires_at,
                "ip": r.ip,
                "user_agent": r.user_agent,
            })
        })
        .collect();
    Ok(Json(json!({ "items": items })))
}

/// DELETE /api/sessions/{token_hash} — 撤销指定会话(仅本人的)。
pub async fn revoke_session(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionUser,
    Path(token_hash): Path<String>,
) -> Result<Json<Value>, AppError> {
    // 仅接受 64 位 hex,避免任意输入
    if token_hash.len() != 64 || !outpost_common::is_lower_hex(&token_hash) {
        return Err(AppError::bad("标识非法"));
    }
    // 限定当前用户,防越权撤销他人会话
    let r = sqlx::query!(
        "DELETE FROM sessions WHERE token_hash = ?1 AND user_id = ?2",
        token_hash,
        user.user_id
    )
    .execute(&st.db)
    .await?;
    if r.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "session_revoke", "").await;
    Ok(Json(json!({ "ok": true })))
}

/// GET /api/backup — 一致性快照(VACUUM INTO 临时文件后回传)。
/// 纯读操作;不提供在线恢复端点(恢复须离线替换文件,详见 README)。
pub async fn backup(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionAdmin,
) -> Result<Response, AppError> {
    // 临时文件放在 db 同目录(同一挂载,保证 VACUUM INTO 可写)
    let base = std::path::Path::new(&st.cfg.storage.db_path);
    let dir = base.parent().unwrap_or_else(|| std::path::Path::new("."));
    // 固定命名 + 先行删除,避免可预测并发;仅本进程使用
    let tmp = dir.join(".outpost-backup.tmp");
    let _ = tokio::fs::remove_file(&tmp).await;
    let tmp_str = tmp.to_string_lossy().to_string();

    // VACUUM INTO 生成一致性副本(参数化路径)
    let q = format!("VACUUM INTO '{}'", tmp_str.replace('\'', "''"));
    if let Err(e) = sqlx::query(&q).execute(&st.db).await {
        tracing::error!(error = %e, "备份 VACUUM 失败");
        return Err(AppError::Internal);
    }
    let bytes = match tokio::fs::read(&tmp).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!(error = %e, "读取备份失败");
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(AppError::Internal);
        }
    };
    let _ = tokio::fs::remove_file(&tmp).await;

    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "backup_download", &format!("{} bytes", bytes.len())).await;

    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"outpost-backup.db\"".to_string()),
        ],
        bytes,
    )
        .into_response())
}
