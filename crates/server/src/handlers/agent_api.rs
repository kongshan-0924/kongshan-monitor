//! agent 侧公开端点:注册换 token、二进制清单与下载、CA 证书、安装脚本。
//! 这些端点不使用 Cookie 认证:注册凭一次性密钥,下载凭 SHA-256 校验完整性。

use crate::audit;
use crate::errors::AppError;
use crate::ratelimit::Class;
use crate::state::AppState;
use crate::util::{client_ip, ct_eq, gen_token_hex, sha256_hex, unix_now};
use axum::extract::{ConnectInfo, Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Form;
use serde::Deserialize;
use std::net::SocketAddr;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegisterForm {
    key: String,
}

/// POST /api/agent/register — 一次性密钥换长期 token(用后即焚,规范 6.3.3)。
/// 响应 text/plain `token=<hex>`,便于安装脚本解析,不含其他信息。
pub async fn register(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Form(req): Form<RegisterForm>,
) -> Result<Response, AppError> {
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    if !st.limiter.check(ip, Class::Register) {
        return Err(AppError::TooManyRequests);
    }
    // 密钥格式:64 位小写 hex;其余一律拒绝(不透露原因细节)
    if req.key.len() != 64 || !outpost_common::is_lower_hex(&req.key) {
        audit::log(&st.db, "", &ip.to_string(), "register_fail", "格式非法").await;
        return Err(AppError::Forbidden);
    }
    let key_hash = sha256_hex(req.key.as_bytes());
    let now = unix_now();

    let row = sqlx::query!(
        r#"SELECT id as "id!", node_id as "node_id!", key_hash as "key_hash!",
                  expires_at as "expires_at!", used_at
           FROM register_keys WHERE key_hash = ?1"#,
        key_hash
    )
    .fetch_optional(&st.db)
    .await?;

    let Some(r) = row else {
        audit::log(&st.db, "", &ip.to_string(), "register_fail", "密钥无效").await;
        return Err(AppError::Forbidden);
    };
    // 常量时间复核(规范 6.3.4)
    if !ct_eq(&r.key_hash, &key_hash) || r.used_at.is_some() || r.expires_at < now {
        audit::log(&st.db, "", &ip.to_string(), "register_fail", "密钥过期或已用").await;
        return Err(AppError::Forbidden);
    }

    // 原子标记已用,防并发双花
    let upd = sqlx::query!(
        "UPDATE register_keys SET used_at = ?1 WHERE id = ?2 AND used_at IS NULL AND expires_at >= ?1",
        now,
        r.id
    )
    .execute(&st.db)
    .await?;
    if upd.rows_affected() == 0 {
        return Err(AppError::Forbidden);
    }

    let token = gen_token_hex().map_err(|_| AppError::Internal)?;
    let token_hash = sha256_hex(token.as_bytes());
    sqlx::query!(
        "UPDATE nodes SET token_hash = ?1, revoked = 0, registered_at = ?2 WHERE id = ?3",
        token_hash,
        now,
        r.node_id
    )
    .execute(&st.db)
    .await?;

    audit::log(&st.db, "", &ip.to_string(), "register_ok", &format!("node#{}", r.node_id)).await;
    tracing::info!(node_id = r.node_id, "agent 注册成功");

    // token 仅此一次以明文经 TLS 返回给安装脚本;服务端只存哈希
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!("token={token}\n"),
    )
        .into_response())
}

/// GET /api/agent/manifest — 行式清单:`<target> <sha256> <path>`,shell 友好。
pub async fn manifest(State(st): State<AppState>) -> Response {
    let mut body = String::new();
    for a in &st.artifacts {
        body.push_str(&format!("{} {} /download/{}\n", a.target, a.sha256, a.filename));
    }
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        body,
    )
        .into_response()
}

/// GET /download/{name} — 仅允许启动时扫描登记的白名单文件名(无路径遍历可能)。
pub async fn download(
    State(st): State<AppState>,
    Path(name): Path<String>,
) -> Result<Response, AppError> {
    let Some(a) = st.artifacts.iter().find(|a| a.filename == name) else {
        return Err(AppError::NotFound);
    };
    let path = std::path::Path::new(&st.cfg.install.dist_dir).join(&a.filename);
    let bytes = tokio::fs::read(&path).await.map_err(|e| {
        tracing::error!(error = %e, "读取分发文件失败");
        AppError::Internal
    })?;
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/octet-stream".to_string()),
            (
                header::CONTENT_DISPOSITION,
                format!("attachment; filename=\"{}\"", a.filename),
            ),
        ],
        bytes,
    )
        .into_response())
}

/// GET /ca.pem — 私有 CA 证书(pinned_ca 模式;安装命令中的指纹与之比对)。
pub async fn ca_pem(State(st): State<AppState>) -> Result<Response, AppError> {
    let Some(pem) = &st.ca_pem else { return Err(AppError::NotFound) };
    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/x-pem-file")],
        pem.clone(),
    )
        .into_response())
}

/// GET /install.sh、/uninstall.sh — 静态可审计脚本。
pub async fn install_sh() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        include_str!("../../static/install.sh"),
    )
        .into_response()
}

pub async fn uninstall_sh() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        include_str!("../../static/uninstall.sh"),
    )
        .into_response()
}

pub async fn upgrade_sh() -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        include_str!("../../static/upgrade.sh"),
    )
        .into_response()
}

/// GET /healthz — 健康检查,不泄露任何信息(规范阶段1)。
pub async fn healthz() -> &'static str {
    "ok"
}
