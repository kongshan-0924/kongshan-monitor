//! 账号管理(轻量 RBAC):admin 可增删账号、切换角色。全部端点仅 admin 可用。
//! viewer 是只读观察者——所有状态变更端点均已改用 [`SessionAdmin`](crate::session::SessionAdmin)
//! 拒绝其访问;本模块是 viewer 账号的唯一创建入口(注册引导 `/api/setup` 仅建管理员)。

use crate::audit;
use crate::errors::AppError;
use crate::handlers::auth::{check_password_strength, hash_password, valid_username};
use crate::session::SessionAdmin;
use crate::state::AppState;
use crate::util::{client_ip, unix_now};
use axum::extract::{ConnectInfo, Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;

const MAX_USERS: i64 = 50;

fn valid_role(r: &str) -> bool {
    r == "admin" || r == "viewer"
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateUserReq {
    username: String,
    password: String,
    role: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleReq {
    role: String,
}

/// GET /api/users
pub async fn list(State(st): State<AppState>, _u: SessionAdmin) -> Result<Json<Value>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT id as "id!", username as "username!", role as "role!", created_at as "created_at!"
           FROM users ORDER BY id"#
    )
    .fetch_all(&st.db)
    .await?;
    let items: Vec<Value> = rows
        .into_iter()
        .map(|r| json!({ "id": r.id, "username": r.username, "role": r.role, "created_at": r.created_at }))
        .collect();
    Ok(Json(json!({ "items": items })))
}

/// POST /api/users — 创建账号(admin 或 viewer)。
pub async fn create(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionAdmin,
    Json(req): Json<CreateUserReq>,
) -> Result<Json<Value>, AppError> {
    if !valid_username(&req.username) {
        return Err(AppError::bad("用户名需 3~32 位,仅限字母数字与 _.-"));
    }
    check_password_strength(&req.password)?;
    if !valid_role(&req.role) {
        return Err(AppError::bad("角色需为 admin 或 viewer"));
    }
    let cnt = sqlx::query_scalar!(r#"SELECT COUNT(*) as "c!: i64" FROM users"#)
        .fetch_one(&st.db)
        .await?;
    if cnt >= MAX_USERS {
        return Err(AppError::bad("账号数量已达上限"));
    }
    let hash = hash_password(&req.password)?;
    let now = unix_now();
    let res = sqlx::query!(
        "INSERT INTO users(username, pass_hash, created_at, role) VALUES(?1, ?2, ?3, ?4)",
        req.username,
        hash,
        now,
        req.role
    )
    .execute(&st.db)
    .await;
    let id = match res {
        Ok(r) => r.last_insert_rowid(),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(AppError::bad("用户名已存在"));
        }
        Err(e) => return Err(e.into()),
    };
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(
        &st.db,
        &user.username,
        &ip.to_string(),
        "user_create",
        &format!("{} role={}", req.username, req.role),
    )
    .await;
    Ok(Json(json!({ "id": id })))
}

/// POST /api/users/{id}/role — 切换角色(禁止把最后一个 admin 降级)。
pub async fn set_role(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionAdmin,
    Path(id): Path<i64>,
    Json(req): Json<RoleReq>,
) -> Result<Json<Value>, AppError> {
    if !valid_role(&req.role) {
        return Err(AppError::bad("角色需为 admin 或 viewer"));
    }
    if req.role == "viewer" {
        let other_admins = sqlx::query_scalar!(
            r#"SELECT COUNT(*) as "c!: i64" FROM users WHERE role = 'admin' AND id != ?1"#,
            id
        )
        .fetch_one(&st.db)
        .await?;
        if other_admins == 0 {
            return Err(AppError::bad("至少保留一个管理员账号"));
        }
    }
    let r = sqlx::query!("UPDATE users SET role = ?1 WHERE id = ?2", req.role, id)
        .execute(&st.db)
        .await?;
    if r.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    // 角色是安全态,变更后吊销该账号的其它会话(保留本次请求所用会话,避免操作者自锁)
    let _ = sqlx::query!(
        "DELETE FROM sessions WHERE user_id = ?1 AND token_hash != ?2",
        id,
        user.token_hash
    )
    .execute(&st.db)
    .await;
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "user_role_change", &format!("#{id} -> {}", req.role))
        .await;
    Ok(Json(json!({ "ok": true })))
}

/// DELETE /api/users/{id} — 不可删除自己,不可删除最后一个 admin。
pub async fn delete(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionAdmin,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    if id == user.user_id {
        return Err(AppError::bad("不能删除自己的账号"));
    }
    let target_role = sqlx::query_scalar!(r#"SELECT role as "role!" FROM users WHERE id = ?1"#, id)
        .fetch_optional(&st.db)
        .await?;
    let Some(target_role) = target_role else {
        return Err(AppError::NotFound);
    };
    if target_role == "admin" {
        let other_admins = sqlx::query_scalar!(
            r#"SELECT COUNT(*) as "c!: i64" FROM users WHERE role = 'admin' AND id != ?1"#,
            id
        )
        .fetch_one(&st.db)
        .await?;
        if other_admins == 0 {
            return Err(AppError::bad("至少保留一个管理员账号"));
        }
    }
    sqlx::query!("DELETE FROM users WHERE id = ?1", id).execute(&st.db).await?;
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "user_delete", &format!("#{id}")).await;
    Ok(Json(json!({ "ok": true })))
}
