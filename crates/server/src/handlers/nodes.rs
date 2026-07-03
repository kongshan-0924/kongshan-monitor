//! 节点管理:创建(生成一次性注册密钥+安装命令)、列表、详情、历史、
//! 重命名、吊销 token、重置密钥、删除。全部要求已认证会话。

use crate::audit;
use crate::errors::AppError;
use crate::session::SessionUser;
use crate::state::AppState;
use crate::util::{client_ip, gen_token_hex, sha256_hex, unix_now};
use axum::extract::{ConnectInfo, Path, Query, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;

const REGISTER_KEY_TTL_SECS: i64 = 30 * 60;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateNodeReq {
    name: String,
    #[serde(default)]
    grp: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenameReq {
    name: String,
    #[serde(default)]
    grp: String,
    #[serde(default)]
    note: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryQuery {
    /// 拉取最近多少秒(300..=30天)。
    secs: i64,
}

fn validate_node_name(name: &str) -> Result<String, AppError> {
    let n = outpost_common::clean_str(name, 64);
    if !outpost_common::valid_short_name(&n) {
        return Err(AppError::bad("节点名需为 1~64 个可见字符"));
    }
    Ok(n)
}

/// 渲染一键安装命令(密钥仅此一次返回,不落库明文)。
fn render_install_command(st: &AppState, key: &str) -> String {
    let url = st.cfg.server.public_url.trim_end_matches('/');
    match (st.cfg.install.mode.as_str(), &st.ca_fingerprint) {
        ("pinned_ca", Some(fpr)) => format!(
            "sh -c 'set -eu; U=\"{url}\"; F=\"{fpr}\"; D=\"$(mktemp -d)\"; cd \"$D\"; \
             curl -fsSk \"$U/ca.pem\" -o ca.pem; echo \"$F  ca.pem\" | sha256sum -c - >/dev/null; \
             curl -fsS --cacert ca.pem \"$U/install.sh\" -o install.sh; \
             sh install.sh --server \"$U\" --ca \"$D/ca.pem\" --key \"{key}\"'"
        ),
        _ => format!(
            "sh -c 'set -eu; U=\"{url}\"; D=\"$(mktemp -d)\"; cd \"$D\"; \
             curl -fsS \"$U/install.sh\" -o install.sh; \
             sh install.sh --server \"$U\" --key \"{key}\"'"
        ),
    }
}

/// GET /api/upgrade_command — 渲染 agent 升级一键命令(会话认证,仅输出文本不执行)。
pub async fn upgrade_command(
    State(st): State<AppState>,
    _user: SessionUser,
) -> Result<Json<Value>, AppError> {
    let url = st.cfg.server.public_url.trim_end_matches('/');
    let cmd = match (st.cfg.install.mode.as_str(), &st.ca_fingerprint) {
        ("pinned_ca", Some(fpr)) => format!(
            "sh -c 'set -eu; U=\"{url}\"; F=\"{fpr}\"; D=\"$(mktemp -d)\"; cd \"$D\"; \
             curl -fsSk \"$U/ca.pem\" -o ca.pem; echo \"$F  ca.pem\" | sha256sum -c - >/dev/null; \
             curl -fsS --cacert ca.pem \"$U/upgrade.sh\" -o upgrade.sh; \
             sh upgrade.sh --server \"$U\" --ca \"$D/ca.pem\"'"
        ),
        _ => format!(
            "sh -c 'set -eu; U=\"{url}\"; D=\"$(mktemp -d)\"; cd \"$D\"; \
             curl -fsS \"$U/upgrade.sh\" -o upgrade.sh; sh upgrade.sh --server \"$U\"'"
        ),
    };
    Ok(Json(json!({ "command": cmd, "expected": env!("CARGO_PKG_VERSION") })))
}

/// 为节点生成新的一次性注册密钥(替换旧密钥)。
async fn issue_register_key(st: &AppState, node_id: i64) -> Result<(String, i64), AppError> {
    let key = gen_token_hex().map_err(|_| AppError::Internal)?;
    let key_hash = sha256_hex(key.as_bytes());
    let exp = unix_now().saturating_add(REGISTER_KEY_TTL_SECS);
    sqlx::query!("DELETE FROM register_keys WHERE node_id = ?1", node_id)
        .execute(&st.db)
        .await?;
    sqlx::query!(
        "INSERT INTO register_keys(node_id, key_hash, expires_at) VALUES(?1, ?2, ?3)",
        node_id,
        key_hash,
        exp
    )
    .execute(&st.db)
    .await?;
    Ok((key, exp))
}

/// POST /api/nodes — 创建节点并返回一次性密钥与安装命令。
pub async fn create(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionUser,
    Json(req): Json<CreateNodeReq>,
) -> Result<Json<Value>, AppError> {
    let name = validate_node_name(&req.name)?;
    let grp = outpost_common::clean_str(&req.grp, 32);
    let now = unix_now();
    let res = sqlx::query!(
        "INSERT INTO nodes(name, grp, created_at) VALUES(?1, ?2, ?3)",
        name,
        grp,
        now
    )
    .execute(&st.db)
    .await;
    let node_id = match res {
        Ok(r) => r.last_insert_rowid(),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(AppError::bad("同名节点已存在"));
        }
        Err(e) => return Err(e.into()),
    };
    let (key, exp) = issue_register_key(&st, node_id).await?;
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "node_create", &name).await;
    Ok(Json(json!({
        "id": node_id,
        "name": name,
        "key": key,
        "expires_at": exp,
        "command": render_install_command(&st, &key),
    })))
}

/// 节点行 → 概览 JSON(附最新一条指标)。
async fn node_summary(st: &AppState, interval: i64) -> Result<Vec<Value>, AppError> {
    let now = unix_now();
    // 正在告警的节点集合(用于高亮/置顶)
    let firing_rows = sqlx::query!(
        r#"SELECT DISTINCT node_id as "node_id!" FROM alert_events WHERE resolved_at IS NULL"#
    )
    .fetch_all(&st.db)
    .await?;
    let firing: std::collections::HashSet<i64> = firing_rows.into_iter().map(|r| r.node_id).collect();
    let rows = sqlx::query!(
        r#"SELECT id as "id!", name as "name!", grp as "grp!", revoked as "revoked!: i64",
                  token_hash, registered_at, last_seen,
                  hostname as "hostname!", os as "os!", kernel as "kernel!", arch as "arch!",
                  cores as "cores!: i64", mem_total as "mem_total!: i64",
                  agent_version as "agent_version!"
           FROM nodes ORDER BY id"#
    )
    .fetch_all(&st.db)
    .await?;

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let latest = sqlx::query!(
            r#"SELECT ts as "ts!", cpu_pct as "cpu_pct!: f64", load1 as "load1!: f64",
                      load5 as "load5!: f64", load15 as "load15!: f64",
                      mem_total as "mem_total!: i64", mem_used as "mem_used!: i64",
                      swap_total as "swap_total!: i64", swap_used as "swap_used!: i64",
                      disk_total as "disk_total!: i64", disk_used as "disk_used!: i64",
                      net_rx_bps as "net_rx_bps!: i64", net_tx_bps as "net_tx_bps!: i64",
                      disk_read_bps as "disk_read_bps!: i64", disk_write_bps as "disk_write_bps!: i64",
                      uptime_secs as "uptime_secs!: i64", procs as "procs!: i64"
               FROM metrics WHERE node_id = ?1 ORDER BY ts DESC LIMIT 1"#,
            r.id
        )
        .fetch_optional(&st.db)
        .await?;

        let online = r
            .last_seen
            .is_some_and(|ls| now.saturating_sub(ls) <= interval.saturating_mul(3).max(10));
        out.push(json!({
            "id": r.id,
            "name": r.name,
            "grp": r.grp,
            "online": online,
            "alerting": firing.contains(&r.id),
            "revoked": r.revoked != 0,
            "registered": r.token_hash.is_some(),
            "registered_at": r.registered_at,
            "last_seen": r.last_seen,
            "hostname": r.hostname,
            "os": r.os,
            "kernel": r.kernel,
            "arch": r.arch,
            "cores": r.cores,
            "mem_total": r.mem_total,
            "agent_version": r.agent_version,
            "latest": latest.map(|m| json!({
                "ts": m.ts, "cpu_pct": m.cpu_pct,
                "load1": m.load1, "load5": m.load5, "load15": m.load15,
                "mem_total": m.mem_total, "mem_used": m.mem_used,
                "swap_total": m.swap_total, "swap_used": m.swap_used,
                "disk_total": m.disk_total, "disk_used": m.disk_used,
                "net_rx_bps": m.net_rx_bps, "net_tx_bps": m.net_tx_bps,
                "disk_read_bps": m.disk_read_bps, "disk_write_bps": m.disk_write_bps,
                "uptime_secs": m.uptime_secs, "procs": m.procs,
            })),
        }));
    }
    Ok(out)
}

/// GET /api/nodes
pub async fn list(
    State(st): State<AppState>,
    _user: SessionUser,
) -> Result<Json<Value>, AppError> {
    let interval = crate::db::setting_i64(&st.db, "report_interval_secs", 5, 1, 3600).await;
    let nodes = node_summary(&st, interval).await?;
    Ok(Json(json!({
        "now": unix_now(),
        "interval": interval,
        "expected_agent": env!("CARGO_PKG_VERSION"),
        "nodes": nodes,
    })))
}

/// GET /api/nodes/{id}
pub async fn detail(
    State(st): State<AppState>,
    _user: SessionUser,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    let r = sqlx::query!(
        r#"SELECT id as "id!", name as "name!", grp as "grp!", note as "note!", revoked as "revoked!: i64",
                  token_hash, created_at as "created_at!", registered_at, last_seen,
                  hostname as "hostname!", os as "os!", kernel as "kernel!", arch as "arch!",
                  cores as "cores!: i64", mem_total as "mem_total!: i64",
                  agent_version as "agent_version!"
           FROM nodes WHERE id = ?1"#,
        id
    )
    .fetch_optional(&st.db)
    .await?
    .ok_or(AppError::NotFound)?;

    let latest = sqlx::query!(
        r#"SELECT ts as "ts!", cpu_pct as "cpu_pct!: f64", load1 as "load1!: f64",
                  load5 as "load5!: f64", load15 as "load15!: f64",
                  mem_total as "mem_total!: i64", mem_used as "mem_used!: i64",
                  mem_available as "mem_available!: i64",
                  swap_total as "swap_total!: i64", swap_used as "swap_used!: i64",
                  disk_total as "disk_total!: i64", disk_used as "disk_used!: i64",
                  net_rx_bps as "net_rx_bps!: i64", net_tx_bps as "net_tx_bps!: i64",
                  disk_read_bps as "disk_read_bps!: i64", disk_write_bps as "disk_write_bps!: i64",
                  uptime_secs as "uptime_secs!: i64", procs as "procs!: i64", detail as "detail!"
           FROM metrics WHERE node_id = ?1 ORDER BY ts DESC LIMIT 1"#,
        id
    )
    .fetch_optional(&st.db)
    .await?;

    let interval = crate::db::setting_i64(&st.db, "report_interval_secs", 5, 1, 3600).await;
    let now = unix_now();
    let online = r
        .last_seen
        .is_some_and(|ls| now.saturating_sub(ls) <= interval.saturating_mul(3).max(10));

    Ok(Json(json!({
        "node": {
            "id": r.id, "name": r.name, "grp": r.grp, "note": r.note,
            "online": online, "revoked": r.revoked != 0,
            "registered": r.token_hash.is_some(),
            "created_at": r.created_at, "registered_at": r.registered_at,
            "last_seen": r.last_seen,
            "hostname": r.hostname, "os": r.os, "kernel": r.kernel, "arch": r.arch,
            "cores": r.cores, "mem_total": r.mem_total, "agent_version": r.agent_version,
        },
        "latest": latest.map(|m| json!({
            "ts": m.ts, "cpu_pct": m.cpu_pct,
            "load1": m.load1, "load5": m.load5, "load15": m.load15,
            "mem_total": m.mem_total, "mem_used": m.mem_used, "mem_available": m.mem_available,
            "swap_total": m.swap_total, "swap_used": m.swap_used,
            "disk_total": m.disk_total, "disk_used": m.disk_used,
            "net_rx_bps": m.net_rx_bps, "net_tx_bps": m.net_tx_bps,
            "disk_read_bps": m.disk_read_bps, "disk_write_bps": m.disk_write_bps,
            "uptime_secs": m.uptime_secs, "procs": m.procs,
            // detail 为服务端入库前清洗后生成的 JSON,解析失败则给空对象
            "detail": serde_json::from_str::<Value>(&m.detail).unwrap_or_else(|_| json!({})),
        })),
        "interval": interval,
    })))
}

/// GET /api/nodes/{id}/metrics?secs=3600 — 历史曲线(自动按桶聚合)。
pub async fn history(
    State(st): State<AppState>,
    _user: SessionUser,
    Path(id): Path<i64>,
    Query(q): Query<HistoryQuery>,
) -> Result<Json<Value>, AppError> {
    let secs = q.secs.clamp(300, 30 * 86400);
    let since = unix_now().saturating_sub(secs);
    // 目标 ~360 个点;步长向上取整到至少 1 秒
    let step = (secs / 360).max(1);
    let rows = sqlx::query!(
        r#"SELECT (ts / ?1) * ?1 as "t!: i64",
                  AVG(cpu_pct) as "cpu!: f64",
                  AVG(mem_used) as "mem_used!: f64", MAX(mem_total) as "mem_total!: i64",
                  AVG(net_rx_bps) as "rx!: f64", AVG(net_tx_bps) as "tx!: f64",
                  AVG(disk_read_bps) as "dr!: f64", AVG(disk_write_bps) as "dw!: f64",
                  AVG(load1) as "load1!: f64"
           FROM metrics WHERE node_id = ?2 AND ts >= ?3
           GROUP BY 1 ORDER BY 1"#,
        step,
        id,
        since
    )
    .fetch_all(&st.db)
    .await?;

    let points: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!([r.t, r.cpu, r.mem_used, r.mem_total, r.rx, r.tx, r.dr, r.dw, r.load1])
        })
        .collect();
    Ok(Json(json!({ "step": step, "points": points })))
}

/// POST /api/nodes/{id}/rename
pub async fn rename(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionUser,
    Path(id): Path<i64>,
    Json(req): Json<RenameReq>,
) -> Result<Json<Value>, AppError> {
    let name = validate_node_name(&req.name)?;
    let grp = outpost_common::clean_str(&req.grp, 32);
    let note = outpost_common::clean_str(&req.note, 200);
    let res = sqlx::query!(
        "UPDATE nodes SET name = ?1, grp = ?2, note = ?3 WHERE id = ?4",
        name,
        grp,
        note,
        id
    )
    .execute(&st.db)
    .await;
    match res {
        Ok(r) if r.rows_affected() == 1 => {}
        Ok(_) => return Err(AppError::NotFound),
        Err(sqlx::Error::Database(e)) if e.is_unique_violation() => {
            return Err(AppError::bad("同名节点已存在"));
        }
        Err(e) => return Err(e.into()),
    }
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "node_rename", &format!("#{id} -> {name}")).await;
    Ok(Json(json!({ "ok": true })))
}

/// POST /api/nodes/{id}/revoke — 吊销 token(即时生效:上报路径校验 revoked)。
pub async fn revoke(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionUser,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    let res = sqlx::query!("UPDATE nodes SET revoked = 1 WHERE id = ?1", id)
        .execute(&st.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    // 同时作废未使用的注册密钥
    sqlx::query!("DELETE FROM register_keys WHERE node_id = ?1", id)
        .execute(&st.db)
        .await?;
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "token_revoke", &format!("#{id}")).await;
    Ok(Json(json!({ "ok": true })))
}

/// POST /api/nodes/{id}/regen_key — 吊销旧 token 并签发新一次性密钥。
pub async fn regen_key(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionUser,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    let res = sqlx::query!("UPDATE nodes SET revoked = 1 WHERE id = ?1", id)
        .execute(&st.db)
        .await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    let (key, exp) = issue_register_key(&st, id).await?;
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "key_regen", &format!("#{id}")).await;
    Ok(Json(json!({
        "id": id,
        "key": key,
        "expires_at": exp,
        "command": render_install_command(&st, &key),
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchReq {
    /// delete | revoke | set_group
    action: String,
    ids: Vec<i64>,
    #[serde(default)]
    grp: String,
}

/// POST /api/nodes/batch — 批量操作(逐条走同样的校验与审计,限单次条数)。
pub async fn batch(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionUser,
    Json(req): Json<BatchReq>,
) -> Result<Json<Value>, AppError> {
    if req.ids.is_empty() || req.ids.len() > 100 {
        return Err(AppError::bad("批量操作数量需为 1~100"));
    }
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips()).to_string();
    let mut affected = 0u64;
    match req.action.as_str() {
        "delete" => {
            for id in &req.ids {
                let r = sqlx::query!("DELETE FROM nodes WHERE id = ?1", id).execute(&st.db).await?;
                if r.rows_affected() == 1 {
                    crate::alerts::forget_node(&st, *id);
                    affected += 1;
                }
            }
        }
        "revoke" => {
            for id in &req.ids {
                let r = sqlx::query!("UPDATE nodes SET revoked = 1 WHERE id = ?1", id)
                    .execute(&st.db)
                    .await?;
                if r.rows_affected() == 1 {
                    let _ = sqlx::query!("DELETE FROM register_keys WHERE node_id = ?1", id)
                        .execute(&st.db)
                        .await;
                    affected += 1;
                }
            }
        }
        "set_group" => {
            let grp = outpost_common::clean_str(&req.grp, 32);
            for id in &req.ids {
                let r = sqlx::query!("UPDATE nodes SET grp = ?1 WHERE id = ?2", grp, id)
                    .execute(&st.db)
                    .await?;
                affected += u64::from(r.rows_affected() == 1);
            }
        }
        _ => return Err(AppError::bad("不支持的批量操作")),
    }
    audit::log(
        &st.db,
        &user.username,
        &ip,
        "node_batch",
        &format!("{} x{} affected={}", req.action, req.ids.len(), affected),
    )
    .await;
    Ok(Json(json!({ "ok": true, "affected": affected })))
}

/// DELETE /api/nodes/{id} — 级联删除指标与密钥,token 随之失效。
pub async fn delete(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionUser,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    let res = sqlx::query!("DELETE FROM nodes WHERE id = ?1", id).execute(&st.db).await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    crate::alerts::forget_node(&st, id); // 告警事件/规则随级联删除,清运行态
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "node_delete", &format!("#{id}")).await;
    Ok(Json(json!({ "ok": true })))
}
