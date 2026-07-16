//! 节点管理:创建(生成一次性注册密钥+安装命令)、列表、详情、历史、
//! 重命名、吊销 token、重置密钥、删除。全部要求已认证会话。

use crate::audit;
use crate::errors::AppError;
use crate::session::{SessionAdmin, SessionUser};
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
    /// 流量统计是否按月清零(不启用则累计计数器一直增长,不清零)。
    #[serde(default)]
    traffic_reset_enabled: bool,
    /// 每月第几天清零(1~28)。
    #[serde(default = "default_reset_day")]
    traffic_reset_day: i64,
}

fn default_reset_day() -> i64 {
    1
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenameReq {
    name: String,
    #[serde(default)]
    grp: String,
    #[serde(default)]
    note: String,
    #[serde(default)]
    traffic_reset_enabled: bool,
    #[serde(default = "default_reset_day")]
    traffic_reset_day: i64,
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
    let public_url = st.public_url();
    let url = public_url.trim_end_matches('/');
    match (st.cfg.install.mode.as_str(), &st.ca_fingerprint) {
        ("pinned_ca", Some(fpr)) => format!(
            "sh -c 'set -eu; U=\"{url}\"; F=\"{fpr}\"; D=\"$(mktemp -d)\"; cd \"$D\"; \
             curl -fsSk \"$U/ca.pem\" -o ca.pem; echo \"$F  ca.pem\" | sha256sum -c - >/dev/null; \
             curl -fsS --cacert ca.pem \"$U/install.sh\" -o install.sh; \
             OP_KEY=\"{key}\" sh install.sh --server \"$U\" --ca \"$D/ca.pem\"'"
        ),
        _ => format!(
            "sh -c 'set -eu; U=\"{url}\"; D=\"$(mktemp -d)\"; cd \"$D\"; \
             curl -fsS \"$U/install.sh\" -o install.sh; \
             OP_KEY=\"{key}\" sh install.sh --server \"$U\"'"
        ),
    }
}

/// GET /api/upgrade_command — 渲染 agent 升级一键命令(会话认证,仅输出文本不执行)。
pub async fn upgrade_command(
    State(st): State<AppState>,
    _user: SessionUser,
) -> Result<Json<Value>, AppError> {
    let public_url = st.public_url();
    let url = public_url.trim_end_matches('/');
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
    user: SessionAdmin,
    Json(req): Json<CreateNodeReq>,
) -> Result<Json<Value>, AppError> {
    let name = validate_node_name(&req.name)?;
    let grp = outpost_common::clean_str(&req.grp, 32);
    if req.traffic_reset_enabled && !crate::traffic::valid_reset_day(req.traffic_reset_day) {
        return Err(AppError::bad("每月清零日需在 1~28 之间"));
    }
    let now = unix_now();
    let reset_enabled = i64::from(req.traffic_reset_enabled);
    let period_start = if req.traffic_reset_enabled {
        crate::traffic::current_period_start(now, req.traffic_reset_day)
    } else {
        0
    };
    let res = sqlx::query!(
        "INSERT INTO nodes(name, grp, created_at, traffic_reset_enabled, traffic_reset_day, traffic_period_start, sort_order)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, (SELECT COALESCE(MAX(sort_order), 0) + 1 FROM nodes))",
        name,
        grp,
        now,
        reset_enabled,
        req.traffic_reset_day,
        period_start
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
        r#"SELECT id as "id!", name as "name!", grp as "grp!", note as "note!", revoked as "revoked!: i64",
                  token_hash, registered_at, last_seen,
                  hostname as "hostname!", os as "os!", kernel as "kernel!", arch as "arch!",
                  cores as "cores!: i64", mem_total as "mem_total!: i64",
                  agent_version as "agent_version!", last_ip as "last_ip!",
                  traffic_rx_total as "traffic_rx_total!: i64", traffic_tx_total as "traffic_tx_total!: i64",
                  traffic_period_start as "traffic_period_start!: i64",
                  traffic_reset_enabled as "traffic_reset_enabled!: i64",
                  traffic_reset_day as "traffic_reset_day!: i64",
                  sort_order as "sort_order!: i64"
           FROM nodes ORDER BY id"#
    )
    .fetch_all(&st.db)
    .await?;

    // 单条查询取每个节点的最新指标(按 ts),避免此前"每节点一次串行 await"的 N+1。
    // JOIN 子查询按 node_id GROUP BY 取 MAX(ts);配合 UNIQUE(node_id,ts) 保证每节点一行。
    let latest_rows = sqlx::query!(
        r#"SELECT m.node_id as "node_id!: i64", m.ts as "ts!", m.cpu_pct as "cpu_pct!: f64",
                  m.load1 as "load1!: f64", m.load5 as "load5!: f64", m.load15 as "load15!: f64",
                  m.mem_total as "mem_total!: i64", m.mem_used as "mem_used!: i64",
                  m.swap_total as "swap_total!: i64", m.swap_used as "swap_used!: i64",
                  m.disk_total as "disk_total!: i64", m.disk_used as "disk_used!: i64",
                  m.net_rx_bps as "net_rx_bps!: i64", m.net_tx_bps as "net_tx_bps!: i64",
                  m.disk_read_bps as "disk_read_bps!: i64", m.disk_write_bps as "disk_write_bps!: i64",
                  m.uptime_secs as "uptime_secs!: i64", m.procs as "procs!: i64"
           FROM metrics m
           JOIN (SELECT node_id, MAX(ts) AS mts FROM metrics GROUP BY node_id) t
             ON t.node_id = m.node_id AND t.mts = m.ts"#
    )
    .fetch_all(&st.db)
    .await?;
    let latest_by_node: std::collections::HashMap<i64, _> =
        latest_rows.into_iter().map(|m| (m.node_id, m)).collect();

    let mut out = Vec::with_capacity(rows.len());
    for r in rows {
        let latest = latest_by_node.get(&r.id);

        let online = r
            .last_seen
            .is_some_and(|ls| now.saturating_sub(ls) <= interval.saturating_mul(3).max(10));
        out.push(json!({
            "id": r.id,
            "name": r.name,
            "grp": r.grp,
            "note": r.note,
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
            "last_ip": r.last_ip,
            "traffic_rx_total": r.traffic_rx_total,
            "traffic_tx_total": r.traffic_tx_total,
            "traffic_period_start": r.traffic_period_start,
            "traffic_reset_enabled": r.traffic_reset_enabled != 0,
            "traffic_reset_day": r.traffic_reset_day,
            "sort_order": r.sort_order,
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
                  agent_version as "agent_version!", last_ip as "last_ip!",
                  traffic_rx_total as "traffic_rx_total!: i64", traffic_tx_total as "traffic_tx_total!: i64",
                  traffic_period_start as "traffic_period_start!: i64",
                  traffic_reset_enabled as "traffic_reset_enabled!: i64",
                  traffic_reset_day as "traffic_reset_day!: i64"
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
            "last_ip": r.last_ip,
            "traffic_rx_total": r.traffic_rx_total, "traffic_tx_total": r.traffic_tx_total,
            "traffic_period_start": r.traffic_period_start,
            "traffic_reset_enabled": r.traffic_reset_enabled != 0,
            "traffic_reset_day": r.traffic_reset_day,
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

/// GET /api/overview/trend?secs=3600 — 全体节点汇总趋势
/// (每桶:CPU 跨节点均值、内存跨节点合计)。近期查原始表,>2 天查聚合表。
pub async fn overview_trend(
    State(st): State<AppState>,
    _user: SessionUser,
    Query(q): Query<HistoryQuery>,
) -> Result<Json<Value>, AppError> {
    let secs = q.secs.clamp(300, 366 * 86400);
    let since = unix_now().saturating_sub(secs);
    let step = (secs / 240).max(1);
    // 先按 (桶, 节点) 归一,再跨节点聚合,避免同节点桶内多点导致内存被重复累加
    let points: Vec<Value> = if secs > 2 * 86400 {
        let bstep = step.max(3600);
        let rows = sqlx::query!(
            r#"SELECT t as "t!: i64", AVG(cpu) as "cpu!: f64",
                      SUM(mu) as "mem_used!: f64", SUM(mt) as "mem_total!: f64"
               FROM (SELECT (hour_ts / ?1) * ?1 AS t, node_id,
                            AVG(cpu_avg) AS cpu, AVG(mem_used_avg) AS mu, MAX(mem_total_max) AS mt
                     FROM metrics_rollup WHERE hour_ts >= ?2 GROUP BY t, node_id)
               GROUP BY t ORDER BY t"#,
            bstep,
            since
        )
        .fetch_all(&st.db)
        .await?;
        rows.into_iter().map(|r| json!([r.t, r.cpu, r.mem_used, r.mem_total])).collect()
    } else {
        let rows = sqlx::query!(
            r#"SELECT t as "t!: i64", AVG(cpu) as "cpu!: f64",
                      SUM(mu) as "mem_used!: f64", SUM(mt) as "mem_total!: f64"
               FROM (SELECT (ts / ?1) * ?1 AS t, node_id,
                            AVG(cpu_pct) AS cpu, AVG(mem_used) AS mu, MAX(mem_total) AS mt
                     FROM metrics WHERE ts >= ?2 GROUP BY t, node_id)
               GROUP BY t ORDER BY t"#,
            step,
            since
        )
        .fetch_all(&st.db)
        .await?;
        rows.into_iter().map(|r| json!([r.t, r.cpu, r.mem_used, r.mem_total])).collect()
    };
    Ok(Json(json!({ "step": step, "points": points })))
}

/// GET /api/nodes/{id}/metrics?secs=3600 — 历史曲线(自动按桶聚合)。
/// 近期(≤2 天)查原始 metrics 表(高分辨率);更长范围查小时聚合表 metrics_rollup
/// (原始表清理后仍可看长历史,且避免对大表全量扫描)。
pub async fn history(
    State(st): State<AppState>,
    _user: SessionUser,
    Path(id): Path<i64>,
    Query(q): Query<HistoryQuery>,
) -> Result<Json<Value>, AppError> {
    let secs = q.secs.clamp(300, 366 * 86400);
    let since = unix_now().saturating_sub(secs);
    // 目标 ~360 个点;步长向上取整到至少 1 秒
    let step = (secs / 360).max(1);

    // 阈值:超过 2 天用小时聚合表。
    // 每桶除均值外附带峰值(下标 9..14):AVG 聚合会把短促尖峰抹平(24h 视图一个桶
    // ≈4 分钟,30 秒的 CPU 100% 只剩十几),前端据此画"峰值带",突发不再被平均掉。
    let points: Vec<Value> = if secs > 2 * 86400 {
        let bstep = step.max(3600); // 聚合表最细为小时
        // 聚合表仅存 cpu_max 一列真峰值;其余取"小时均值中的最大者"——粒度≥数小时时仍能
        // 体现峰谷,恰为 1 小时粒度时带宽收敛为 0(与均值线重合),属可接受的降级。
        let rows = sqlx::query!(
            r#"SELECT (hour_ts / ?1) * ?1 as "t!: i64",
                      AVG(cpu_avg) as "cpu!: f64",
                      AVG(mem_used_avg) as "mem_used!: f64", MAX(mem_total_max) as "mem_total!: i64",
                      AVG(net_rx_avg) as "rx!: f64", AVG(net_tx_avg) as "tx!: f64",
                      AVG(disk_read_avg) as "dr!: f64", AVG(disk_write_avg) as "dw!: f64",
                      AVG(load1_avg) as "load1!: f64",
                      MAX(cpu_max) as "cpu_max!: f64",
                      MAX(net_rx_avg) as "rx_max!: f64", MAX(net_tx_avg) as "tx_max!: f64",
                      MAX(disk_read_avg) as "dr_max!: f64", MAX(disk_write_avg) as "dw_max!: f64",
                      MAX(load1_avg) as "load1_max!: f64"
               FROM metrics_rollup WHERE node_id = ?2 AND hour_ts >= ?3
               GROUP BY 1 ORDER BY 1"#,
            bstep,
            id,
            since
        )
        .fetch_all(&st.db)
        .await?;
        rows.into_iter()
            .map(|r| {
                json!([
                    r.t, r.cpu, r.mem_used, r.mem_total, r.rx, r.tx, r.dr, r.dw, r.load1,
                    r.cpu_max, r.rx_max, r.tx_max, r.dr_max, r.dw_max, r.load1_max
                ])
            })
            .collect()
    } else {
        let rows = sqlx::query!(
            r#"SELECT (ts / ?1) * ?1 as "t!: i64",
                      AVG(cpu_pct) as "cpu!: f64",
                      AVG(mem_used) as "mem_used!: f64", MAX(mem_total) as "mem_total!: i64",
                      AVG(net_rx_bps) as "rx!: f64", AVG(net_tx_bps) as "tx!: f64",
                      AVG(disk_read_bps) as "dr!: f64", AVG(disk_write_bps) as "dw!: f64",
                      AVG(load1) as "load1!: f64",
                      MAX(cpu_pct) as "cpu_max!: f64",
                      MAX(net_rx_bps) as "rx_max!: i64", MAX(net_tx_bps) as "tx_max!: i64",
                      MAX(disk_read_bps) as "dr_max!: i64", MAX(disk_write_bps) as "dw_max!: i64",
                      MAX(load1) as "load1_max!: f64"
               FROM metrics WHERE node_id = ?2 AND ts >= ?3
               GROUP BY 1 ORDER BY 1"#,
            step,
            id,
            since
        )
        .fetch_all(&st.db)
        .await?;
        rows.into_iter()
            .map(|r| {
                json!([
                    r.t, r.cpu, r.mem_used, r.mem_total, r.rx, r.tx, r.dr, r.dw, r.load1,
                    r.cpu_max, r.rx_max, r.tx_max, r.dr_max, r.dw_max, r.load1_max
                ])
            })
            .collect()
    };
    Ok(Json(json!({ "step": step, "points": points })))
}

/// POST /api/nodes/{id}/rename
pub async fn rename(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionAdmin,
    Path(id): Path<i64>,
    Json(req): Json<RenameReq>,
) -> Result<Json<Value>, AppError> {
    let name = validate_node_name(&req.name)?;
    let grp = outpost_common::clean_str(&req.grp, 32);
    let note = outpost_common::clean_str(&req.note, 200);
    if req.traffic_reset_enabled && !crate::traffic::valid_reset_day(req.traffic_reset_day) {
        return Err(AppError::bad("每月清零日需在 1~28 之间"));
    }
    let reset_enabled = i64::from(req.traffic_reset_enabled);
    // 仅更新记账基准,不在此处清零计数器;真正的清零由每小时巡检在跨周期边界时执行。
    let period_start = if req.traffic_reset_enabled {
        crate::traffic::current_period_start(unix_now(), req.traffic_reset_day)
    } else {
        0
    };
    let res = sqlx::query!(
        "UPDATE nodes SET name = ?1, grp = ?2, note = ?3,
                traffic_reset_enabled = ?4, traffic_reset_day = ?5, traffic_period_start = ?6
         WHERE id = ?7",
        name,
        grp,
        note,
        reset_enabled,
        req.traffic_reset_day,
        period_start,
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
    user: SessionAdmin,
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
    user: SessionAdmin,
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
    user: SessionAdmin,
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
            if affected > 0 {
                // 删节点会经外键级联删掉其节点级告警规则(隐式变更 alert_rules),刷新规则缓存
                crate::alerts::reload_rules(&st).await;
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
        "upgrade" => {
            // 触发在线 agent 远程自升级(规范 6.4 红线破例,见 crates/common 模块文档与
            // SECURITY_AUDIT 附录 F)。当前有活跃连接的节点立即下发;触发瞬间恰无连接的
            // (常因升级/重连造成的短暂断开)记入补发窗口:节点在 UPGRADE_RESEND_SECS 秒内
            // 重连即自动补发一次,不再直接判定"离线无法下发"。窗口过后自动失效,不做持久排队。
            let now = crate::util::unix_now();
            let deadline = now.saturating_add(crate::state::UPGRADE_RESEND_SECS);
            let mut queued = Vec::new();
            for id in &req.ids {
                // 读 sender 与写 pending 必须在同一临界区(锁序:先 upgrade_tx 后 pending_upgrade),
                // 与 conn_loop 的"插 sender + drain pending"互斥,消除补发窗口的丢发/双发竞态。
                let sent = {
                    let m = st.upgrade_tx.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    if m.get(id).is_some_and(|tx| tx.send(()).is_ok()) {
                        true
                    } else {
                        let mut p =
                            st.pending_upgrade.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                        p.retain(|_, exp| *exp > now); // 顺手清理过期项,防泄漏
                        p.insert(*id, deadline);
                        false
                    }
                };
                if sent {
                    affected += 1;
                } else {
                    queued.push(*id);
                }
            }
            audit::log(
                &st.db,
                &user.username,
                &ip,
                "node_batch",
                &format!("upgrade x{} affected={} queued={}", req.ids.len(), affected, queued.len()),
            )
            .await;
            // 兼容旧前端字段名:queued 同时以 offline 键回传(语义已从"离线"变为"待重连补发")。
            return Ok(Json(
                json!({ "ok": true, "affected": affected, "queued": queued, "offline": [] }),
            ));
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReorderReq {
    /// 完整节点 id 列表,顺序即展示顺序(数组下标写入 sort_order)。
    ids: Vec<i64>,
}

/// POST /api/nodes/reorder — 保存服务器列表手动拖拽排序。
pub async fn reorder(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionAdmin,
    Json(req): Json<ReorderReq>,
) -> Result<Json<Value>, AppError> {
    if req.ids.is_empty() || req.ids.len() > 500 {
        return Err(AppError::bad("排序数量需为 1~500"));
    }
    let mut tx = st.db.begin().await?;
    for (i, id) in req.ids.iter().enumerate() {
        let order = i as i64;
        sqlx::query!("UPDATE nodes SET sort_order = ?1 WHERE id = ?2", order, id)
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "node_reorder", &format!("{} 个节点", req.ids.len())).await;
    Ok(Json(json!({ "ok": true })))
}

/// DELETE /api/nodes/{id} — 级联删除指标与密钥,token 随之失效。
pub async fn delete(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionAdmin,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    let res = sqlx::query!("DELETE FROM nodes WHERE id = ?1", id).execute(&st.db).await?;
    if res.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    crate::alerts::forget_node(&st, id); // 告警事件/规则随级联删除,清运行态
    crate::alerts::reload_rules(&st).await; // 级联删了节点级规则,刷新规则缓存(避免缓存陈旧)
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "node_delete", &format!("#{id}")).await;
    Ok(Json(json!({ "ok": true })))
}
