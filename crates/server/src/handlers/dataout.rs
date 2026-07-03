//! 数据出口:Prometheus 兼容 /metrics、只读 v1 查询、历史导出(CSV/JSON)。
//! 全部经 [`ReadAuth`](crate::apiauth::ReadAuth):会话或只读 API Token 其一。

use crate::apiauth::ReadAuth;
use crate::errors::AppError;
use crate::state::AppState;
use crate::util::unix_now;
use axum::extract::{Path, Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::fmt::Write as _;

/// Prometheus label 值转义:反斜杠、双引号、换行。
fn esc_label(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            c if c.is_control() => {} // 丢弃其它控制字符
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::esc_label;
    #[test]
    fn prometheus_label_escaping() {
        // 引号/反斜杠转义,换行→\n,其它控制字符丢弃 —— 防标签注入/断行
        assert_eq!(esc_label("a\"b"), "a\\\"b");
        assert_eq!(esc_label("a\\b"), "a\\\\b");
        assert_eq!(esc_label("a\nb"), "a\\nb");
        assert_eq!(esc_label("a\u{7}b\u{0}c"), "abc");
        assert_eq!(esc_label("正常-name_1"), "正常-name_1");
    }
}

/// GET /metrics — Prometheus 文本格式(每节点最新一条)。
pub async fn prometheus(State(st): State<AppState>, _a: ReadAuth) -> Result<Response, AppError> {
    let interval = crate::db::setting_i64(&st.db, "report_interval_secs", 5, 1, 3600).await;
    let now = unix_now();
    let rows = sqlx::query!(
        r#"SELECT n.id as "id!", n.name as "name!", n.last_seen,
                  m.cpu_pct, m.mem_used, m.mem_total, m.disk_used, m.disk_total,
                  m.load1, m.net_rx_bps, m.net_tx_bps, m.uptime_secs, m.procs
           FROM nodes n
           LEFT JOIN metrics m ON m.id = (SELECT id FROM metrics WHERE node_id = n.id ORDER BY ts DESC LIMIT 1)
           WHERE n.token_hash IS NOT NULL"#
    )
    .fetch_all(&st.db)
    .await?;

    let mut b = String::new();
    let g = |b: &mut String, name: &str, help: &str| {
        let _ = writeln!(b, "# HELP outpost_{name} {help}");
        let _ = writeln!(b, "# TYPE outpost_{name} gauge");
    };
    g(&mut b, "up", "Node online (1) or offline (0)");
    g(&mut b, "cpu_percent", "CPU usage percent");
    g(&mut b, "mem_used_bytes", "Memory used bytes");
    g(&mut b, "mem_total_bytes", "Memory total bytes");
    g(&mut b, "disk_used_bytes", "Primary disk used bytes");
    g(&mut b, "disk_total_bytes", "Primary disk total bytes");
    g(&mut b, "load1", "1-minute load average");
    g(&mut b, "net_rx_bps", "Network receive bytes/sec");
    g(&mut b, "net_tx_bps", "Network transmit bytes/sec");
    g(&mut b, "uptime_seconds", "Uptime seconds");
    g(&mut b, "procs", "Process count");

    for r in rows {
        let lbl = format!("{{node=\"{}\",node_id=\"{}\"}}", esc_label(&r.name), r.id);
        let online = i32::from(
            r.last_seen.is_some_and(|ls| now.saturating_sub(ls) <= interval.saturating_mul(3).max(10)),
        );
        let _ = writeln!(b, "outpost_up{lbl} {online}");
        // 仅在有指标时输出数值型
        if let Some(cpu) = r.cpu_pct {
            let _ = writeln!(b, "outpost_cpu_percent{lbl} {cpu}");
            let _ = writeln!(b, "outpost_mem_used_bytes{lbl} {}", r.mem_used.unwrap_or(0));
            let _ = writeln!(b, "outpost_mem_total_bytes{lbl} {}", r.mem_total.unwrap_or(0));
            let _ = writeln!(b, "outpost_disk_used_bytes{lbl} {}", r.disk_used.unwrap_or(0));
            let _ = writeln!(b, "outpost_disk_total_bytes{lbl} {}", r.disk_total.unwrap_or(0));
            let _ = writeln!(b, "outpost_load1{lbl} {}", r.load1.unwrap_or(0.0));
            let _ = writeln!(b, "outpost_net_rx_bps{lbl} {}", r.net_rx_bps.unwrap_or(0));
            let _ = writeln!(b, "outpost_net_tx_bps{lbl} {}", r.net_tx_bps.unwrap_or(0));
            let _ = writeln!(b, "outpost_uptime_seconds{lbl} {}", r.uptime_secs.unwrap_or(0));
            let _ = writeln!(b, "outpost_procs{lbl} {}", r.procs.unwrap_or(0));
        }
    }

    Ok((
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
        b,
    )
        .into_response())
}

/// GET /api/v1/nodes — 只读节点概览(供外部系统)。
pub async fn v1_nodes(State(st): State<AppState>, _a: ReadAuth) -> Result<Json<Value>, AppError> {
    let interval = crate::db::setting_i64(&st.db, "report_interval_secs", 5, 1, 3600).await;
    let now = unix_now();
    let rows = sqlx::query!(
        r#"SELECT n.id as "id!", n.name as "name!", n.grp as "grp!", n.hostname as "hostname!",
                  n.os as "os!", n.arch as "arch!", n.last_seen,
                  m.cpu_pct, m.mem_used, m.mem_total, m.disk_used, m.disk_total, m.load1
           FROM nodes n
           LEFT JOIN metrics m ON m.id = (SELECT id FROM metrics WHERE node_id = n.id ORDER BY ts DESC LIMIT 1)
           WHERE n.token_hash IS NOT NULL ORDER BY n.id"#
    )
    .fetch_all(&st.db)
    .await?;
    let items: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            let online = r.last_seen.is_some_and(|ls| now.saturating_sub(ls) <= interval.saturating_mul(3).max(10));
            json!({
                "id": r.id, "name": r.name, "grp": r.grp, "hostname": r.hostname,
                "os": r.os, "arch": r.arch, "online": online, "last_seen": r.last_seen,
                "cpu_pct": r.cpu_pct, "mem_used": r.mem_used, "mem_total": r.mem_total,
                "disk_used": r.disk_used, "disk_total": r.disk_total, "load1": r.load1,
            })
        })
        .collect();
    Ok(Json(json!({ "now": now, "nodes": items })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExportQuery {
    secs: i64,
    #[serde(default = "default_fmt")]
    format: String,
}
fn default_fmt() -> String {
    "csv".to_string()
}

/// GET /api/v1/nodes/{id}/export?secs=&format=csv|json — 历史指标导出。
pub async fn export(
    State(st): State<AppState>,
    _a: ReadAuth,
    Path(id): Path<i64>,
    Query(q): Query<ExportQuery>,
) -> Result<Response, AppError> {
    let secs = q.secs.clamp(300, 90 * 86400);
    let since = unix_now().saturating_sub(secs);
    let rows = sqlx::query!(
        r#"SELECT ts as "ts!", cpu_pct as "cpu_pct!: f64", load1 as "load1!: f64",
                  mem_used as "mem_used!: i64", mem_total as "mem_total!: i64",
                  disk_used as "disk_used!: i64", disk_total as "disk_total!: i64",
                  net_rx_bps as "net_rx_bps!: i64", net_tx_bps as "net_tx_bps!: i64",
                  procs as "procs!: i64"
           FROM metrics WHERE node_id = ?1 AND ts >= ?2 ORDER BY ts"#,
        id,
        since
    )
    .fetch_all(&st.db)
    .await?;
    if rows.is_empty() {
        // 节点不存在或无数据:统一 404,不区分(避免探测)
        let exists = sqlx::query_scalar!(r#"SELECT COUNT(*) as "c!: i64" FROM nodes WHERE id = ?1"#, id)
            .fetch_one(&st.db)
            .await?;
        if exists == 0 {
            return Err(AppError::NotFound);
        }
    }

    if q.format == "json" {
        let items: Vec<Value> = rows
            .iter()
            .map(|r| {
                json!({
                    "ts": r.ts, "cpu_pct": r.cpu_pct, "load1": r.load1,
                    "mem_used": r.mem_used, "mem_total": r.mem_total,
                    "disk_used": r.disk_used, "disk_total": r.disk_total,
                    "net_rx_bps": r.net_rx_bps, "net_tx_bps": r.net_tx_bps, "procs": r.procs,
                })
            })
            .collect();
        Ok((
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/json; charset=utf-8".to_string()),
                (header::CONTENT_DISPOSITION, format!("attachment; filename=\"node{id}.json\"")),
            ],
            serde_json::to_string(&items).unwrap_or_else(|_| "[]".into()),
        )
            .into_response())
    } else {
        let mut csv = String::from(
            "ts,cpu_pct,load1,mem_used,mem_total,disk_used,disk_total,net_rx_bps,net_tx_bps,procs\n",
        );
        // 全部为数值字段,无注入面;仍避免任何用户字符串进入 CSV
        for r in &rows {
            let _ = writeln!(
                csv,
                "{},{:.2},{:.2},{},{},{},{},{},{},{}",
                r.ts, r.cpu_pct, r.load1, r.mem_used, r.mem_total, r.disk_used,
                r.disk_total, r.net_rx_bps, r.net_tx_bps, r.procs
            );
        }
        Ok((
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
                (header::CONTENT_DISPOSITION, format!("attachment; filename=\"node{id}.csv\"")),
            ],
            csv,
        )
            .into_response())
    }
}
