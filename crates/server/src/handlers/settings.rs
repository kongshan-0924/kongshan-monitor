//! 系统设置与审计日志查看。

use crate::audit;
use crate::db::{set_setting, setting_i64};
use crate::errors::AppError;
use crate::session::SessionUser;
use crate::state::AppState;
use crate::util::client_ip;
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::fmt::Write as _;
use std::net::SocketAddr;

/// CSV 单元格转义:防公式注入(=,+,-,@,制表/回车 前缀)+ 引号包裹。
fn csv_cell(s: &str) -> String {
    let cleaned: String = s.chars().filter(|c| *c != '\r' && *c != '\n').collect();
    let needs_prefix = cleaned
        .as_bytes()
        .first()
        .is_some_and(|b| matches!(b, b'=' | b'+' | b'-' | b'@' | b'\t'));
    let body = if needs_prefix { format!("'{cleaned}") } else { cleaned };
    if body.contains([',', '"']) {
        format!("\"{}\"", body.replace('"', "\"\""))
    } else {
        body
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SettingsReq {
    report_interval_secs: i64,
    retention_days: i64,
}

/// GET /api/settings
pub async fn get(State(st): State<AppState>, _user: SessionUser) -> Result<Json<Value>, AppError> {
    let interval = setting_i64(&st.db, "report_interval_secs", 5, 1, 3600).await;
    let retention = setting_i64(&st.db, "retention_days", 30, 1, 3650).await;
    let slug = crate::db::setting_str(&st.db, "status_slug").await;
    let status_url = if slug.is_empty() {
        String::new()
    } else {
        format!("{}/status/{}", st.cfg.server.public_url.trim_end_matches('/'), slug)
    };
    Ok(Json(json!({
        "report_interval_secs": interval,
        "retention_days": retention,
        "status_enabled": !slug.is_empty(),
        "status_url": status_url,
    })))
}

/// POST /api/settings — 校验范围;间隔变更实时推送给在线 agent(白名单下行)。
pub async fn set(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionUser,
    Json(req): Json<SettingsReq>,
) -> Result<Json<Value>, AppError> {
    if !(1..=3600).contains(&req.report_interval_secs) {
        return Err(AppError::bad("上报间隔需在 1~3600 秒之间"));
    }
    if !(1..=3650).contains(&req.retention_days) {
        return Err(AppError::bad("数据保留需在 1~3650 天之间"));
    }
    set_setting(&st.db, "report_interval_secs", &req.report_interval_secs.to_string()).await?;
    set_setting(&st.db, "retention_days", &req.retention_days.to_string()).await?;

    let interval = u32::try_from(req.report_interval_secs).unwrap_or(5);
    let _ = st.interval_tx.send(interval);

    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(
        &st.db,
        &user.username,
        &ip.to_string(),
        "settings_change",
        &format!("interval={} retention={}d", req.report_interval_secs, req.retention_days),
    )
    .await;
    Ok(Json(json!({ "ok": true })))
}

/// GET /api/audit — 最近 100 条审计记录。
pub async fn audit_list(
    State(st): State<AppState>,
    _user: SessionUser,
) -> Result<Json<Value>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT ts as "ts!", username as "username!", ip as "ip!",
                  action as "action!", detail as "detail!"
           FROM audit_log ORDER BY id DESC LIMIT 100"#
    )
    .fetch_all(&st.db)
    .await?;
    let items: Vec<Value> = rows
        .into_iter()
        .map(|r| json!({ "ts": r.ts, "username": r.username, "ip": r.ip, "action": r.action, "detail": r.detail }))
        .collect();
    Ok(Json(json!({ "items": items })))
}

/// GET /api/audit/export — 全量审计日志 CSV(公式注入安全)。
pub async fn audit_export(State(st): State<AppState>, _u: SessionUser) -> Result<Response, AppError> {
    let rows = sqlx::query!(
        r#"SELECT ts as "ts!", username as "username!", ip as "ip!",
                  action as "action!", detail as "detail!"
           FROM audit_log ORDER BY id DESC LIMIT 100000"#
    )
    .fetch_all(&st.db)
    .await?;
    let mut csv = String::from("ts,time,username,ip,action,detail\n");
    for r in rows {
        let time = format!("{}", r.ts); // 客户端可再格式化;此处给原始秒
        let _ = writeln!(
            csv,
            "{},{},{},{},{},{}",
            r.ts,
            time,
            csv_cell(&r.username),
            csv_cell(&r.ip),
            csv_cell(&r.action),
            csv_cell(&r.detail)
        );
    }
    Ok((
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/csv; charset=utf-8".to_string()),
            (header::CONTENT_DISPOSITION, "attachment; filename=\"outpost-audit.csv\"".to_string()),
        ],
        csv,
    )
        .into_response())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::csv_cell;
    #[test]
    fn csv_injection_defused() {
        assert_eq!(csv_cell("=1+2"), "'=1+2");
        assert_eq!(csv_cell("@cmd"), "'@cmd");
        assert_eq!(csv_cell("-5"), "'-5");
        assert_eq!(csv_cell("a,b"), "\"a,b\"");
        assert_eq!(csv_cell("he\"llo"), "\"he\"\"llo\"");
        assert_eq!(csv_cell("normal"), "normal");
        assert_eq!(csv_cell("line\nbreak"), "linebreak");
    }
}
