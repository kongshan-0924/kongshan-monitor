//! 系统设置与审计日志查看。

use crate::audit;
use crate::db::{set_setting, setting_i64};
use crate::errors::AppError;
use crate::session::{SessionAdmin, SessionUser};
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
    /// 自动本地备份周期(小时,0=关闭)
    #[serde(default)]
    auto_backup_hours: i64,
    /// 自动备份保留份数
    #[serde(default = "default_keep")]
    auto_backup_keep: i64,
    /// 对外访问地址(用于 Origin 校验/安装命令/状态页链接),必须 https(本机回环+关闭
    /// Secure Cookie 时例外允许 http)。
    #[serde(default)]
    public_url: String,
    /// 额外允许的 Origin,每行一个;留空即清空。
    #[serde(default)]
    extra_origins: String,
}

fn default_keep() -> i64 {
    7
}

/// GET /api/settings
pub async fn get(State(st): State<AppState>, _user: SessionUser) -> Result<Json<Value>, AppError> {
    let interval = setting_i64(&st.db, "report_interval_secs", 5, 1, 3600).await;
    let retention = setting_i64(&st.db, "retention_days", 30, 1, 3650).await;
    let backup_hours = setting_i64(&st.db, "auto_backup_hours", 0, 0, 168).await;
    let backup_keep = setting_i64(&st.db, "auto_backup_keep", 7, 1, 90).await;
    let slug = crate::db::setting_str(&st.db, "status_slug").await;
    let public_url = st.public_url();
    let status_url = if slug.is_empty() {
        String::new()
    } else {
        format!("{}/status/{}", public_url.trim_end_matches('/'), slug)
    };
    Ok(Json(json!({
        "report_interval_secs": interval,
        "retention_days": retention,
        "auto_backup_hours": backup_hours,
        "auto_backup_keep": backup_keep,
        "status_enabled": !slug.is_empty(),
        "status_url": status_url,
        "public_url": public_url,
        "extra_origins": st.extra_origins().join("\n"),
    })))
}

/// POST /api/settings — 校验范围;间隔变更实时推送给在线 agent(白名单下行)。
pub async fn set(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionAdmin,
    Json(req): Json<SettingsReq>,
) -> Result<Json<Value>, AppError> {
    if !(1..=3600).contains(&req.report_interval_secs) {
        return Err(AppError::bad("上报间隔需在 1~3600 秒之间"));
    }
    if !(1..=3650).contains(&req.retention_days) {
        return Err(AppError::bad("数据保留需在 1~3650 天之间"));
    }
    if !(0..=168).contains(&req.auto_backup_hours) {
        return Err(AppError::bad("自动备份周期需在 0(关闭)~168 小时"));
    }
    if !(1..=90).contains(&req.auto_backup_keep) {
        return Err(AppError::bad("备份保留份数需在 1~90"));
    }
    let dev_local = st.cfg.dev_local();
    let public_url = req.public_url.trim().to_string();
    if public_url.is_empty() || public_url.len() > 200 {
        return Err(AppError::bad("对外访问地址不能为空且不超过 200 字符"));
    }
    if !crate::config::scheme_ok(&public_url, dev_local) {
        return Err(AppError::bad(
            "对外访问地址必须为 https://(本机回环预览可用 http:// 并关闭 Secure Cookie)",
        ));
    }
    let extra_origins: Vec<String> = req
        .extra_origins
        .lines()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    if extra_origins.len() > 16 {
        return Err(AppError::bad("额外 Origin 最多 16 条"));
    }
    for o in &extra_origins {
        if o.len() > 200 || !crate::config::scheme_ok(o, dev_local) {
            return Err(AppError::bad(
                "额外 Origin 每条须为 https://(本机预览可 http://),且不超过 200 字符",
            ));
        }
    }

    set_setting(&st.db, "report_interval_secs", &req.report_interval_secs.to_string()).await?;
    set_setting(&st.db, "retention_days", &req.retention_days.to_string()).await?;
    set_setting(&st.db, "auto_backup_hours", &req.auto_backup_hours.to_string()).await?;
    set_setting(&st.db, "auto_backup_keep", &req.auto_backup_keep.to_string()).await?;
    set_setting(&st.db, "public_url", &public_url).await?;
    set_setting(
        &st.db,
        "extra_origins",
        &serde_json::to_string(&extra_origins).unwrap_or_else(|_| "[]".into()),
    )
    .await?;
    *st.net.write().unwrap_or_else(std::sync::PoisonError::into_inner) =
        crate::state::NetCfg { public_url, extra_origins };

    let interval = u32::try_from(req.report_interval_secs).unwrap_or(5);
    let _ = st.interval_tx.send(interval);

    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(
        &st.db,
        &user.username,
        &ip.to_string(),
        "settings_change",
        &format!(
            "interval={} retention={}d public_url={}",
            req.report_interval_secs, req.retention_days, req.public_url
        ),
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
