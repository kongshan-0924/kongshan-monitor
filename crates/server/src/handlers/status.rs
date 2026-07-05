//! 公开只读状态页(默认关闭)。由高熵 slug 门控,数据脱敏(无 IP/主机名/备注/版本)。
//! 启用/关闭需会话;公开端点仅返回汇总健康度。

use crate::audit;
use crate::db::{set_setting, setting_str};
use crate::errors::AppError;
use crate::session::SessionAdmin;
use crate::state::AppState;
use crate::util::{client_ip, ct_eq, gen_token_hex, unix_now};
use axum::extract::{ConnectInfo, Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde_json::{json, Value};
use std::net::SocketAddr;

const SLUG_KEY: &str = "status_slug";

/// slug 合法性:2~64 位,仅小写字母/数字/连字符/下划线(自定义后缀)。
fn valid_slug(s: &str) -> bool {
    let n = s.len();
    (2..=64).contains(&n)
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnableReq {
    /// 自定义后缀(留空则随机生成)。前缀固定为面板访问地址,不可改。
    #[serde(default)]
    slug: String,
}

/// POST /api/status/enable — 用自定义(或随机)后缀启用状态页。
pub async fn enable(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionAdmin,
    Json(req): Json<EnableReq>,
) -> Result<Json<Value>, AppError> {
    let slug = if req.slug.trim().is_empty() {
        // 未指定 → 随机 12 位
        let full = gen_token_hex().map_err(|_| AppError::Internal)?;
        full.get(..12).unwrap_or("").to_string()
    } else {
        let s = req.slug.trim().to_lowercase();
        if !valid_slug(&s) {
            return Err(AppError::bad("后缀需为 2~64 位,仅限小写字母、数字、连字符、下划线"));
        }
        s
    };
    set_setting(&st.db, SLUG_KEY, &slug).await?;
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "status_enable", &slug).await;
    Ok(Json(json!({
        "slug": slug,
        "url": format!("{}/status/{}", st.public_url().trim_end_matches('/'), slug),
    })))
}

/// POST /api/status/disable — 清除 slug(立即失效)。
pub async fn disable(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionAdmin,
) -> Result<Json<Value>, AppError> {
    set_setting(&st.db, SLUG_KEY, "").await?;
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "status_disable", "").await;
    Ok(Json(json!({ "ok": true })))
}

/// 校验请求 slug 是否匹配已启用的 slug(常量时间)。
pub async fn slug_ok(st: &AppState, slug: &str) -> bool {
    if !valid_slug(slug) {
        return false;
    }
    let stored = setting_str(&st.db, SLUG_KEY).await;
    !stored.is_empty() && ct_eq(&stored, slug)
}

/// GET /api/status/{slug} — 公开脱敏健康度(无 IP/主机名/备注/版本)。
pub async fn public_json(
    State(st): State<AppState>,
    Path(slug): Path<String>,
) -> Result<Json<Value>, AppError> {
    if !slug_ok(&st, &slug).await {
        return Err(AppError::NotFound);
    }
    let interval = crate::db::setting_i64(&st.db, "report_interval_secs", 5, 1, 3600).await;
    let now = unix_now();
    let rows = sqlx::query!(
        r#"SELECT n.id as "id!", n.name as "name!", n.grp as "grp!", n.last_seen,
                  m.cpu_pct, m.mem_used, m.mem_total, m.disk_used, m.disk_total
           FROM nodes n
           LEFT JOIN metrics m ON m.id = (SELECT id FROM metrics WHERE node_id = n.id ORDER BY ts DESC LIMIT 1)
           WHERE n.token_hash IS NOT NULL ORDER BY n.grp, n.name"#
    )
    .fetch_all(&st.db)
    .await?;
    #[allow(clippy::cast_precision_loss)]
    let pctf = |u: Option<i64>, t: Option<i64>| match (u, t) {
        (Some(u), Some(t)) if t > 0 => (u as f64 / t as f64 * 100.0 * 10.0).round() / 10.0,
        _ => 0.0,
    };
    let items: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            let online = r.last_seen.is_some_and(|ls| now.saturating_sub(ls) <= interval.saturating_mul(3).max(10));
            json!({
                "name": r.name, "grp": r.grp, "online": online,
                "cpu": r.cpu_pct.unwrap_or(0.0), "mem": pctf(r.mem_used, r.mem_total),
                "disk": pctf(r.disk_used, r.disk_total),
            })
        })
        .collect();
    Ok(Json(json!({ "nodes": items, "now": now })))
}
