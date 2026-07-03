//! 告警规则、事件、通知渠道的管理端点。全部需会话认证。
//! 输入严格校验:指标/比较符/渠道类型走白名单枚举,URL 交由 SSRF 加固客户端处理。

use crate::alerts::{
    valid_channel_kind, valid_chat_id, valid_comparator, valid_metric, valid_severity,
    valid_telegram_token,
};
use crate::audit;
use crate::errors::AppError;
use crate::session::SessionUser;
use crate::state::AppState;
use crate::util::{client_ip, unix_now};
use axum::extract::{ConnectInfo, Path, State};
use axum::http::HeaderMap;
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::net::SocketAddr;

const MAX_RULES: i64 = 500;
const MAX_CHANNELS: i64 = 50;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleReq {
    name: String,
    metric: String,
    #[serde(default = "default_gt")]
    comparator: String,
    #[serde(default)]
    threshold: f64,
    #[serde(default)]
    duration_secs: i64,
    /// None = 所有节点
    #[serde(default)]
    node_id: Option<i64>,
    #[serde(default = "default_warning")]
    severity: String,
}

fn default_gt() -> String {
    "gt".to_string()
}
fn default_warning() -> String {
    "warning".to_string()
}
fn default_info() -> String {
    "info".to_string()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelReq {
    name: String,
    #[serde(default = "default_webhook")]
    kind: String,
    /// webhook: 完整 https URL;telegram: bot token;bark: 推送基址(https)
    #[serde(default)]
    url: String,
    /// telegram: chat_id;其余留空
    #[serde(default)]
    target: String,
    // --- SMTP 渠道字段 ---
    #[serde(default)]
    smtp_host: String,
    #[serde(default)]
    smtp_port: Option<u16>,
    #[serde(default)]
    smtp_user: String,
    #[serde(default)]
    smtp_pass: String,
    #[serde(default)]
    smtp_from: String,
    #[serde(default)]
    smtp_to: String,
    /// 渠道最低接收严重度(info/warning/critical)
    #[serde(default = "default_info")]
    min_severity: String,
}

fn default_webhook() -> String {
    "webhook".to_string()
}

/// 按渠道类型校验并归一化 (url, extra)。
fn validate_channel(req: &ChannelReq) -> Result<(String, String), AppError> {
    match req.kind.as_str() {
        "webhook" | "bark" => {
            let url = req.url.trim();
            if url.len() > 2048 {
                return Err(AppError::bad("地址过长"));
            }
            if !url.starts_with("https://") {
                return Err(AppError::bad("必须是 https:// 地址"));
            }
            Ok((url.to_string(), String::new()))
        }
        "telegram" => {
            let url = req.url.trim();
            if !valid_telegram_token(url) {
                return Err(AppError::bad("Telegram Bot Token 格式不正确"));
            }
            let chat = req.target.trim();
            if !valid_chat_id(chat) {
                return Err(AppError::bad("Telegram chat_id 格式不正确(数字或 @频道名)"));
            }
            Ok((url.to_string(), chat.to_string()))
        }
        "smtp" => {
            let host = req.smtp_host.trim();
            if host.is_empty() || host.len() > 255 {
                return Err(AppError::bad("SMTP 服务器地址非法"));
            }
            let port = req.smtp_port.unwrap_or(465);
            if !crate::notify_smtp::valid_email(&req.smtp_from)
                || !crate::notify_smtp::valid_email(&req.smtp_to)
            {
                return Err(AppError::bad("发件人/收件人邮箱格式非法"));
            }
            if req.smtp_user.is_empty()
                || req.smtp_user.len() > 320
                || req.smtp_pass.is_empty()
                || req.smtp_pass.len() > 256
            {
                return Err(AppError::bad("SMTP 账号或密码非法"));
            }
            let extra = json!({
                "host": host, "port": port,
                "username": req.smtp_user, "password": req.smtp_pass,
                "from": req.smtp_from.trim(), "to": req.smtp_to.trim(),
            })
            .to_string();
            Ok((host.to_string(), extra))
        }
        _ => Err(AppError::bad("暂不支持的渠道类型")),
    }
}

/// GET /api/alerts/rules
pub async fn list_rules(State(st): State<AppState>, _u: SessionUser) -> Result<Json<Value>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT r.id as "id!", r.name as "name!", r.metric as "metric!",
                  r.comparator as "comparator!", r.threshold as "threshold!: f64",
                  r.duration_secs as "duration_secs!", r.node_id, r.enabled as "enabled!: i64",
                  r.severity as "severity!", n.name as node_name
           FROM alert_rules r LEFT JOIN nodes n ON n.id = r.node_id
           ORDER BY r.id DESC"#
    )
    .fetch_all(&st.db)
    .await?;
    let items: Vec<Value> = rows
        .into_iter()
        .map(|r| {
            json!({
                "id": r.id, "name": r.name, "metric": r.metric, "comparator": r.comparator,
                "threshold": r.threshold, "duration_secs": r.duration_secs,
                "node_id": r.node_id, "node_name": r.node_name, "enabled": r.enabled != 0,
                "severity": r.severity,
            })
        })
        .collect();
    Ok(Json(json!({ "items": items })))
}

/// POST /api/alerts/rules
pub async fn create_rule(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionUser,
    Json(req): Json<RuleReq>,
) -> Result<Json<Value>, AppError> {
    let name = outpost_common::clean_str(&req.name, 64);
    if !outpost_common::valid_short_name(&name) {
        return Err(AppError::bad("规则名需为 1~64 个可见字符"));
    }
    if !valid_metric(&req.metric) {
        return Err(AppError::bad("不支持的指标"));
    }
    if !valid_comparator(&req.comparator) {
        return Err(AppError::bad("不支持的比较符"));
    }
    if !req.threshold.is_finite() || !(0.0..=1_000_000.0).contains(&req.threshold) {
        return Err(AppError::bad("阈值超出范围"));
    }
    if !(0..=86400).contains(&req.duration_secs) {
        return Err(AppError::bad("持续时间需在 0~86400 秒"));
    }
    if !valid_severity(&req.severity) {
        return Err(AppError::bad("严重度需为 info/warning/critical"));
    }
    // 校验 node_id 存在(避免悬挂引用/越权探测)
    if let Some(nid) = req.node_id {
        let exists = sqlx::query_scalar!(r#"SELECT COUNT(*) as "c!: i64" FROM nodes WHERE id = ?1"#, nid)
            .fetch_one(&st.db)
            .await?;
        if exists == 0 {
            return Err(AppError::bad("指定节点不存在"));
        }
    }
    let cnt = sqlx::query_scalar!(r#"SELECT COUNT(*) as "c!: i64" FROM alert_rules"#)
        .fetch_one(&st.db)
        .await?;
    if cnt >= MAX_RULES {
        return Err(AppError::bad("告警规则数量已达上限"));
    }
    let now = unix_now();
    let r = sqlx::query!(
        "INSERT INTO alert_rules(name, metric, comparator, threshold, duration_secs, node_id, severity, created_at)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        name, req.metric, req.comparator, req.threshold, req.duration_secs, req.node_id, req.severity, now
    )
    .execute(&st.db)
    .await?;
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "alert_rule_create", &name).await;
    Ok(Json(json!({ "id": r.last_insert_rowid() })))
}

/// POST /api/alerts/rules/{id}/toggle
pub async fn toggle_rule(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionUser,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    let r = sqlx::query!("UPDATE alert_rules SET enabled = 1 - enabled WHERE id = ?1", id)
        .execute(&st.db)
        .await?;
    if r.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    // 若切换后为停用,收敛其未消解事件与运行态
    let enabled = sqlx::query_scalar!(r#"SELECT enabled as "e!: i64" FROM alert_rules WHERE id = ?1"#, id)
        .fetch_optional(&st.db)
        .await?;
    if enabled == Some(0) {
        crate::alerts::resolve_rule_events(&st, id).await;
    }
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "alert_rule_toggle", &format!("#{id}")).await;
    Ok(Json(json!({ "ok": true })))
}

/// DELETE /api/alerts/rules/{id}
pub async fn delete_rule(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionUser,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    let r = sqlx::query!("DELETE FROM alert_rules WHERE id = ?1", id).execute(&st.db).await?;
    if r.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    crate::alerts::forget_rule(&st, id); // 事件随级联删除,清运行态
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "alert_rule_delete", &format!("#{id}")).await;
    Ok(Json(json!({ "ok": true })))
}

/// GET /api/alerts/events — 当前 firing + 最近历史。
pub async fn list_events(State(st): State<AppState>, _u: SessionUser) -> Result<Json<Value>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT e.id as "id!", e.rule_id as "rule_id!", e.node_id as "node_id!",
                  e.state as "state!", e.value as "value!: f64", e.started_at as "started_at!",
                  e.resolved_at, e.message as "message!",
                  n.name as node_name, r.name as rule_name
           FROM alert_events e
           LEFT JOIN nodes n ON n.id = e.node_id
           LEFT JOIN alert_rules r ON r.id = e.rule_id
           ORDER BY (e.resolved_at IS NULL) DESC, e.started_at DESC
           LIMIT 100"#
    )
    .fetch_all(&st.db)
    .await?;
    let items: Vec<Value> = rows
        .into_iter()
        .map(|e| {
            json!({
                "id": e.id, "rule_id": e.rule_id, "node_id": e.node_id, "state": e.state,
                "value": e.value, "started_at": e.started_at, "resolved_at": e.resolved_at,
                "message": e.message, "node_name": e.node_name, "rule_name": e.rule_name,
                "firing": e.resolved_at.is_none(),
            })
        })
        .collect();
    let firing = sqlx::query_scalar!(r#"SELECT COUNT(*) as "c!: i64" FROM alert_events WHERE resolved_at IS NULL"#)
        .fetch_one(&st.db)
        .await?;
    Ok(Json(json!({ "items": items, "firing": firing })))
}

/// GET /api/alerts/channels
pub async fn list_channels(State(st): State<AppState>, _u: SessionUser) -> Result<Json<Value>, AppError> {
    let rows = sqlx::query!(
        r#"SELECT id as "id!", kind as "kind!", name as "name!", url as "url!",
                  extra as "extra!", enabled as "enabled!: i64", min_severity as "min_severity!"
           FROM notify_channels ORDER BY id DESC"#
    )
    .fetch_all(&st.db)
    .await?;
    let items: Vec<Value> = rows
        .into_iter()
        .map(|c| {
            json!({
                "id": c.id, "kind": c.kind, "name": c.name,
                "url": mask_target(&c.kind, &c.url, &c.extra), "enabled": c.enabled != 0,
                "min_severity": c.min_severity,
            })
        })
        .collect();
    Ok(Json(json!({ "items": items })))
}

/// 脱敏展示(隐藏 webhook 密钥段 / telegram token / bark key),防前端泄露。
fn mask_target(kind: &str, url: &str, extra: &str) -> String {
    match kind {
        "telegram" => {
            let id = url.split(':').next().unwrap_or("bot");
            format!("Telegram bot {id}··· → {extra}")
        }
        "smtp" => {
            // extra 是含凭据的 JSON,绝不回显;仅显示主机与收件人
            let to = serde_json::from_str::<Value>(extra)
                .ok()
                .and_then(|v| v.get("to").and_then(Value::as_str).map(str::to_string))
                .unwrap_or_default();
            format!("SMTP {url} → {to}")
        }
        _ => {
            let host = url.strip_prefix("https://").and_then(|r| r.split('/').next()).unwrap_or("");
            if host.is_empty() {
                "***".into()
            } else {
                format!("https://{host}/***")
            }
        }
    }
}

/// POST /api/alerts/channels
pub async fn create_channel(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionUser,
    Json(req): Json<ChannelReq>,
) -> Result<Json<Value>, AppError> {
    let name = outpost_common::clean_str(&req.name, 64);
    if !outpost_common::valid_short_name(&name) {
        return Err(AppError::bad("渠道名需为 1~64 个可见字符"));
    }
    if !valid_channel_kind(&req.kind) {
        return Err(AppError::bad("暂不支持的渠道类型"));
    }
    if !valid_severity(&req.min_severity) {
        return Err(AppError::bad("最低严重度需为 info/warning/critical"));
    }
    let (url, extra) = validate_channel(&req)?;
    let cnt = sqlx::query_scalar!(r#"SELECT COUNT(*) as "c!: i64" FROM notify_channels"#)
        .fetch_one(&st.db)
        .await?;
    if cnt >= MAX_CHANNELS {
        return Err(AppError::bad("通知渠道数量已达上限"));
    }
    let now = unix_now();
    let r = sqlx::query!(
        "INSERT INTO notify_channels(kind, name, url, extra, min_severity, created_at) VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        req.kind, name, url, extra, req.min_severity, now
    )
    .execute(&st.db)
    .await?;
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "channel_create", &name).await;
    Ok(Json(json!({ "id": r.last_insert_rowid() })))
}

/// POST /api/alerts/channels/{id}/test — 发送一条测试通知(经 SSRF 加固客户端)。
pub async fn test_channel(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionUser,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    let row = sqlx::query!(
        r#"SELECT kind as "kind!", url as "url!", extra as "extra!" FROM notify_channels WHERE id = ?1"#,
        id
    )
    .fetch_optional(&st.db)
    .await?
    .ok_or(AppError::NotFound)?;
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "channel_test", &format!("#{id}")).await;

    match crate::alerts::send_one(
        &row.kind,
        &row.url,
        &row.extra,
        "Outpost 测试通知:配置成功 ✅",
        st.cfg.notify.allow_private_targets,
    )
    .await
    {
        Ok(code) if (200..300).contains(&code) => Ok(Json(json!({ "ok": true, "status": code }))),
        Ok(code) => Err(AppError::bad(&format!("接收端返回 HTTP {code}"))),
        Err(e) => Err(AppError::bad(&format!("发送失败:{e}"))),
    }
}

/// DELETE /api/alerts/channels/{id}
pub async fn delete_channel(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionUser,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    let r = sqlx::query!("DELETE FROM notify_channels WHERE id = ?1", id).execute(&st.db).await?;
    if r.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "channel_delete", &format!("#{id}")).await;
    Ok(Json(json!({ "ok": true })))
}

const MAX_SILENCES: i64 = 200;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SilenceReq {
    /// None = 所有节点
    #[serde(default)]
    node_id: Option<i64>,
    /// None = 所有规则
    #[serde(default)]
    rule_id: Option<i64>,
    /// 静默时长(秒),60 ~ 30 天
    duration_secs: i64,
    #[serde(default)]
    reason: String,
}

/// GET /api/alerts/silences — 生效中/未来的静默窗口。
pub async fn list_silences(State(st): State<AppState>, _u: SessionUser) -> Result<Json<Value>, AppError> {
    let now = unix_now();
    let rows = sqlx::query!(
        r#"SELECT s.id as "id!", s.node_id, s.rule_id, s.start_ts as "start_ts!",
                  s.end_ts as "end_ts!", s.reason as "reason!",
                  n.name as node_name, r.name as rule_name
           FROM alert_silences s
           LEFT JOIN nodes n ON n.id = s.node_id
           LEFT JOIN alert_rules r ON r.id = s.rule_id
           WHERE s.end_ts > ?1
           ORDER BY s.end_ts ASC"#,
        now
    )
    .fetch_all(&st.db)
    .await?;
    let items: Vec<Value> = rows
        .into_iter()
        .map(|s| {
            json!({
                "id": s.id, "node_id": s.node_id, "rule_id": s.rule_id,
                "node_name": s.node_name, "rule_name": s.rule_name,
                "start_ts": s.start_ts, "end_ts": s.end_ts, "reason": s.reason,
                "active": s.start_ts <= now,
            })
        })
        .collect();
    Ok(Json(json!({ "items": items })))
}

/// POST /api/alerts/silences — 新建静默窗口(自现在起 duration 秒)。
pub async fn create_silence(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionUser,
    Json(req): Json<SilenceReq>,
) -> Result<Json<Value>, AppError> {
    if !(60..=30 * 86400).contains(&req.duration_secs) {
        return Err(AppError::bad("静默时长需在 60 秒 ~ 30 天"));
    }
    if let Some(nid) = req.node_id {
        let ok = sqlx::query_scalar!(r#"SELECT COUNT(*) as "c!: i64" FROM nodes WHERE id = ?1"#, nid)
            .fetch_one(&st.db)
            .await?;
        if ok == 0 {
            return Err(AppError::bad("指定节点不存在"));
        }
    }
    if let Some(rid) = req.rule_id {
        let ok = sqlx::query_scalar!(r#"SELECT COUNT(*) as "c!: i64" FROM alert_rules WHERE id = ?1"#, rid)
            .fetch_one(&st.db)
            .await?;
        if ok == 0 {
            return Err(AppError::bad("指定规则不存在"));
        }
    }
    let cnt = sqlx::query_scalar!(r#"SELECT COUNT(*) as "c!: i64" FROM alert_silences"#)
        .fetch_one(&st.db)
        .await?;
    if cnt >= MAX_SILENCES {
        return Err(AppError::bad("静默窗口数量已达上限"));
    }
    let reason = outpost_common::clean_str(&req.reason, 200);
    let now = unix_now();
    let end = now.saturating_add(req.duration_secs);
    let r = sqlx::query!(
        "INSERT INTO alert_silences(node_id, rule_id, start_ts, end_ts, reason, created_at)
         VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
        req.node_id, req.rule_id, now, end, reason, now
    )
    .execute(&st.db)
    .await?;
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "silence_create", &reason).await;
    Ok(Json(json!({ "id": r.last_insert_rowid() })))
}

/// DELETE /api/alerts/silences/{id}
pub async fn delete_silence(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionUser,
    Path(id): Path<i64>,
) -> Result<Json<Value>, AppError> {
    let r = sqlx::query!("DELETE FROM alert_silences WHERE id = ?1", id).execute(&st.db).await?;
    if r.rows_affected() == 0 {
        return Err(AppError::NotFound);
    }
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "silence_delete", &format!("#{id}")).await;
    Ok(Json(json!({ "ok": true })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenotifyReq {
    secs: i64,
}

/// GET /api/alerts/renotify — 当前重复提醒间隔(0=关闭)。
pub async fn get_renotify(State(st): State<AppState>, _u: SessionUser) -> Result<Json<Value>, AppError> {
    let secs = crate::db::setting_i64(&st.db, "alert_renotify_secs", 0, 0, 7 * 86400).await;
    Ok(Json(json!({ "secs": secs })))
}

/// POST /api/alerts/renotify — 设置重复提醒间隔(0 或 300~7 天)。
pub async fn set_renotify(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    user: SessionUser,
    Json(req): Json<RenotifyReq>,
) -> Result<Json<Value>, AppError> {
    if req.secs != 0 && !(300..=7 * 86400).contains(&req.secs) {
        return Err(AppError::bad("重复提醒间隔需为 0(关闭)或 300 秒 ~ 7 天"));
    }
    crate::db::set_setting(&st.db, "alert_renotify_secs", &req.secs.to_string())
        .await
        .map_err(|_| AppError::bad("保存失败"))?;
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    audit::log(&st.db, &user.username, &ip.to_string(), "alert_renotify_set", &req.secs.to_string()).await;
    Ok(Json(json!({ "ok": true })))
}
