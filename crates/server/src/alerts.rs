//! 告警引擎:规则评估 + 触发/恢复消抖状态机 + 离线巡检 + 通知分发。
//!
//! 安全:规则用白名单枚举(无任意表达式);运行态消抖用内存 Mutex(不跨 await 持有);
//! 通知经 [`crate::notify`] 的 SSRF 加固客户端异步发送,绝不阻塞上报路径。

use crate::state::AppState;
use crate::util::unix_now;
use outpost_common::Metrics;
use std::collections::HashMap;
use std::sync::Mutex;

/// 指标白名单。
pub const METRICS: &[&str] = &[
    "cpu_pct", "mem_pct", "disk_pct", "swap_pct", "load1", "cpu_temp", "tcp_conns", "inode_pct",
    "services_down", "offline",
];
/// 比较符白名单。roc(变化率):窗口 `roc_window_secs` 秒内绝对变化量 >= threshold。
pub const COMPARATORS: &[&str] = &["gt", "lt", "gte", "lte", "roc"];
/// roc 仅支持有独立列、可从历史行直接重算的核心指标(其余存于 detail JSON,暂不支持)。
pub const ROC_METRICS: &[&str] = &["cpu_pct", "mem_pct", "disk_pct", "swap_pct", "load1"];
/// 渠道类型白名单。
pub const CHANNEL_KINDS: &[&str] = &["webhook", "telegram", "bark", "smtp"];
/// 严重度白名单(有序:info < warning < critical)。
pub const SEVERITIES: &[&str] = &["info", "warning", "critical"];
/// 同一 (渠道, 文本) 的最小重发间隔(秒),去重防风暴。
const NOTIFY_DEDUP_SECS: i64 = 60;

const OFFLINE_PATROL_SECS: u64 = 30;
/// 离线首次确认时长(秒):节点静默超过"容忍时长"后,还须在该确认期内持续离线才告警,
/// 过滤偶发延迟/丢包造成的瞬时"离线"(至少再跨一个巡检周期确认)。
const OFFLINE_CONFIRM_SECS: i64 = 30;
/// 离线抗抖动窗口(秒):节点从离线恢复后的这段时间内视为"疑似链路抖动"。
const FLAP_WINDOW_SECS: i64 = 600;
/// 抗抖期内再次离线须持续满这么久才允许再次告警,避免延迟/丢包反复触发离线/恢复刷屏。
const FLAP_REFIRE_SECS: i64 = 300;

/// 计算本次离线 breach 距离"允许告警"还需持续多久:普通情况用调用方给的确认时长;
/// 若节点刚从离线恢复不久(疑似抖动),抬高到 [`FLAP_REFIRE_SECS`],让偶发再离线不再刷屏。
/// 首次离线(`recovered_at` 为空)不受影响,保证真实宕机仍能及时告警。
fn offline_fire_debounce(metric: &str, base: i64, recovered_at: Option<i64>, now: i64) -> i64 {
    if metric == "offline" && recovered_at.is_some_and(|r| now.saturating_sub(r) < FLAP_WINDOW_SECS)
    {
        base.max(FLAP_REFIRE_SECS)
    } else {
        base
    }
}

#[must_use]
pub fn valid_metric(m: &str) -> bool {
    METRICS.contains(&m)
}
#[must_use]
pub fn valid_comparator(c: &str) -> bool {
    COMPARATORS.contains(&c)
}
#[must_use]
pub fn valid_roc_metric(m: &str) -> bool {
    ROC_METRICS.contains(&m)
}
#[must_use]
pub fn valid_channel_kind(k: &str) -> bool {
    CHANNEL_KINDS.contains(&k)
}
#[must_use]
pub fn valid_severity(s: &str) -> bool {
    SEVERITIES.contains(&s)
}
/// 严重度序:info=0 < warning=1 < critical=2(未知视为 warning)。
#[must_use]
pub fn sev_rank(s: &str) -> u8 {
    match s {
        "info" => 0,
        "critical" => 2,
        _ => 1,
    }
}

/// Telegram bot token 形态:`<数字>:<字母数字_-,>=20`。
#[must_use]
pub fn valid_telegram_token(t: &str) -> bool {
    if t.len() > 128 {
        return false;
    }
    match t.split_once(':') {
        Some((a, b)) => {
            !a.is_empty()
                && a.bytes().all(|c| c.is_ascii_digit())
                && b.len() >= 20
                && b.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
        }
        None => false,
    }
}

/// Telegram chat_id:数字(可负)或 `@频道名`。
#[must_use]
pub fn valid_chat_id(s: &str) -> bool {
    if s.is_empty() || s.len() > 40 {
        return false;
    }
    if let Some(name) = s.strip_prefix('@') {
        return name.len() >= 3 && name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'_');
    }
    let body = s.strip_prefix('-').unwrap_or(s);
    !body.is_empty() && body.bytes().all(|c| c.is_ascii_digit())
}

#[derive(Default, Clone, Copy)]
struct Breach {
    since: Option<i64>,
    firing: bool,
    event_id: Option<i64>,
    /// 上次从离线**恢复**的时刻(仅离线规则维护),用于抗抖动:刚恢复不久又离线要求更久确认。
    recovered_at: Option<i64>,
}

/// 每 (rule_id, node_id) 的运行态消抖状态。
#[derive(Default)]
pub struct AlertRuntime {
    inner: Mutex<HashMap<(i64, i64), Breach>>,
}

impl AlertRuntime {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<(i64, i64), Breach>> {
        // 中毒锁恢复内部数据,避免 panic(lint 禁 unwrap)
        self.inner.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// 单条告警规则的精简运行态。常驻规则缓存(见 [`reload_rules`]),故需 `pub(crate)` 以便
/// [`crate::state`] 在 `Arc<Vec<RuleLite>>` 里命名它;字段仅本模块访问。
pub(crate) struct RuleLite {
    id: i64,
    name: String,
    metric: String,
    comparator: String,
    threshold: f64,
    duration_secs: i64,
    severity: String,
    roc_window_secs: i64,
    /// 归属节点:None=全局规则(对所有节点生效),Some(id)=仅该节点。
    node_id: Option<i64>,
}

#[allow(clippy::cast_precision_loss)]
fn metric_value(name: &str, m: &Metrics, disk_total: i64, disk_used: i64) -> Option<f64> {
    let pct = |used: f64, total: f64| if total > 0.0 { used / total * 100.0 } else { 0.0 };
    match name {
        "cpu_pct" => Some(m.cpu_pct),
        "mem_pct" => Some(pct(m.mem_used as f64, m.mem_total as f64)),
        // 遍历所有挂载点取最大使用率(与 inode_pct 一致):独立挂载的 /data、/var 写满
        // 也能触发,不再只看主盘漏报。m.disks 为空时回退到入参的主盘。
        "disk_pct" => m
            .disks
            .iter()
            .filter(|d| d.total > 0)
            .map(|d| pct(d.used as f64, d.total as f64))
            .fold(None, |acc, v| Some(acc.map_or(v, |a: f64| a.max(v))))
            .or_else(|| (disk_total > 0).then(|| pct(disk_used as f64, disk_total as f64))),
        "swap_pct" => Some(pct(m.swap_used as f64, m.swap_total as f64)),
        "load1" => Some(m.load1),
        "cpu_temp" => m.cpu_temp_c,
        "tcp_conns" => m.tcp_conns.map(f64::from),
        "inode_pct" => m
            .disks
            .iter()
            .filter(|d| d.inodes_total > 0)
            .map(|d| pct(d.inodes_used as f64, d.inodes_total as f64))
            .fold(None, |acc, v| Some(acc.map_or(v, |a: f64| a.max(v)))),
        "services_down" => Some(m.services.iter().filter(|s| !s.active).count() as f64),
        _ => None,
    }
}

/// 重新载入告警规则缓存(启用中的**全部**规则,含 node_id 归属)。
///
/// 规则极少变更,却要在每条上报(on_metrics)与每次离线巡检(patrol)时逐条匹配。此前每次
/// 都查库:N 个节点每 interval 各一次(P1-5),巡检还每节点一次(P1-4,N+1)。改为常驻内存 +
/// 增删改后由对应 handler 显式 reload。启动时须调用一次填充缓存。
pub(crate) async fn reload_rules(st: &AppState) {
    let rows = sqlx::query!(
        r#"SELECT id as "id!", name as "name!", metric as "metric!",
                  comparator as "comparator!", threshold as "threshold!: f64",
                  duration_secs as "duration_secs!", severity as "severity!",
                  roc_window_secs as "roc_window_secs!", node_id as "node_id?: i64"
           FROM alert_rules WHERE enabled = 1"#
    )
    .fetch_all(&st.db)
    .await
    .unwrap_or_default();
    let rules: Vec<RuleLite> = rows
        .into_iter()
        .map(|r| RuleLite {
            id: r.id,
            name: r.name,
            metric: r.metric,
            comparator: r.comparator,
            threshold: r.threshold,
            duration_secs: r.duration_secs,
            severity: r.severity,
            roc_window_secs: r.roc_window_secs,
            node_id: r.node_id,
        })
        .collect();
    if let Ok(mut w) = st.rule_cache.write() {
        *w = std::sync::Arc::new(rules);
    }
}

/// 取规则缓存快照(克隆 Arc,不在持锁期间做任何 await)。
fn rules_snapshot(st: &AppState) -> std::sync::Arc<Vec<RuleLite>> {
    st.rule_cache
        .read()
        .map(|g| std::sync::Arc::clone(&g))
        .unwrap_or_default()
}

/// 该规则是否作用于给定节点(全局规则对所有节点生效)。
fn rule_applies(rule: &RuleLite, node_id: i64) -> bool {
    rule.node_id.is_none() || rule.node_id == Some(node_id)
}

/// 取节点在 `at_or_before` 时刻(含)之前最近一条历史指标,重算出 `metric` 的值
/// (roc 变化率专用:仅支持有独立列的核心指标,从 `metrics` 表直接重算)。
#[allow(clippy::cast_precision_loss)]
async fn past_core_value(
    st: &AppState,
    node_id: i64,
    metric: &str,
    at_or_before: i64,
    not_before: i64,
) -> Option<f64> {
    // 加时间下界:命中点须落在 [not_before, at_or_before] 内,否则视为历史不足返回 None。
    // 否则节点离线数小时恢复后,会拿离线"前"那条陈旧点算变化率 → 假 critical。
    let row = sqlx::query!(
        r#"SELECT cpu_pct as "cpu_pct!: f64", load1 as "load1!: f64",
                  mem_used as "mem_used!: i64", mem_total as "mem_total!: i64",
                  swap_used as "swap_used!: i64", swap_total as "swap_total!: i64",
                  disk_used as "disk_used!: i64", disk_total as "disk_total!: i64"
           FROM metrics WHERE node_id = ?1 AND ts <= ?2 AND ts >= ?3 ORDER BY ts DESC LIMIT 1"#,
        node_id,
        at_or_before,
        not_before
    )
    .fetch_optional(&st.db)
    .await
    .ok()
    .flatten()?;
    let pct = |used: f64, total: f64| if total > 0.0 { used / total * 100.0 } else { 0.0 };
    match metric {
        "cpu_pct" => Some(row.cpu_pct),
        "mem_pct" => Some(pct(row.mem_used as f64, row.mem_total as f64)),
        "disk_pct" => Some(pct(row.disk_used as f64, row.disk_total as f64)),
        "swap_pct" => Some(pct(row.swap_used as f64, row.swap_total as f64)),
        "load1" => Some(row.load1),
        _ => None,
    }
}

/// 指标上报路径调用:评估该节点全部非离线规则。
pub async fn on_metrics(st: &AppState, node_id: i64, m: &Metrics, disk_total: i64, disk_used: i64) {
    let now = unix_now();
    let rules = rules_snapshot(st);
    for rule in rules
        .iter()
        .filter(|r| r.metric != "offline" && rule_applies(r, node_id))
    {
        let Some(val) = metric_value(&rule.metric, m, disk_total, disk_used) else {
            continue;
        };
        // roc(变化率):与窗口前的历史值比较,上报的"val"改为变化量(可正可负);
        // 其余比较符仍按当前值判定。历史数据不足(节点刚上线等)时不判定,避免误报。
        let (breaching, report_val) = if rule.comparator == "roc" {
            let window = rule.roc_window_secs.max(30);
            // 过去点须落在 [now-2*window, now-window]:超出即历史不足,不判定(防跨离线误报)。
            let at = now.saturating_sub(window);
            let floor = now.saturating_sub(window.saturating_mul(2));
            match past_core_value(st, node_id, &rule.metric, at, floor).await {
                Some(past) => {
                    let delta = val - past;
                    (delta.abs() >= rule.threshold, delta)
                }
                None => (false, 0.0),
            }
        } else {
            let breaching = match rule.comparator.as_str() {
                "gt" => val > rule.threshold,
                "lt" => val < rule.threshold,
                "gte" => val >= rule.threshold,
                "lte" => val <= rule.threshold,
                _ => false,
            };
            (breaching, val)
        };
        transition(st, rule, node_id, breaching, report_val, rule.duration_secs, now).await;
    }
}

/// 离线巡检后台循环:按 last_seen 判定,独立于上报路径。
pub async fn patrol(st: AppState) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(OFFLINE_PATROL_SECS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let now = unix_now();
        // 所有已注册节点及其 last_seen
        let nodes = sqlx::query!(
            r#"SELECT id as "id!", last_seen FROM nodes WHERE token_hash IS NOT NULL AND revoked = 0"#
        )
        .fetch_all(&st.db)
        .await
        .unwrap_or_default();

        // 一次性取规则缓存快照,offline 规则在内存里按节点过滤,替代此前每节点一次查库(P1-4)。
        let rules = rules_snapshot(&st);
        for node in &nodes {
            for rule in rules
                .iter()
                .filter(|r| r.metric == "offline" && rule_applies(r, node.id))
            {
                // grace = 容忍时长(下限 60s:不足 1 分钟的静默几乎都是延迟/丢包抖动,不算离线)
                let grace = rule.duration_secs.max(60);
                let offline_secs = node.last_seen.map_or(i64::MAX, |ls| now.saturating_sub(ls));
                let breaching = offline_secs > grace;
                let val = offline_secs.min(i64::from(u32::MAX)) as f64;
                // 越过 grace 后仍要求持续 OFFLINE_CONFIRM_SECS(跨一个巡检周期确认)才告警,
                // 叠加 transition 内的抗抖动,滤掉偶发瞬时离线。
                transition(&st, rule, node.id, breaching, val, OFFLINE_CONFIRM_SECS, now).await;
            }
        }
        renotify_sweep(&st).await;
        prune_runtime(&st, now);
    }
}

/// 重复提醒:对仍 firing 且距上次通知超过重发间隔的事件再次外发(全局设置,0=关闭)。
async fn renotify_sweep(st: &AppState) {
    let secs = crate::db::setting_i64(&st.db, "alert_renotify_secs", 0, 0, 7 * 86400).await;
    if secs <= 0 {
        return;
    }
    let now = unix_now();
    let cutoff = now.saturating_sub(secs);
    let rows = sqlx::query!(
        r#"SELECT e.id as "id!", e.rule_id as "rule_id!", e.node_id as "node_id!",
                  e.message as "message!", r.severity as "severity!", n.name as "node_name!"
           FROM alert_events e
           JOIN alert_rules r ON r.id = e.rule_id
           JOIN nodes n ON n.id = e.node_id
           WHERE e.resolved_at IS NULL
             AND (e.last_notified_at IS NULL OR e.last_notified_at <= ?1)
           LIMIT 200"#,
        cutoff
    )
    .fetch_all(&st.db)
    .await
    .unwrap_or_default();
    for row in rows {
        if is_silenced(st, row.node_id, row.rule_id, now).await {
            continue;
        }
        let text = format!("🔴 [持续告警] 节点 {} · {}", row.node_name, row.message);
        notify_all(st, &text, &row.severity).await;
        let _ = sqlx::query!("UPDATE alert_events SET last_notified_at = ?1 WHERE id = ?2", now, row.id)
            .execute(&st.db)
            .await;
    }
}

/// 清理不再活跃的运行态键,防内存缓慢增长。
/// 保留:仍在告警、正在计时、或"刚恢复且仍在抗抖窗口内"的键(否则抗抖动状态会被过早清掉)。
fn prune_runtime(st: &AppState, now: i64) {
    let mut map = st.alert_rt.lock();
    map.retain(|_, b| {
        b.firing
            || b.since.is_some()
            || b.recovered_at.is_some_and(|r| now.saturating_sub(r) < FLAP_WINDOW_SECS)
    });
}

/// 单条 (规则 × 节点) 的状态转移。消抖 debounce 由调用方给定。
async fn transition(
    st: &AppState,
    rule: &RuleLite,
    node_id: i64,
    breaching: bool,
    val: f64,
    debounce: i64,
    now: i64,
) {
    let key = (rule.id, node_id);
    // 阶段一:锁内决策(不跨 await)
    let mut do_fire = false;
    let mut resolve_event: Option<i64> = None;
    {
        let mut map = st.alert_rt.lock();
        let b = map.entry(key).or_default();
        if breaching {
            if b.since.is_none() {
                b.since = Some(now);
            }
            let elapsed = now.saturating_sub(b.since.unwrap_or(now));
            // 离线抗抖:刚从离线恢复不久又离线,要求持续更久才再次告警(见 offline_fire_debounce)。
            let need = offline_fire_debounce(&rule.metric, debounce, b.recovered_at, now);
            if !b.firing && elapsed >= need {
                b.firing = true; // 乐观置位,防同键重复插入
                do_fire = true;
            }
        } else {
            if b.firing {
                resolve_event = b.event_id;
                b.firing = false;
                if rule.metric == "offline" {
                    b.recovered_at = Some(now); // 记录恢复时刻,供抗抖判断
                }
            }
            b.since = None;
            b.event_id = None;
        }
    }

    if do_fire {
        let msg = format_message(rule, val, true);
        let ins = sqlx::query!(
            "INSERT INTO alert_events(rule_id, node_id, state, value, started_at, message, last_notified_at)
             VALUES(?1, ?2, 'firing', ?3, ?4, ?5, ?4)",
            rule.id,
            node_id,
            val,
            now,
            msg
        )
        .execute(&st.db)
        .await;
        match ins {
            Ok(r) => {
                let eid = r.last_insert_rowid();
                // 回填前复核:INSERT 的 await 期间,若并发的 not-breaching 转移已把本键置为
                // 非 firing(彼时 event_id 还是 None 无从消解),此处立即把刚插入的事件标记
                // resolved,避免在库里留下永不消解的幽灵 firing 事件。
                let still_firing = {
                    let mut map = st.alert_rt.lock();
                    let b = map.entry(key).or_default();
                    if b.firing && b.event_id.is_none() {
                        b.event_id = Some(eid);
                        true
                    } else {
                        false
                    }
                };
                if still_firing {
                    push_and_notify(st, rule, node_id, val, true).await;
                } else {
                    let _ = sqlx::query!(
                        "UPDATE alert_events SET state = 'resolved', resolved_at = ?1 WHERE id = ?2 AND resolved_at IS NULL",
                        now,
                        eid
                    )
                    .execute(&st.db)
                    .await;
                }
            }
            Err(e) => tracing::error!(error = %e, "告警事件写入失败"),
        }
    } else if let Some(eid) = resolve_event {
        let _ = sqlx::query!(
            "UPDATE alert_events SET state = 'resolved', resolved_at = ?1 WHERE id = ?2 AND resolved_at IS NULL",
            now,
            eid
        )
        .execute(&st.db)
        .await;
        push_and_notify(st, rule, node_id, val, false).await;
    }
}

fn format_message(rule: &RuleLite, val: f64, firing: bool) -> String {
    let label = metric_label(&rule.metric);
    if rule.metric == "offline" {
        return if firing {
            format!("节点离线(规则:{})", rule.name)
        } else {
            format!("节点恢复在线(规则:{})", rule.name)
        };
    }
    if rule.comparator == "roc" {
        let w = rule.roc_window_secs.max(30);
        let win = if w < 60 { format!("{w} 秒") } else { format!("{} 分钟", w / 60) };
        return if firing {
            format!(
                "{label} 在 {win} 内变化 {val:+.1}(阈值 ±{:.1};规则:{})",
                rule.threshold, rule.name
            )
        } else {
            format!("{label} 变化已恢复平稳(规则:{})", rule.name)
        };
    }
    let cmp = if rule.comparator == "lt" || rule.comparator == "lte" { "低于" } else { "高于" };
    if firing {
        format!("{label} {val:.1} {cmp}阈值 {:.1}(规则:{})", rule.threshold, rule.name)
    } else {
        format!("{label} 已恢复:{val:.1}(规则:{})", rule.name)
    }
}

fn metric_label(m: &str) -> &'static str {
    match m {
        "cpu_pct" => "CPU 使用率",
        "mem_pct" => "内存使用率",
        "disk_pct" => "磁盘使用率",
        "swap_pct" => "Swap 使用率",
        "load1" => "1 分钟负载",
        "cpu_temp" => "CPU 温度(℃)",
        "tcp_conns" => "TCP 连接数",
        "inode_pct" => "inode 使用率",
        "services_down" => "异常服务数",
        "offline" => "在线状态",
        _ => "指标",
    }
}

/// 推送到 UI + 分发到通知渠道(异步,不阻塞调用者)。
async fn push_and_notify(st: &AppState, rule: &RuleLite, node_id: i64, val: f64, firing: bool) {
    let node_name = sqlx::query_scalar!(r#"SELECT name as "name!" FROM nodes WHERE id = ?1"#, node_id)
        .fetch_optional(&st.db)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();

    let body = format_message(rule, val, firing);
    let icon = if firing { "🔴" } else { "🟢" };
    let head = if firing { "[告警]" } else { "[恢复]" };
    let text = format!("{icon} {head} 节点 {node_name} · {body}");

    // UI 实时推送(数据已是我们自造的安全字符串;前端仍 textContent 渲染)
    let live = serde_json::json!({
        "type": "alert",
        "node_id": node_id,
        "firing": firing,
        "rule": rule.name,
        "severity": rule.severity,
        "text": text,
        "ts": unix_now(),
    });
    let _ = st.live_tx.send(live.to_string());

    // 静默窗口:命中则不外发通知(UI 已推、事件已记录)
    if is_silenced(st, node_id, rule.id, unix_now()).await {
        return;
    }
    notify_all(st, &text, &rule.severity).await;
}

/// 是否命中生效中的静默窗口(按节点/规则,NULL 表示通配)。
pub async fn is_silenced(st: &AppState, node_id: i64, rule_id: i64, now: i64) -> bool {
    sqlx::query_scalar!(
        r#"SELECT id as "id!" FROM alert_silences
           WHERE start_ts <= ?1 AND end_ts > ?1
             AND (node_id IS NULL OR node_id = ?2)
             AND (rule_id IS NULL OR rule_id = ?3)
           LIMIT 1"#,
        now,
        node_id,
        rule_id
    )
    .fetch_optional(&st.db)
    .await
    .ok()
    .flatten()
    .is_some()
}

/// 简易 FNV-1a,用于去重键(非密码学用途)。
fn text_hash(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// 向匹配严重度的启用渠道发送一段文本(异步、去重节流、失败仅记录)。
/// 渠道仅接收 >= 自身 `min_severity` 的告警。供告警与登录通知复用
///(登录/新设备等系统通知按 `info` 级发送)。
pub async fn notify_all(st: &AppState, text: &str, severity: &str) {
    let alert_rank = sev_rank(severity);
    let channels = sqlx::query!(
        r#"SELECT id as "id!", kind as "kind!", url as "url!", extra as "extra!",
                  min_severity as "min_severity!"
           FROM notify_channels WHERE enabled = 1"#
    )
    .fetch_all(&st.db)
    .await
    .unwrap_or_default();

    let allow_private = st.cfg.notify.allow_private_targets;
    let now = unix_now();
    let h = text_hash(text);
    for ch in channels {
        // 严重度路由:渠道 min_severity 高于本次告警级别则跳过
        if sev_rank(&ch.min_severity) > alert_rank {
            continue;
        }
        // 去重节流:同渠道同文本 NOTIFY_DEDUP_SECS 内只发一次
        {
            let mut guard = st
                .notify_throttle
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if guard.len() > 4096 {
                guard.retain(|_, &mut t| now.saturating_sub(t) < 3600);
            }
            let key = (ch.id, h);
            if guard.get(&key).is_some_and(|&t| now.saturating_sub(t) < NOTIFY_DEDUP_SECS) {
                continue;
            }
            guard.insert(key, now);
        }
        let (kind, url, extra, text_owned, cid) =
            (ch.kind, ch.url, ch.extra, text.to_string(), ch.id);
        tokio::spawn(async move {
            match send_one(&kind, &url, &extra, &text_owned, allow_private).await {
                Ok(code) if (200..300).contains(&code) => {}
                Ok(code) => tracing::warn!(channel = cid, status = code, "通知返回非 2xx"),
                Err(e) => tracing::warn!(channel = cid, error = %e, "通知发送失败"),
            }
        });
    }
}

/// 按渠道类型构造并发送。全部经 SSRF 加固的 [`crate::notify::post_json`]。
pub(crate) async fn send_one(
    kind: &str,
    url: &str,
    extra: &str,
    text: &str,
    allow_private: bool,
) -> Result<u16, String> {
    match kind {
        "webhook" => {
            let payload = webhook_payload(url, text);
            crate::notify::post_json(url, &payload, allow_private).await
        }
        "telegram" => {
            // url = bot token(已在入库前校验形态);目标 api.telegram.org 为公网
            if !valid_telegram_token(url) {
                return Err("Telegram token 形态非法".into());
            }
            let endpoint = format!("https://api.telegram.org/bot{url}/sendMessage");
            let chat: serde_json::Value = if extra.starts_with('@') {
                serde_json::Value::String(extra.to_string())
            } else {
                extra.parse::<i64>().map_or_else(
                    |_| serde_json::Value::String(extra.to_string()),
                    serde_json::Value::from,
                )
            };
            let body = serde_json::json!({ "chat_id": chat, "text": text }).to_string();
            crate::notify::post_json(&endpoint, &body, allow_private).await
        }
        "bark" => {
            // url = Bark 推送基址(https://<server>/<key>);标题+正文 JSON
            let body = serde_json::json!({ "title": "Outpost", "body": text }).to_string();
            crate::notify::post_json(url, &body, allow_private).await
        }
        "smtp" => {
            // extra = SmtpCfg JSON(含 host/凭据/收发件)
            let cfg: crate::notify_smtp::SmtpCfg =
                serde_json::from_str(extra).map_err(|_| "SMTP 配置损坏".to_string())?;
            crate::notify_smtp::send(&cfg, "Outpost 告警通知", text, allow_private, unix_now()).await
        }
        _ => Err("未知渠道类型".into()),
    }
}

/// 按目标平台自动适配消息体(飞书/钉钉/Slack/通用),用 serde 构造避免注入。
pub(crate) fn webhook_payload(url: &str, text: &str) -> String {
    let host = url
        .strip_prefix("https://")
        .and_then(|r| r.split('/').next())
        .unwrap_or("");
    let v = if host.contains("feishu") || host.contains("larksuite") {
        serde_json::json!({ "msg_type": "text", "content": { "text": text } })
    } else if host.contains("dingtalk") || host.contains("qyapi.weixin") {
        // 钉钉与企业微信同为 msgtype/text/content 结构
        serde_json::json!({ "msgtype": "text", "text": { "content": text } })
    } else {
        // Slack 及通用接收端:同时给 text 与结构化字段
        serde_json::json!({ "text": text })
    };
    v.to_string()
}

/// 丢弃某规则的全部运行态键(规则停用/删除时)。
pub fn forget_rule(st: &AppState, rule_id: i64) {
    st.alert_rt.lock().retain(|k, _| k.0 != rule_id);
}

/// 丢弃某节点的全部运行态键(节点删除时)。
pub fn forget_node(st: &AppState, node_id: i64) {
    st.alert_rt.lock().retain(|k, _| k.1 != node_id);
}

/// 停用规则时:关闭其未消解事件并清运行态(否则会永久 firing)。
pub async fn resolve_rule_events(st: &AppState, rule_id: i64) {
    let now = unix_now();
    let _ = sqlx::query!(
        "UPDATE alert_events SET state='resolved', resolved_at=?1 WHERE rule_id=?2 AND resolved_at IS NULL",
        now,
        rule_id
    )
    .execute(&st.db)
    .await;
    forget_rule(st, rule_id);
}

/// 启动时对账:内存态已清空,遗留的 firing 事件标记为 resolved(重启视为消解)。
pub async fn reconcile_on_startup(st: &AppState) {
    let now = unix_now();
    let n = sqlx::query!(
        "UPDATE alert_events SET state='resolved', resolved_at=?1,
                message = message || ' (服务重启对账)'
         WHERE resolved_at IS NULL",
        now
    )
    .execute(&st.db)
    .await;
    if let Ok(r) = n {
        if r.rows_affected() > 0 {
            tracing::info!(closed = r.rows_affected(), "启动对账:关闭遗留 firing 事件");
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    fn m() -> Metrics {
        Metrics {
            ts: 0, cpu_pct: 95.0, load1: 3.0, load5: 0.0, load15: 0.0,
            mem_total: 1000, mem_used: 800, mem_available: 200,
            swap_total: 100, swap_used: 90, disks: vec![], disk_read_bps: 0,
            disk_write_bps: 0, nets: vec![], uptime_secs: 0, procs: 0,
            cpu_temp_c: Some(60.0), tcp_conns: Some(100),
            disk_read_iops: 0, disk_write_iops: 0, procs_watch: vec![],
            cpu_per_core: vec![], services: vec![], top_procs: vec![],
            tcp_estab: None, tcp_listen: None, tcp_time_wait: None,
            containers: vec![],
        }
    }

    #[test]
    fn metric_values_computed() {
        let s = m();
        assert!((metric_value("cpu_pct", &s, 0, 0).unwrap() - 95.0).abs() < 1e-9);
        assert!((metric_value("mem_pct", &s, 0, 0).unwrap() - 80.0).abs() < 1e-9);
        // disks 为空时回退到入参主盘
        assert!((metric_value("disk_pct", &s, 200, 50).unwrap() - 25.0).abs() < 1e-9);
        assert!((metric_value("swap_pct", &s, 0, 0).unwrap() - 90.0).abs() < 1e-9);
        // 无任何磁盘数据(disks 空且入参 total=0)→ 返回 None 不评估,优于旧的 Some(0.0)
        // (后者会让"disk_pct < X"规则误报)。
        assert!(metric_value("disk_pct", &s, 0, 0).is_none());
        // 遍历所有挂载点取最大使用率:/ 20% 与 /data 95% → 取 95%(次盘满也能告警)
        let mut sd = m();
        sd.disks = vec![
            outpost_common::DiskUsage { mount: "/".into(), fs: "ext4".into(), total: 100, used: 20, inodes_total: 0, inodes_used: 0 },
            outpost_common::DiskUsage { mount: "/data".into(), fs: "ext4".into(), total: 100, used: 95, inodes_total: 0, inodes_used: 0 },
        ];
        assert!((metric_value("disk_pct", &sd, 100, 20).unwrap() - 95.0).abs() < 1e-9);
        assert!(metric_value("unknown", &s, 0, 0).is_none());
    }

    #[test]
    fn roc_whitelist_and_message() {
        assert!(valid_comparator("roc"));
        assert!(valid_roc_metric("cpu_pct") && !valid_roc_metric("tcp_conns"));
        let rule = RuleLite {
            id: 1,
            name: "spike".into(),
            metric: "cpu_pct".into(),
            comparator: "roc".into(),
            threshold: 30.0,
            duration_secs: 0,
            severity: "warning".into(),
            roc_window_secs: 300,
            node_id: None,
        };
        let msg = format_message(&rule, 42.5, true);
        assert!(msg.contains("变化") && msg.contains("+42.5"));
        let resolved = format_message(&rule, 0.0, false);
        assert!(resolved.contains("恢复"));
    }

    #[test]
    fn whitelists() {
        assert!(valid_metric("cpu_pct") && valid_metric("offline"));
        assert!(!valid_metric("cpu_pct; DROP TABLE"));
        assert!(valid_comparator("gt") && !valid_comparator("regex"));
        assert!(valid_channel_kind("webhook") && !valid_channel_kind("exec"));
    }

    #[test]
    fn telegram_validators() {
        assert!(valid_telegram_token("123456789:AAF-abcDEFghiJKLmno1234567890xyz"));
        assert!(!valid_telegram_token("noколон"));
        assert!(!valid_telegram_token("123:short"));
        assert!(!valid_telegram_token("abc:AAF-abcDEFghiJKLmno1234567890xyz"));
        assert!(valid_chat_id("123456"));
        assert!(valid_chat_id("-1001234567"));
        assert!(valid_chat_id("@mychannel"));
        assert!(!valid_chat_id("@ab"));
        assert!(!valid_chat_id("12x34"));
        assert!(!valid_chat_id(""));
    }

    #[test]
    fn dedup_hash_stable() {
        assert_eq!(text_hash("hello"), text_hash("hello"));
        assert_ne!(text_hash("hello"), text_hash("world"));
    }

    #[test]
    fn payload_adapts_by_host() {
        assert!(webhook_payload("https://open.feishu.cn/x", "hi").contains("msg_type"));
        assert!(webhook_payload("https://oapi.dingtalk.com/x", "hi").contains("msgtype"));
        assert!(webhook_payload("https://hooks.slack.com/x", "hi").contains("\"text\""));
        // 注入字符经 serde 转义
        assert!(webhook_payload("https://x.com", "a\"b\n").contains("a\\\"b\\n"));
    }

    #[test]
    fn offline_flap_hysteresis() {
        let now = 10_000;
        // 首次离线(从未恢复过):用基础确认时长,及时告警
        assert_eq!(offline_fire_debounce("offline", 30, None, now), 30);
        // 刚恢复不久(抗抖窗口内)又离线:抬高到抗抖再触发时长,滤掉刷屏
        assert_eq!(offline_fire_debounce("offline", 30, Some(now - 60), now), FLAP_REFIRE_SECS);
        // 恢复已久(超出抗抖窗口):回到基础确认时长
        assert_eq!(offline_fire_debounce("offline", 30, Some(now - FLAP_WINDOW_SECS - 1), now), 30);
        // 非离线规则:抗抖动不介入,原样返回基础消抖
        assert_eq!(offline_fire_debounce("cpu_pct", 30, Some(now - 60), now), 30);
        // 基础消抖已比抗抖阈值更大时,取更大者(不缩短用户设定)
        assert_eq!(offline_fire_debounce("offline", 600, Some(now - 60), now), 600);
    }
}
