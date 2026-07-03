//! 历史数据保留:每小时聚合原始指标到小时表(降采样),再按设置清理过期
//! 原始点 / 聚合点 / 告警事件 + 增量 vacuum,防 SQLite 膨胀。

use crate::state::AppState;
use crate::util::unix_now;
use sqlx::SqlitePool;
use std::time::Duration;

/// 重滚窗口:每次多回滚最近 N 小时,以纳入乱序/断线补传的迟到点(INSERT OR REPLACE 幂等)。
const REROLL_HOURS: i64 = 6;

pub async fn run(st: AppState) {
    let mut tick = tokio::time::interval(Duration::from_secs(3600));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;

        // 先把已完成的整点小时聚合入 rollup 表(在清理原始点之前)
        rollup(&st.db).await;

        let days = crate::db::setting_i64(&st.db, "retention_days", 30, 1, 3650).await;
        let cutoff = unix_now().saturating_sub(days.saturating_mul(86400));
        match sqlx::query!("DELETE FROM metrics WHERE ts < ?1", cutoff).execute(&st.db).await {
            Ok(r) if r.rows_affected() > 0 => {
                tracing::info!(deleted = r.rows_affected(), days, "过期指标已清理");
            }
            Ok(_) => {}
            Err(e) => tracing::error!(error = %e, "指标清理失败"),
        }

        // 聚合表保留更久(默认 365 天),原始点删除后仍可看低分辨率长历史
        let rdays = crate::db::setting_i64(&st.db, "rollup_retention_days", 365, 7, 3650).await;
        let rcut = unix_now().saturating_sub(rdays.saturating_mul(86400));
        let _ = sqlx::query!("DELETE FROM metrics_rollup WHERE hour_ts < ?1", rcut)
            .execute(&st.db)
            .await;

        // 告警事件滚动保留:已恢复的保留 90 天;仍触发的(resolved_at IS NULL)永久保留
        let ev_cutoff = unix_now().saturating_sub(90 * 86400);
        let _ = sqlx::query!(
            "DELETE FROM alert_events WHERE resolved_at IS NOT NULL AND resolved_at < ?1",
            ev_cutoff
        )
        .execute(&st.db)
        .await;

        // 审计日志滚动保留:固定 180 天 + 硬上限 10 万行,防无限增长
        let audit_cutoff = unix_now().saturating_sub(180 * 86400);
        let _ = sqlx::query!("DELETE FROM audit_log WHERE ts < ?1", audit_cutoff)
            .execute(&st.db)
            .await;
        let _ = sqlx::query!(
            "DELETE FROM audit_log WHERE id < (SELECT MAX(id) - 100000 FROM audit_log)"
        )
        .execute(&st.db)
        .await;

        // 清理过期会话与注册密钥
        let now = unix_now();
        let _ = sqlx::query!("DELETE FROM sessions WHERE expires_at < ?1", now)
            .execute(&st.db)
            .await;
        let _ = sqlx::query!(
            "DELETE FROM register_keys WHERE expires_at < ?1 AND used_at IS NULL",
            now
        )
        .execute(&st.db)
        .await;
        if let Err(e) = sqlx::query("PRAGMA incremental_vacuum(500)").execute(&st.db).await {
            tracing::warn!(error = %e, "incremental_vacuum 失败");
        }
    }
}

/// 把 [cursor-REROLL_HOURS, 当前整点) 内已完成的小时聚合进 rollup 表(幂等 upsert),
/// 然后把游标推进到当前整点。仅聚合完整小时,当前进行中的小时不聚合。
async fn rollup(db: &SqlitePool) {
    let cur_hour = (unix_now() / 3600) * 3600;
    let cursor = crate::db::setting_i64(db, "rollup_cursor_ts", 0, 0, i64::MAX).await;
    if cur_hour <= cursor.saturating_sub(REROLL_HOURS * 3600) {
        return; // 时钟回拨等异常:不倒退
    }
    let from = cursor.saturating_sub(REROLL_HOURS * 3600).max(0);
    let res = sqlx::query!(
        r#"INSERT OR REPLACE INTO metrics_rollup
             (node_id, hour_ts, samples, cpu_avg, cpu_max, mem_used_avg, mem_total_max,
              swap_used_avg, disk_used_avg, disk_total_max, net_rx_avg, net_tx_avg,
              disk_read_avg, disk_write_avg, load1_avg)
           SELECT node_id, (ts / 3600) * 3600 AS h, COUNT(*),
                  AVG(cpu_pct), MAX(cpu_pct), AVG(mem_used), MAX(mem_total),
                  AVG(swap_used), AVG(disk_used), MAX(disk_total),
                  AVG(net_rx_bps), AVG(net_tx_bps), AVG(disk_read_bps), AVG(disk_write_bps),
                  AVG(load1)
           FROM metrics
           WHERE ts >= ?1 AND ts < ?2
           GROUP BY node_id, h"#,
        from,
        cur_hour
    )
    .execute(db)
    .await;
    match res {
        Ok(r) => {
            if r.rows_affected() > 0 {
                tracing::debug!(buckets = r.rows_affected(), "指标聚合完成");
            }
            let _ = crate::db::set_setting(db, "rollup_cursor_ts", &cur_hour.to_string()).await;
        }
        Err(e) => tracing::error!(error = %e, "指标聚合失败"),
    }
}
