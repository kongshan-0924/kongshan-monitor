//! 历史数据保留:每小时按设置清理过期指标 + 增量 vacuum,防 SQLite 膨胀。

use crate::state::AppState;
use crate::util::unix_now;
use std::time::Duration;

pub async fn run(st: AppState) {
    let mut tick = tokio::time::interval(Duration::from_secs(3600));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tick.tick().await;
        let days = crate::db::setting_i64(&st.db, "retention_days", 30, 1, 3650).await;
        let cutoff = unix_now().saturating_sub(days.saturating_mul(86400));
        match sqlx::query!("DELETE FROM metrics WHERE ts < ?1", cutoff).execute(&st.db).await {
            Ok(r) if r.rows_affected() > 0 => {
                tracing::info!(deleted = r.rows_affected(), days, "过期指标已清理");
            }
            Ok(_) => {}
            Err(e) => tracing::error!(error = %e, "指标清理失败"),
        }
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
