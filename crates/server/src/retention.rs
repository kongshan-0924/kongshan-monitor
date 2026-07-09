//! 历史数据保留:每小时聚合原始指标到小时表(降采样),再按设置清理过期
//! 原始点 / 聚合点 / 告警事件 + 增量 vacuum,防 SQLite 膨胀。

use crate::state::AppState;
use crate::util::unix_now;
use sqlx::SqlitePool;
use std::os::unix::fs::PermissionsExt;
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

        // detail JSON(容器/每核 CPU/进程明细)体积大、历史价值低:比原始点更早
        // 清空为 '{}',只保留核心数值列供长期图表,压缩历史行体积(配合末尾的
        // incremental_vacuum 回收空间)。默认 7 天,可经 settings 键 detail_retention_days 调整。
        let ddays = crate::db::setting_i64(&st.db, "detail_retention_days", 7, 1, 3650).await;
        let dcut = unix_now().saturating_sub(ddays.saturating_mul(86400));
        match sqlx::query!("UPDATE metrics SET detail = '{}' WHERE ts < ?1 AND detail <> '{}'", dcut)
            .execute(&st.db)
            .await
        {
            Ok(r) if r.rows_affected() > 0 => {
                tracing::info!(cleared = r.rows_affected(), days = ddays, "过期 detail 明细已清空");
            }
            Ok(_) => {}
            Err(e) => tracing::error!(error = %e, "detail 清空失败"),
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

        auto_backup(&st).await;
        crate::traffic::sweep_resets(&st).await;
    }
}

/// 定时本地备份(轮转):按设置周期 VACUUM INTO 到 <db 目录>/backups,保留最近 N 份。
async fn auto_backup(st: &AppState) {
    let hours = crate::db::setting_i64(&st.db, "auto_backup_hours", 0, 0, 168).await;
    if hours <= 0 {
        return; // 关闭
    }
    let now = unix_now();
    let last = crate::db::setting_i64(&st.db, "auto_backup_last", 0, 0, i64::MAX).await;
    if now.saturating_sub(last) < hours.saturating_mul(3600) {
        return;
    }
    let keep = usize::try_from(crate::db::setting_i64(&st.db, "auto_backup_keep", 7, 1, 90).await).unwrap_or(7);
    let db_path = std::path::Path::new(&st.cfg.storage.db_path);
    let Some(dir) = db_path.parent() else { return };
    let bdir = dir.join("backups");
    if let Err(e) = std::fs::create_dir_all(&bdir) {
        tracing::error!(error = %e, "创建备份目录失败");
        return;
    }
    let target = bdir.join(format!("outpost-{now}.db"));
    let Some(target_str) = target.to_str() else { return };
    // 路径由服务端派生(无用户输入),仍对单引号转义以防万一
    let q = format!("VACUUM INTO '{}'", target_str.replace('\'', "''"));
    match sqlx::query(&q).execute(&st.db).await {
        Ok(_) => {
            // 备份内含密码哈希/API Token 等敏感数据,显式收紧权限,不依赖 umask 副作用。
            if let Err(e) = std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)) {
                tracing::error!(error = %e, path = target_str, "备份文件权限设置失败");
            }
            let _ = crate::db::set_setting(&st.db, "auto_backup_last", &now.to_string()).await;
            tracing::info!(path = target_str, "自动备份完成");
            rotate_backups(&bdir, keep);
        }
        Err(e) => tracing::error!(error = %e, "自动备份失败"),
    }
}

/// 轮转:文件名含 unix 时间戳,字典序即时间序;删除超出保留数的最旧份。
fn rotate_backups(dir: &std::path::Path, keep: usize) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    let mut files: Vec<std::path::PathBuf> = rd
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("outpost-") && n.ends_with(".db"))
        })
        .collect();
    files.sort();
    let remove = files.len().saturating_sub(keep);
    for old in files.iter().take(remove) {
        let _ = std::fs::remove_file(old);
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
