//! SQLite 连接与迁移。WAL + 外键 + 增量 vacuum(防膨胀)。

use sqlx::sqlite::{SqliteAutoVacuum, SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use sqlx::SqlitePool;
use std::str::FromStr;
use std::time::Duration;

/// 打开(必要时创建)数据库并执行迁移。
///
/// # Errors
/// 路径不可写 / 迁移失败时返回错误。
pub async fn open(db_path: &str) -> Result<SqlitePool, sqlx::Error> {
    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{db_path}"))?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .auto_vacuum(SqliteAutoVacuum::Incremental)
        .foreign_keys(true)
        .busy_timeout(Duration::from_secs(5));

    let pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(opts)
        .await?;

    sqlx::migrate!("./migrations").run(&pool).await.map_err(|e| {
        sqlx::Error::Protocol(format!("migration failed: {e}"))
    })?;
    Ok(pool)
}

/// 读取设置项(整数),带默认值与范围约束。
pub async fn setting_i64(pool: &SqlitePool, key: &str, default: i64, lo: i64, hi: i64) -> i64 {
    let v: Option<String> = sqlx::query_scalar!("SELECT value FROM settings WHERE key = ?1", key)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();
    v.and_then(|s| s.parse::<i64>().ok())
        .map_or(default, |n| n.clamp(lo, hi))
}

/// 读取设置项(字符串),不存在返回空串。
pub async fn setting_str(pool: &SqlitePool, key: &str) -> String {
    sqlx::query_scalar!("SELECT value FROM settings WHERE key = ?1", key)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten()
        .unwrap_or_default()
}

/// 写入设置项。
///
/// # Errors
/// 数据库写入失败。
pub async fn set_setting(pool: &SqlitePool, key: &str, value: &str) -> Result<(), sqlx::Error> {
    sqlx::query!(
        "INSERT INTO settings(key, value) VALUES(?1, ?2)
         ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        key,
        value
    )
    .execute(pool)
    .await?;
    Ok(())
}
