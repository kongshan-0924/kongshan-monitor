//! 审计日志:敏感操作留痕(规范 6.1.12)。绝不写入 token / 密码 / 密钥内容。

use sqlx::SqlitePool;

/// 记录一条审计事件。失败仅记日志,不影响主流程。
pub async fn log(pool: &SqlitePool, username: &str, ip: &str, action: &str, detail: &str) {
    let ts = outpost_common::unix_now();
    // detail 由调用方书写(节点名等已清洗数据),再兜底限长
    let detail = outpost_common::clean_str(detail, 256);
    let username = outpost_common::clean_str(username, 64);
    let ip = outpost_common::clean_str(ip, 64);
    if let Err(e) = sqlx::query!(
        "INSERT INTO audit_log(ts, username, ip, action, detail) VALUES(?1, ?2, ?3, ?4, ?5)",
        ts,
        username,
        ip,
        action,
        detail
    )
    .execute(pool)
    .await
    {
        tracing::error!(error = %e, "audit log write failed");
    }
}
