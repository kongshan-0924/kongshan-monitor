//! 节点流量统计:按上报速率(bps)× 时间估算累计收/发字节(不是精确抓包计费,
//! 是监控面板常见的估算口径),可选按月清零。
//!
//! 月份边界计算用纯整数日历算法(Howard Hinnant 的 civil_from_days / days_from_civil,
//! 公有领域算法),不引入 chrono/time 等日期库依赖。清零日限定 1~28,避开"某月没有第
//! 29/30/31 天"的边界问题,不做月末截断。全程按 UTC 天边界计算,不做时区换算。

use crate::state::AppState;
use crate::util::unix_now;

/// 清零日合法范围(避开短月边界问题)。
#[must_use]
pub fn valid_reset_day(d: i64) -> bool {
    (1..=28).contains(&d)
}

/// Unix 天数(自 1970-01-01 起,可为负)→ (年, 月[1..=12], 日[1..=31])。
#[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };
    (year, m, d)
}

/// (年, 月[1..=12], 日[1..=31]) → Unix 天数。
#[allow(clippy::cast_possible_wrap, clippy::cast_possible_truncation)]
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u64; // [0, 399]
    let mp = u64::from(if m > 2 { m - 3 } else { m + 9 }); // [0, 11]
    let doy = (153 * mp + 2) / 5 + u64::from(d) - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe as i64 - 719_468
}

/// 给定当前时刻与"每月第几天清零",计算当前所在统计周期的起始时刻(UTC 当天 00:00:00)。
#[must_use]
pub fn current_period_start(now: i64, reset_day: i64) -> i64 {
    let reset_day = reset_day.clamp(1, 28) as u32;
    let days = now.div_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    let start_days = if d >= reset_day {
        days_from_civil(y, m, reset_day)
    } else {
        let (py, pm) = if m == 1 { (y - 1, 12) } else { (y, m - 1) };
        days_from_civil(py, pm, reset_day)
    };
    start_days * 86400
}

/// 按本次上报的速率估算这段时间的流量,累加进节点的周期计数器。静默失败(不影响主流程)。
///
/// 用**单条原子 UPDATE**完成"读上次时刻→算时长→累加→写新时刻":elapsed 直接以行内当前
/// `traffic_last_ts` 计算,并以 `?now > traffic_last_ts` 作乐观并发保护。此前是先 SELECT
/// 再 UPDATE,同一节点两条上报并发(各自 spawn 的任务)会读到同一 last_ts 而重复累加(C8);
/// 现在写操作串行化后,后者读到的是已提交的新 last_ts,同秒重复上报直接不满足 WHERE、不累加。
/// 报告间隔改从内存 watch 读取,免去每条上报一次 settings 查库(P1-6,热路径去库化)。
pub async fn accumulate(st: &AppState, node_id: i64, now: i64, rx_bps: i64, tx_bps: i64) {
    let interval_secs = i64::from(*st.interval_tx.borrow());
    // 单次计入时长上限:断线重连后不用"离线全部秒数"乘瞬时速率造成流量暴涨;上限取
    // interval*3(与"在线判定"同量级),至少 30s。SQL 里以 MIN(elapsed, cap) 落地。
    let cap = interval_secs.saturating_mul(3).max(30);
    // 把单条上报速率夹到安全上界:被攻陷的 agent(威胁模型 6.2.5)可上报接近 i64 上限的速率,
    // rx*elapsed 越过 i64::MAX 后 SQLite 会把结果转成 REAL,污染 INTEGER 计数列,之后以 i64
    // 读回将解码失败(节点列表/详情 500)。2^40 B/s(~8.8Tbps)远高于任何真实链路,合法数据不受影响。
    const MAX_RATE_BPS: i64 = 1 << 40;
    // 累计总量同样封顶(2^60 B ≈ 1.15 EB,远超任何真实月流量),防恶意上报把总量累加过 i64::MAX。
    const MAX_TRAFFIC_TOTAL: i64 = 1 << 60;
    let rx = rx_bps.clamp(0, MAX_RATE_BPS);
    let tx = tx_bps.clamp(0, MAX_RATE_BPS);
    // last_ts=0(首次上报)只登记时刻、不累加,避免把"从未上报到现在"的时长乘进流量。
    // 各中间量均被夹在安全范围:rx≤2^40、elapsed≤cap<2^14 → 乘积≤2^54;总量+乘积<2^61<i64::MAX,
    // 外层 MIN 再把总量封顶到 2^60,任一步都不会溢出。
    let _ = sqlx::query!(
        "UPDATE nodes SET
            traffic_rx_total = MIN(traffic_rx_total + ?1 * (CASE WHEN traffic_last_ts > 0 THEN MIN(?2 - traffic_last_ts, ?3) ELSE 0 END), ?6),
            traffic_tx_total = MIN(traffic_tx_total + ?4 * (CASE WHEN traffic_last_ts > 0 THEN MIN(?2 - traffic_last_ts, ?3) ELSE 0 END), ?6),
            traffic_last_ts = ?2
         WHERE id = ?5 AND ?2 > traffic_last_ts",
        rx,
        now,
        cap,
        tx,
        node_id,
        MAX_TRAFFIC_TOTAL
    )
    .execute(&st.db)
    .await;
}

/// 周期性(每小时)巡检:对开启按月清零的节点,若已跨过当前统计周期边界则清零。
pub async fn sweep_resets(st: &AppState) {
    let now = unix_now();
    let rows = sqlx::query!(
        r#"SELECT id as "id!", traffic_reset_day as "reset_day!", traffic_period_start as "period_start!"
           FROM nodes WHERE traffic_reset_enabled = 1"#
    )
    .fetch_all(&st.db)
    .await
    .unwrap_or_default();
    for r in rows {
        let expected = current_period_start(now, r.reset_day);
        if r.period_start == 0 {
            // 刚开启按月清零而尚未登记起点(period_start 为 0 哨兵):仅登记本期起点,
            // 不清零已累计流量。否则首次巡检会因 expected≠0 立即把历史流量清空(C12)。
            let _ = sqlx::query!(
                "UPDATE nodes SET traffic_period_start = ?1 WHERE id = ?2 AND traffic_period_start = 0",
                expected,
                r.id
            )
            .execute(&st.db)
            .await;
        } else if expected != r.period_start {
            // 已跨过统计周期边界:清零并登记新起点。
            let _ = sqlx::query!(
                "UPDATE nodes SET traffic_rx_total = 0, traffic_tx_total = 0, traffic_period_start = ?1
                 WHERE id = ?2",
                expected,
                r.id
            )
            .execute(&st.db)
            .await;
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn civil_roundtrip_known_dates() {
        // (unix_days, y, m, d)
        // 天数与日期对照(与 Python `(date - date(1970,1,1)).days` 核对一致)
        let cases: &[(i64, i64, u32, u32)] = &[
            (0, 1970, 1, 1),
            (-1, 1969, 12, 31),
            (19722, 2023, 12, 31),
            (19723, 2024, 1, 1),
            (19781, 2024, 2, 28),
            (19782, 2024, 2, 29), // 闰年(能被 4 整除、不能被 100 整除)
            (19783, 2024, 3, 1),
        ];
        for &(days, y, m, d) in cases {
            assert_eq!(civil_from_days(days), (y, m, d), "civil_from_days({days})");
            assert_eq!(days_from_civil(y, m, d), days, "days_from_civil({y},{m},{d})");
        }
    }

    #[test]
    fn century_leap_rule() {
        // 1900 不是闰年(能被 100 整除但不能被 400 整除);2000 是闰年
        let d1900 = days_from_civil(1900, 2, 28);
        let d1900_mar1 = days_from_civil(1900, 3, 1);
        assert_eq!(d1900_mar1 - d1900, 1); // 1900 年 2 月只有 28 天
        let d2000 = days_from_civil(2000, 2, 28);
        let d2000_mar1 = days_from_civil(2000, 3, 1);
        assert_eq!(d2000_mar1 - d2000, 2); // 2000 年 2 月有 29 天
    }

    #[test]
    fn period_start_same_month_and_rollover() {
        // 2026-07-05,清零日=1 → 本期起点 2026-07-01
        let ts_20260705 = days_from_civil(2026, 7, 5) * 86400 + 12 * 3600;
        assert_eq!(current_period_start(ts_20260705, 1), days_from_civil(2026, 7, 1) * 86400);

        // 2026-07-05,清零日=10 → 还没到本月 10 号,应回退到上月(6 月)10 号
        assert_eq!(current_period_start(ts_20260705, 10), days_from_civil(2026, 6, 10) * 86400);

        // 跨年:2026-01-05,清零日=10 → 上月是 2025-12-10
        let ts_20260105 = days_from_civil(2026, 1, 5) * 86400;
        assert_eq!(current_period_start(ts_20260105, 10), days_from_civil(2025, 12, 10) * 86400);
    }

    #[test]
    fn reset_day_validation() {
        assert!(valid_reset_day(1) && valid_reset_day(28));
        assert!(!valid_reset_day(0) && !valid_reset_day(29) && !valid_reset_day(31));
    }

}
