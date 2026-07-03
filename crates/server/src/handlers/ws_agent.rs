//! agent 上报通道(WSS):Bearer token 认证(常量时间)、消息大小限制、
//! 严格反序列化、清洗入库、吊销即时生效、白名单下行(仅 UpdateConfig)。

use crate::errors::AppError;
use crate::ratelimit::Class;
use crate::state::AppState;
use crate::util::{client_ip, ct_eq, sha256_hex, unix_now};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap};
use axum::response::Response;
use outpost_common::{clean_host_info, validate_and_clean_metrics, AgentToServer, ServerToAgent};
use serde_json::json;
use std::net::SocketAddr;
use std::time::Duration;

/// GET /ws/agent(Upgrade)。认证在升级前完成:失败不建立 WS。
pub async fn upgrade(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Result<Response, AppError> {
    let ip = client_ip(peer, &headers, &st.cfg.trusted_proxy_ips());
    if !st.limiter.check(ip, Class::Ws) {
        return Err(AppError::TooManyRequests);
    }

    // Bearer token:64 hex
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(str::trim)
        .unwrap_or("");
    if token.len() != 64 || !outpost_common::is_lower_hex(token) {
        return Err(AppError::Unauthorized);
    }
    let th = sha256_hex(token.as_bytes());
    let row = sqlx::query!(
        r#"SELECT id as "id!", token_hash as "token_hash!", revoked as "revoked!: i64"
           FROM nodes WHERE token_hash = ?1"#,
        th
    )
    .fetch_optional(&st.db)
    .await?;
    let Some(r) = row else { return Err(AppError::Unauthorized) };
    if !ct_eq(&r.token_hash, &th) || r.revoked != 0 {
        return Err(AppError::Unauthorized);
    }

    let node_id = r.id;
    let max = st.cfg.metrics.ws_max_message_bytes;
    tracing::info!(node_id, %ip, "agent 已连接");
    Ok(ws
        .max_message_size(max)
        .max_frame_size(max)
        .on_upgrade(move |sock| conn_loop(st, sock, node_id)))
}

/// 从清洗后的指标构造 detail JSON 与主磁盘(优先 "/",否则容量最大挂载点)。
fn build_detail(m: &outpost_common::Metrics) -> (String, i64, i64) {
    let primary = m
        .disks
        .iter()
        .find(|d| d.mount == "/")
        .or_else(|| m.disks.iter().max_by_key(|d| d.total));
    let (dt, du) = primary.map_or((0i64, 0i64), |d| {
        (
            i64::try_from(d.total).unwrap_or(i64::MAX),
            i64::try_from(d.used).unwrap_or(i64::MAX),
        )
    });
    let detail = json!({
        "disks": m.disks.iter().map(|d| json!({
            "mount": d.mount, "fs": d.fs, "total": d.total, "used": d.used,
            "inodes_total": d.inodes_total, "inodes_used": d.inodes_used,
        })).collect::<Vec<_>>(),
        "nets": m.nets.iter().map(|n| json!({
            "name": n.name, "rx_bps": n.rx_bps, "tx_bps": n.tx_bps,
            "rx_bytes": n.rx_bytes, "tx_bytes": n.tx_bytes,
        })).collect::<Vec<_>>(),
        "cpu_temp_c": m.cpu_temp_c,
        "tcp_conns": m.tcp_conns,
        "disk_read_iops": m.disk_read_iops,
        "disk_write_iops": m.disk_write_iops,
        "cpu_per_core": m.cpu_per_core,
        "procs_watch": m.procs_watch.iter().map(|p| json!({
            "name": p.name, "running": p.running, "count": p.count,
            "cpu_pct": p.cpu_pct, "rss": p.rss,
        })).collect::<Vec<_>>(),
        "services": m.services.iter().map(|s| json!({
            "name": s.name, "active": s.active,
        })).collect::<Vec<_>>(),
        "top_procs": m.top_procs.iter().map(|p| json!({
            "name": p.name, "cpu_pct": p.cpu_pct, "rss": p.rss,
        })).collect::<Vec<_>>(),
        "tcp_estab": m.tcp_estab,
        "tcp_listen": m.tcp_listen,
        "tcp_time_wait": m.tcp_time_wait,
    })
    .to_string();
    (detail, dt, du)
}

#[allow(clippy::too_many_lines)]
async fn conn_loop(st: AppState, mut sock: WebSocket, node_id: i64) {
    let mut interval_rx = st.interval_tx.subscribe();

    // 连接建立即下发当前上报间隔(唯一的白名单下行消息)
    let current = *interval_rx.borrow();
    let msg = ServerToAgent::UpdateConfig { report_interval_secs: current };
    if let Ok(s) = serde_json::to_string(&msg) {
        if sock.send(Message::Text(s.into())).await.is_err() {
            return;
        }
    }

    let mut ping = tokio::time::interval(Duration::from_secs(30));
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut last_activity = tokio::time::Instant::now();

    loop {
        tokio::select! {
            _ = ping.tick() => {
                if last_activity.elapsed() > Duration::from_secs(120) {
                    tracing::info!(node_id, "agent 超时,断开");
                    break;
                }
                if sock.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break;
                }
            }
            changed = interval_rx.changed() => {
                if changed.is_ok() {
                    let v = *interval_rx.borrow_and_update();
                    let m = ServerToAgent::UpdateConfig { report_interval_secs: v };
                    if let Ok(s) = serde_json::to_string(&m) {
                        if sock.send(Message::Text(s.into())).await.is_err() { break; }
                    }
                }
            }
            incoming = sock.recv() => {
                let Some(Ok(msg)) = incoming else { break };
                last_activity = tokio::time::Instant::now();
                match msg {
                    Message::Text(txt) => {
                        // 严格反序列化:未知字段/未知类型一律丢弃并记录
                        match serde_json::from_str::<AgentToServer>(txt.as_str()) {
                            Ok(m) => {
                                if handle_msg(&st, node_id, m).await.is_err() {
                                    // token 已吊销 → 立即断开
                                    tracing::info!(node_id, "token 已吊销,断开连接");
                                    break;
                                }
                            }
                            Err(e) => {
                                tracing::warn!(node_id, error = %e, "拒绝畸形上报");
                            }
                        }
                    }
                    Message::Binary(_) => {
                        tracing::warn!(node_id, "拒绝二进制帧");
                    }
                    Message::Close(_) => break,
                    Message::Ping(_) | Message::Pong(_) => {}
                }
            }
        }
    }
    tracing::info!(node_id, "agent 连接结束");
}

/// Err(()) 表示应断开连接(吊销/删除)。
async fn handle_msg(st: &AppState, node_id: i64, m: AgentToServer) -> Result<(), ()> {
    let now = unix_now();
    match m {
        AgentToServer::Hello { host } => {
            let h = clean_host_info(&host);
            let cores = i64::from(h.cores);
            let mem = i64::try_from(h.mem_total).unwrap_or(i64::MAX);
            let res = sqlx::query!(
                "UPDATE nodes SET hostname=?1, os=?2, kernel=?3, arch=?4, cores=?5,
                        mem_total=?6, agent_version=?7, last_seen=?8
                 WHERE id=?9 AND revoked=0",
                h.hostname, h.os, h.kernel, h.arch, cores, mem, h.agent_version, now, node_id
            )
            .execute(&st.db)
            .await;
            match res {
                Ok(r) if r.rows_affected() == 1 => Ok(()),
                Ok(_) => Err(()),
                Err(e) => {
                    tracing::error!(error = %e, "hello 更新失败");
                    Ok(())
                }
            }
        }
        AgentToServer::Metrics { mut metrics } => {
            // 时钟偏移检查(规范 6.3.6):异常时间戳直接拒绝该条
            let skew = st.cfg.metrics.ts_skew_secs;
            if (metrics.ts - now).abs() > skew {
                tracing::warn!(node_id, agent_ts = metrics.ts, server_ts = now, "时间戳异常,丢弃");
                return Ok(());
            }
            if let Err(e) = validate_and_clean_metrics(&mut metrics) {
                tracing::warn!(node_id, error = e, "指标校验失败,丢弃");
                return Ok(());
            }

            // 吊销即时生效:revoked=0 条件不满足 → 通知断开
            let upd = sqlx::query!(
                "UPDATE nodes SET last_seen = ?1 WHERE id = ?2 AND revoked = 0",
                now,
                node_id
            )
            .execute(&st.db)
            .await;
            match upd {
                Ok(r) if r.rows_affected() == 1 => {}
                Ok(_) => return Err(()),
                Err(e) => {
                    tracing::error!(error = %e, "last_seen 更新失败");
                    return Ok(());
                }
            }

            let (detail, disk_total, disk_used) = build_detail(&metrics);
            // 入库使用 server 时间(抗重放/时钟漂移)
            let mem_total = i64::try_from(metrics.mem_total).unwrap_or(i64::MAX);
            let mem_used = i64::try_from(metrics.mem_used).unwrap_or(i64::MAX);
            let mem_avail = i64::try_from(metrics.mem_available).unwrap_or(i64::MAX);
            let swap_total = i64::try_from(metrics.swap_total).unwrap_or(i64::MAX);
            let swap_used = i64::try_from(metrics.swap_used).unwrap_or(i64::MAX);
            let dr = i64::try_from(metrics.disk_read_bps).unwrap_or(i64::MAX);
            let dw = i64::try_from(metrics.disk_write_bps).unwrap_or(i64::MAX);
            let rx: i64 = metrics
                .nets
                .iter()
                .map(|n| i64::try_from(n.rx_bps).unwrap_or(0))
                .fold(0i64, i64::saturating_add);
            let tx: i64 = metrics
                .nets
                .iter()
                .map(|n| i64::try_from(n.tx_bps).unwrap_or(0))
                .fold(0i64, i64::saturating_add);
            let uptime = i64::try_from(metrics.uptime_secs).unwrap_or(i64::MAX);
            let procs = i64::from(metrics.procs);

            let ins = sqlx::query!(
                "INSERT INTO metrics(node_id, ts, cpu_pct, load1, load5, load15,
                        mem_total, mem_used, mem_available, swap_total, swap_used,
                        disk_total, disk_used, disk_read_bps, disk_write_bps,
                        net_rx_bps, net_tx_bps, uptime_secs, procs, detail)
                 VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20)",
                node_id, now, metrics.cpu_pct, metrics.load1, metrics.load5, metrics.load15,
                mem_total, mem_used, mem_avail, swap_total, swap_used,
                disk_total, disk_used, dr, dw, rx, tx, uptime, procs, detail
            )
            .execute(&st.db)
            .await;
            if let Err(e) = ins {
                tracing::error!(error = %e, "指标写入失败");
                return Ok(());
            }

            // 实时推送给 UI(数据已清洗;前端仍只用 textContent 渲染)
            let live = json!({
                "type": "metrics",
                "node_id": node_id,
                "ts": now,
                "latest": {
                    "ts": now, "cpu_pct": metrics.cpu_pct,
                    "load1": metrics.load1, "load5": metrics.load5, "load15": metrics.load15,
                    "mem_total": metrics.mem_total, "mem_used": metrics.mem_used,
                    "swap_total": metrics.swap_total, "swap_used": metrics.swap_used,
                    "disk_total": disk_total, "disk_used": disk_used,
                    "net_rx_bps": rx, "net_tx_bps": tx,
                    "disk_read_bps": dr, "disk_write_bps": dw,
                    "uptime_secs": metrics.uptime_secs, "procs": metrics.procs,
                    "cpu_temp_c": metrics.cpu_temp_c, "tcp_conns": metrics.tcp_conns,
                    "disk_read_iops": metrics.disk_read_iops, "disk_write_iops": metrics.disk_write_iops,
                }
            });
            let _ = st.live_tx.send(live.to_string());

            // 告警评估(在 clone 出的句柄上跑,不阻断上报循环;数据已清洗)
            let st2 = st.clone();
            let m2 = metrics.clone();
            tokio::spawn(async move {
                crate::alerts::on_metrics(&st2, node_id, &m2, disk_total, disk_used).await;
            });
            Ok(())
        }
        AgentToServer::Backfill { points } => {
            // 断线补传:历史点携带原始 ts。安全边界——仅接受 [now-2h, now+skew] 窗口内的
            // 过去点,按 (node_id, ts) 去重入库;不更新 last_seen、不推实时、不触发告警
            //(避免陈旧数据造成误报)。补传是上行数据,token 持有者即被监控机自身,
            // 允许其补自身近期历史不构成新的威胁面。
            const MAX_BACKFILL_AGE: i64 = 2 * 3600;
            const MAX_POINTS: usize = 500;
            let skew = st.cfg.metrics.ts_skew_secs;

            // 节点须存在且未吊销
            let alive = sqlx::query_scalar!("SELECT 1 FROM nodes WHERE id = ?1 AND revoked = 0", node_id)
                .fetch_optional(&st.db)
                .await
                .ok()
                .flatten();
            if alive.is_none() {
                return Err(());
            }

            let mut inserted = 0u64;
            for mut metrics in points.into_iter().take(MAX_POINTS) {
                let ts = metrics.ts;
                if ts > now.saturating_add(skew) || ts < now.saturating_sub(MAX_BACKFILL_AGE) {
                    continue; // 越界:未来点或过旧点一律丢弃
                }
                if validate_and_clean_metrics(&mut metrics).is_err() {
                    continue;
                }
                let (detail, disk_total, disk_used) = build_detail(&metrics);
                let mem_total = i64::try_from(metrics.mem_total).unwrap_or(i64::MAX);
                let mem_used = i64::try_from(metrics.mem_used).unwrap_or(i64::MAX);
                let mem_avail = i64::try_from(metrics.mem_available).unwrap_or(i64::MAX);
                let swap_total = i64::try_from(metrics.swap_total).unwrap_or(i64::MAX);
                let swap_used = i64::try_from(metrics.swap_used).unwrap_or(i64::MAX);
                let dr = i64::try_from(metrics.disk_read_bps).unwrap_or(i64::MAX);
                let dw = i64::try_from(metrics.disk_write_bps).unwrap_or(i64::MAX);
                let rx: i64 = metrics
                    .nets
                    .iter()
                    .map(|n| i64::try_from(n.rx_bps).unwrap_or(0))
                    .fold(0i64, i64::saturating_add);
                let tx: i64 = metrics
                    .nets
                    .iter()
                    .map(|n| i64::try_from(n.tx_bps).unwrap_or(0))
                    .fold(0i64, i64::saturating_add);
                let uptime = i64::try_from(metrics.uptime_secs).unwrap_or(i64::MAX);
                let procs = i64::from(metrics.procs);
                // 按 (node_id, ts) 去重:同秒已存在则不插入
                let res = sqlx::query!(
                    "INSERT INTO metrics(node_id, ts, cpu_pct, load1, load5, load15,
                            mem_total, mem_used, mem_available, swap_total, swap_used,
                            disk_total, disk_used, disk_read_bps, disk_write_bps,
                            net_rx_bps, net_tx_bps, uptime_secs, procs, detail)
                     SELECT ?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20
                     WHERE NOT EXISTS (SELECT 1 FROM metrics WHERE node_id = ?1 AND ts = ?2)",
                    node_id, ts, metrics.cpu_pct, metrics.load1, metrics.load5, metrics.load15,
                    mem_total, mem_used, mem_avail, swap_total, swap_used,
                    disk_total, disk_used, dr, dw, rx, tx, uptime, procs, detail
                )
                .execute(&st.db)
                .await;
                if let Ok(r) = res {
                    inserted = inserted.saturating_add(r.rows_affected());
                }
            }
            if inserted > 0 {
                tracing::info!(node_id, inserted, "断线补传入库");
            }
            Ok(())
        }
    }
}
