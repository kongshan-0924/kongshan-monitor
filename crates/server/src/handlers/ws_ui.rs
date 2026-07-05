//! 浏览器实时推送通道:会话认证 + Origin 校验后升级,单向下发(忽略上行内容)。

use crate::errors::AppError;
use crate::ratelimit::Class;
use crate::session::try_session;
use crate::state::AppState;
use crate::util::client_ip;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State};
use axum::http::{header, HeaderMap};
use axum::response::Response;
use std::net::SocketAddr;
use std::time::Duration;

/// GET /ws/ui(Upgrade)。
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
    // 会话认证(Cookie);未认证不升级
    if try_session(&st, &headers).await.is_none() {
        return Err(AppError::Unauthorized);
    }
    // WS 不受 SameSite 保护 → 显式校验 Origin,防跨站 WebSocket 劫持
    let origin = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()).unwrap_or("");
    if !st.allowed_origins().iter().any(|a| a == origin) {
        tracing::warn!(origin, "WS Origin 校验拒绝");
        return Err(AppError::Forbidden);
    }
    Ok(ws
        .max_message_size(4096)
        .max_frame_size(4096)
        .on_upgrade(move |sock| conn_loop(st, sock)))
}

async fn conn_loop(st: AppState, mut sock: WebSocket) {
    let mut rx = st.live_tx.subscribe();
    let mut ping = tokio::time::interval(Duration::from_secs(30));
    ping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = ping.tick() => {
                if sock.send(Message::Ping(Vec::new().into())).await.is_err() {
                    break;
                }
            }
            item = rx.recv() => {
                match item {
                    Ok(txt) => {
                        if sock.send(Message::Text(txt.into())).await.is_err() {
                            break;
                        }
                    }
                    // 慢消费者被挤掉若干条:继续即可(UI 会以下一条刷新)
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
                }
            }
            incoming = sock.recv() => {
                match incoming {
                    // 上行内容一律忽略(通道单向),仅处理关闭
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Ok(_)) => {}
                    Some(Err(_)) => break,
                }
            }
        }
    }
}
