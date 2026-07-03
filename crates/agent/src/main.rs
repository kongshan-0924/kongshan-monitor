//! outpost-agent:只读采集 + WSS 上报。
//! 安全要点:严格 TLS 校验(自定义 CA 亦是校验而非跳过)、token 不落日志、
//! 下行消息强类型白名单、断线指数退避、单线程小内存运行时。

mod collect;
mod config;
#[macro_use]
mod logging;
mod parsers;

use crate::collect::Sampler;
use crate::config::AgentConfig;
use futures_util::{Sink, SinkExt, StreamExt};
use outpost_common::{AgentToServer, Metrics, ServerToAgent};
use std::collections::VecDeque;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::header::AUTHORIZATION;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::Connector;

const VERSION: &str = env!("CARGO_PKG_VERSION");

fn main() -> ExitCode {
    let mut cfg_path = std::env::var("OUTPOST_AGENT_CONFIG")
        .unwrap_or_else(|_| "/etc/outpost-agent/config.toml".to_string());
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--version" | "-V" => {
                println!("outpost-agent {VERSION}");
                return ExitCode::SUCCESS;
            }
            "--config" => {
                let Some(p) = args.next() else {
                    log_error!("--config 需要参数");
                    return ExitCode::FAILURE;
                };
                cfg_path = p;
            }
            other => {
                log_error!("未知参数: {other}");
                return ExitCode::FAILURE;
            }
        }
    }

    if rustls::crypto::ring::default_provider().install_default().is_err() {
        log_error!("rustls provider 安装失败");
        return ExitCode::FAILURE;
    }

    let cfg = match AgentConfig::load(&cfg_path) {
        Ok(c) => c,
        Err(e) => {
            log_error!("配置 {cfg_path} 加载失败: {e}");
            return ExitCode::FAILURE;
        }
    };

    let token = match read_token(&cfg.token_file) {
        Ok(t) => t,
        Err(e) => {
            log_error!("token 读取失败: {e}");
            return ExitCode::FAILURE;
        }
    };

    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(r) => r,
        Err(e) => {
            log_error!("运行时启动失败: {e}");
            return ExitCode::FAILURE;
        }
    };
    rt.block_on(run(cfg, token))
}

/// 读取并校验 token(64 位小写 hex)。内容绝不打印。
fn read_token(path: &str) -> Result<String, String> {
    let raw = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    let tok = raw.trim().to_string();
    if tok.len() != 64 || !outpost_common::is_lower_hex(&tok) {
        return Err("token 格式非法(需 64 位小写 hex)".to_string());
    }
    Ok(tok)
}

/// 构建严格校验的 TLS 配置:自定义 CA(仅信任它)或系统 webpki 根。
/// 本代码库不存在任何"跳过证书校验"的分支(红线 2)。
fn build_tls(cfg: &AgentConfig) -> Result<Arc<rustls::ClientConfig>, String> {
    let mut roots = rustls::RootCertStore::empty();
    match &cfg.ca_file {
        Some(path) => {
            use rustls_pki_types::pem::PemObject;
            let pem = std::fs::read(path).map_err(|e| format!("CA {path}: {e}"))?;
            let mut added = 0usize;
            for cert in rustls_pki_types::CertificateDer::pem_slice_iter(&pem) {
                let cert = cert.map_err(|e| format!("CA 解析失败: {e}"))?;
                roots.add(cert).map_err(|e| format!("CA 无效: {e}"))?;
                added = added.saturating_add(1);
            }
            if added == 0 {
                return Err("CA 文件中没有证书".to_string());
            }
            log_info!("使用自定义 CA({added} 张)严格校验服务端证书");
        }
        None => {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
    }
    let tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(Arc::new(tls))
}

async fn run(cfg: AgentConfig, token: String) -> ExitCode {
    let tls = match build_tls(&cfg) {
        Ok(t) => t,
        Err(e) => {
            log_error!("TLS 初始化失败: {e}");
            return ExitCode::FAILURE;
        }
    };

    let (stop_tx, mut stop_rx) = tokio::sync::watch::channel(false);
    tokio::spawn(async move {
        wait_shutdown().await;
        let _ = stop_tx.send(true);
    });

    let mut sampler = Sampler::new();
    sampler.set_watch(cfg.watch_processes.clone());
    sampler.set_watch_services(cfg.watch_services.clone());
    let mut interval_secs = cfg.report_interval_secs;
    let mut backoff: u64 = 1;
    // 断线期间的采样缓冲(有界,丢最旧),重连后补传
    let mut buffer: VecDeque<Metrics> = VecDeque::new();

    log_info!("outpost-agent {VERSION} 启动,上报至 {}", cfg.ws_url());
    loop {
        if *stop_rx.borrow() {
            break;
        }
        let session = session(
            &cfg,
            &token,
            &tls,
            &mut sampler,
            &mut interval_secs,
            &mut stop_rx,
            &mut buffer,
        );
        match session.await {
            Ok(()) => {
                // 服务端正常关闭:小间隔重连
                backoff = 1;
            }
            Err(e) => {
                log_warn!("连接中断: {e};{backoff}s 后重连");
            }
        }
        if *stop_rx.borrow() {
            break;
        }
        // 指数退避 + 时间派生抖动(0..400ms),上限 64s;
        // 退避等待期间仍按间隔采样并入缓冲,重连后补传,避免数据空洞
        let jitter = u64::try_from(outpost_common::unix_now()).unwrap_or(0) % 400;
        let wait = Duration::from_millis(backoff.saturating_mul(1000).saturating_add(jitter));
        wait_and_sample(wait, interval_secs, &mut sampler, &mut buffer, &mut stop_rx).await;
        if *stop_rx.borrow() {
            break;
        }
        backoff = (backoff.saturating_mul(2)).min(64);
    }
    log_info!("outpost-agent 退出");
    ExitCode::SUCCESS
}

/// 缓冲上限:约 1000 个采样点(有界,超限丢最旧,防内存膨胀)。
const MAX_BUFFER: usize = 1000;
/// 单条 Backfill 消息最多携带的点数(配合 WS 消息大小上限分块)。
const BACKFILL_CHUNK: usize = 120;

/// 入缓冲,满则丢弃最旧点。
fn push_buffered(buf: &mut VecDeque<Metrics>, m: Metrics) {
    if buf.len() >= MAX_BUFFER {
        buf.pop_front();
    }
    buf.push_back(m);
}

/// 退避等待期间持续采样并入缓冲,直到等待结束或收到停止信号。
async fn wait_and_sample(
    wait: Duration,
    interval_secs: u32,
    sampler: &mut Sampler,
    buffer: &mut VecDeque<Metrics>,
    stop_rx: &mut tokio::sync::watch::Receiver<bool>,
) {
    let deadline = tokio::time::Instant::now() + wait;
    let mut tick = tokio::time::interval(Duration::from_secs(u64::from(interval_secs.max(1))));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tick.tick().await; // 立即触发的首拍,丢弃
    loop {
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => break,
            _ = stop_rx.changed() => break,
            _ = tick.tick() => push_buffered(buffer, sampler.sample()),
        }
    }
}

/// 分块把缓冲点作为 Backfill 消息发送;发送失败即返回错误且缓冲保持不变
/// (下次重连再补传)。成功发送的块才从缓冲移除。
async fn flush_backfill<S>(ws: &mut S, buffer: &mut VecDeque<Metrics>) -> Result<(), String>
where
    S: Sink<Message> + Unpin,
    <S as Sink<Message>>::Error: std::fmt::Display,
{
    if buffer.is_empty() {
        return Ok(());
    }
    let total = buffer.len();
    while !buffer.is_empty() {
        let n = buffer.len().min(BACKFILL_CHUNK);
        let points: Vec<Metrics> = buffer.iter().take(n).cloned().collect();
        let m = AgentToServer::Backfill { points };
        let txt = serde_json::to_string(&m).map_err(|e| format!("序列化失败: {e}"))?;
        ws.send(Message::Text(txt.into())).await.map_err(|e| format!("补传失败: {e}"))?;
        for _ in 0..n {
            buffer.pop_front();
        }
    }
    log_info!("已补传 {total} 个断线期间的采样点");
    Ok(())
}

async fn wait_shutdown() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        if let Ok(mut s) = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            s.recv().await;
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = term => {},
    }
}

/// 单次连接会话:连接 → Hello → 补传缓冲 → 周期上报,处理白名单下行。
async fn session(
    cfg: &AgentConfig,
    token: &str,
    tls: &Arc<rustls::ClientConfig>,
    sampler: &mut Sampler,
    interval_secs: &mut u32,
    stop_rx: &mut tokio::sync::watch::Receiver<bool>,
    buffer: &mut VecDeque<Metrics>,
) -> Result<(), String> {
    let mut req = cfg
        .ws_url()
        .into_client_request()
        .map_err(|e| format!("URL 无效: {e}"))?;
    let auth = format!("Bearer {token}");
    let auth_val = auth.parse().map_err(|_| "认证头构造失败".to_string())?;
    req.headers_mut().insert(AUTHORIZATION, auth_val);

    let ws_cfg = WebSocketConfig::default()
        .max_message_size(Some(outpost_common::MAX_WS_MESSAGE_BYTES))
        .max_frame_size(Some(outpost_common::MAX_WS_MESSAGE_BYTES));

    let connect = tokio_tungstenite::connect_async_tls_with_config(
        req,
        Some(ws_cfg),
        false,
        Some(Connector::Rustls(tls.clone())),
    );
    let (mut ws, _resp) = tokio::time::timeout(Duration::from_secs(15), connect)
        .await
        .map_err(|_| "连接超时".to_string())?
        .map_err(|e| format!("连接失败: {e}"))?;

    log_info!("已连接服务端");

    // 首条:Hello(静态信息)
    let hello = AgentToServer::Hello { host: sampler.host_info() };
    let txt = serde_json::to_string(&hello).map_err(|e| format!("序列化失败: {e}"))?;
    ws.send(Message::Text(txt.into())).await.map_err(|e| format!("发送失败: {e}"))?;

    // 补传断线期间缓冲的采样点(分块;发送失败则保留缓冲,下次重连再传)
    flush_backfill(&mut ws, buffer).await?;

    let mut tick = tokio::time::interval(Duration::from_secs(u64::from(*interval_secs)));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = stop_rx.changed() => {
                let _ = ws.close(None).await;
                return Ok(());
            }
            _ = tick.tick() => {
                let metrics = sampler.sample();
                let m = AgentToServer::Metrics { metrics: metrics.clone() };
                let txt = serde_json::to_string(&m).map_err(|e| format!("序列化失败: {e}"))?;
                if let Err(e) = ws.send(Message::Text(txt.into())).await {
                    // 发送失败:把这条纳入缓冲,断开重连后补传
                    push_buffered(buffer, metrics);
                    return Err(format!("发送失败: {e}"));
                }
            }
            incoming = ws.next() => {
                let Some(msg) = incoming else { return Err("连接被关闭".to_string()) };
                let msg = msg.map_err(|e| format!("接收失败: {e}"))?;
                match msg {
                    Message::Text(t) => {
                        // 服务端也可能被攻破:严格解析,畸形一律忽略(规范 6.2.5)
                        match serde_json::from_str::<ServerToAgent>(t.as_str()) {
                            Ok(ServerToAgent::UpdateConfig { report_interval_secs }) => {
                                let v = report_interval_secs.clamp(1, 3600);
                                if v != *interval_secs {
                                    log_info!("上报间隔更新: {v}s");
                                    *interval_secs = v;
                                    tick = tokio::time::interval(Duration::from_secs(u64::from(v)));
                                    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                                }
                            }
                            Err(e) => log_warn!("忽略无法识别的下行消息: {e}"),
                        }
                    }
                    Message::Close(_) => return Ok(()),
                    // Ping 由 tungstenite 自动回 Pong;Binary 一律忽略
                    _ => {}
                }
            }
        }
    }
}
