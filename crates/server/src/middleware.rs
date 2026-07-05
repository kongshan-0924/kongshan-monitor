//! 全局中间件:安全响应头、CSRF/Origin 校验、API 限速。

use crate::errors::AppError;
use crate::ratelimit::Class;
use crate::state::AppState;
use crate::util::client_ip;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderValue, Method};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::net::SocketAddr;

/// 安全响应头(规范 6.1.11)。CSP 严格:无 inline 脚本/样式,仅同源。
pub async fn security_headers(
    State(st): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let is_api = req.uri().path().starts_with("/api/");
    let mut res = next.run(req).await;
    let h = res.headers_mut();

    // connect-src 需包含 ws(s) 形式的公开源(浏览器 WebSocket);随 scheme 适配
    let po = st.public_origin();
    let ws_origin = po.strip_prefix("https://").map_or_else(
        || po.strip_prefix("http://").map_or_else(|| po.clone(), |r| format!("ws://{r}")),
        |r| format!("wss://{r}"),
    );
    let csp = format!(
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
         connect-src 'self' {ws_origin}; font-src 'self'; object-src 'none'; base-uri 'none'; \
         form-action 'self'; frame-ancestors 'none'"
    );
    if let Ok(v) = HeaderValue::from_str(&csp) {
        h.insert(header::CONTENT_SECURITY_POLICY, v);
    }
    h.insert(header::X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(
        "permissions-policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    if st.cfg.security.hsts {
        h.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=63072000"),
        );
    }
    if is_api {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    res
}

/// CSRF 防线(规范 6.1.6):Cookie 会话 + SameSite=Strict 之上,再对改状态请求做
/// Origin 白名单校验;Origin 缺失(非浏览器客户端)时要求自定义头 `x-op`
/// (跨站上下文无法携带自定义头,除非通过 CORS 预检——本服务不启用 CORS)。
/// `/api/agent/*` 豁免:该路径不使用 Cookie 认证,不存在 CSRF 面。
pub async fn csrf_origin_check(
    State(st): State<AppState>,
    req: Request,
    next: Next,
) -> Response {
    let m = req.method();
    let unsafe_method =
        matches!(*m, Method::POST | Method::PUT | Method::PATCH | Method::DELETE);
    let path = req.uri().path();
    if unsafe_method && path.starts_with("/api/") && !path.starts_with("/api/agent/") {
        let origin = req.headers().get(header::ORIGIN).and_then(|v| v.to_str().ok());
        let allowed = st.allowed_origins();
        let ok = match origin {
            Some(o) => allowed.iter().any(|a| a == o),
            None => req.headers().contains_key("x-op"),
        };
        if !ok {
            tracing::warn!(path, origin = origin.unwrap_or("-"), "CSRF/Origin 校验拒绝");
            return AppError::Forbidden.into_response();
        }
    }
    next.run(req).await
}

/// API 通用限速(登录/注册等端点内部还有更严格的专用限速)。
pub async fn api_rate_limit(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    let ip = client_ip(peer, req.headers(), &st.cfg.trusted_proxy_ips());
    if !st.limiter.check(ip, Class::Api) {
        return AppError::TooManyRequests.into_response();
    }
    next.run(req).await
}
