//! 页面与静态资源:全部编译期内嵌(单二进制部署),白名单精确匹配,
//! 不存在文件系统路径拼接 → 无路径遍历面。
//! 页面本身是无数据的静态壳(所有数据经认证 API 获取),受保护页面未登录时 302。

use crate::session::try_session;
use crate::state::AppState;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};

const HTML: &str = "text/html; charset=utf-8";

fn page(body: &'static str) -> Response {
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, HTML),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        body,
    )
        .into_response()
}

/// 静态资源白名单:(URL 名, 内容, MIME)。新增文件必须显式登记。
const ASSETS: &[(&str, &str, &str)] = &[
    ("app.css", include_str!("../../static/app.css"), "text/css; charset=utf-8"),
    ("app.js", include_str!("../../static/app.js"), "text/javascript; charset=utf-8"),
    ("chart.js", include_str!("../../static/chart.js"), "text/javascript; charset=utf-8"),
    ("dashboard.js", include_str!("../../static/dashboard.js"), "text/javascript; charset=utf-8"),
    ("node.js", include_str!("../../static/node.js"), "text/javascript; charset=utf-8"),
    ("settings.js", include_str!("../../static/settings.js"), "text/javascript; charset=utf-8"),
    ("alerts.js", include_str!("../../static/alerts.js"), "text/javascript; charset=utf-8"),
    ("compare.js", include_str!("../../static/compare.js"), "text/javascript; charset=utf-8"),
    ("status.js", include_str!("../../static/status.js"), "text/javascript; charset=utf-8"),
    ("auth.js", include_str!("../../static/auth.js"), "text/javascript; charset=utf-8"),
    ("favicon.svg", include_str!("../../static/favicon.svg"), "image/svg+xml"),
];

/// GET /static/{file}
pub async fn asset(Path(name): Path<String>) -> Response {
    for (n, body, mime) in ASSETS {
        if *n == name {
            return (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, *mime),
                    (header::CACHE_CONTROL, "max-age=3600, must-revalidate"),
                ],
                *body,
            )
                .into_response();
        }
    }
    StatusCode::NOT_FOUND.into_response()
}

pub async fn favicon() -> Response {
    asset(Path("favicon.svg".to_string())).await
}

async fn guard(st: &AppState, headers: &HeaderMap) -> Option<Response> {
    if try_session(st, headers).await.is_none() {
        return Some(Redirect::to("/login").into_response());
    }
    None
}

/// GET / — 总览。
pub async fn index(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(r) = guard(&st, &headers).await {
        return r;
    }
    page(include_str!("../../static/index.html"))
}

/// GET /nodes/{id} — 节点详情(id 由前端 JS 校验解析;页面为静态壳)。
pub async fn node_page(
    State(st): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    let _ = id; // 路由参数仅用于 URL 形态,数据由 API 按会话鉴权返回
    if let Some(r) = guard(&st, &headers).await {
        return r;
    }
    page(include_str!("../../static/node.html"))
}

/// GET /settings
pub async fn settings_page(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(r) = guard(&st, &headers).await {
        return r;
    }
    page(include_str!("../../static/settings.html"))
}

/// GET /alerts
pub async fn alerts_page(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(r) = guard(&st, &headers).await {
        return r;
    }
    page(include_str!("../../static/alerts.html"))
}

/// GET /compare
pub async fn compare_page(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(r) = guard(&st, &headers).await {
        return r;
    }
    page(include_str!("../../static/compare.html"))
}

/// GET /status/{slug} — 公开状态页(仅 slug 匹配时;静态壳,数据由公开 API 拉取)。
pub async fn status_page(State(st): State<AppState>, Path(slug): Path<String>) -> Response {
    if crate::handlers::status::slug_ok(&st, &slug).await {
        page(include_str!("../../static/status.html"))
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

/// GET /login — 已登录则回首页。
pub async fn login_page(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if try_session(&st, &headers).await.is_some() {
        return Redirect::to("/").into_response();
    }
    page(include_str!("../../static/login.html"))
}

/// GET /setup — 仅未初始化时可见,否则 302 登录页(不暴露引导端点)。
pub async fn setup_page(State(st): State<AppState>) -> Response {
    match crate::handlers::auth::setup_done(&st).await {
        Ok(false) => page(include_str!("../../static/setup.html")),
        _ => Redirect::to("/login").into_response(),
    }
}
