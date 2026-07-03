//! 统一错误类型:对外脱敏(规范 6.1.8),内部细节只进日志。

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("未认证")]
    Unauthorized,
    #[error("禁止访问")]
    Forbidden,
    #[error("不存在")]
    NotFound,
    /// 面向用户的请求错误(内容由我们自己书写,不含内部细节)。
    #[error("{0}")]
    BadRequest(String),
    #[error("请求过于频繁,请稍后再试")]
    TooManyRequests,
    /// 任何内部错误:细节仅入日志,响应固定文案。
    #[error("内部错误")]
    Internal,
}

impl AppError {
    pub fn bad(msg: &str) -> Self {
        Self::BadRequest(msg.to_string())
    }
}

/// sqlx 错误 → 记录日志,对外统一"内部错误"(不泄露 SQL / 路径)。
impl From<sqlx::Error> for AppError {
    fn from(e: sqlx::Error) -> Self {
        tracing::error!(error = %e, "database error");
        AppError::Internal
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (code, msg) = match &self {
            AppError::Unauthorized => (StatusCode::UNAUTHORIZED, self.to_string()),
            AppError::Forbidden => (StatusCode::FORBIDDEN, self.to_string()),
            AppError::NotFound => (StatusCode::NOT_FOUND, self.to_string()),
            AppError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            AppError::TooManyRequests => (StatusCode::TOO_MANY_REQUESTS, self.to_string()),
            AppError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()),
        };
        (code, Json(serde_json::json!({ "error": msg }))).into_response()
    }
}
