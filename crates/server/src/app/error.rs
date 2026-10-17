//! API errors as RFC 9457 problem details. Internals never reach the client.

use axum::{
    Json,
    extract::{
        FromRequest, FromRequestParts,
        rejection::{JsonRejection, PathRejection, QueryRejection},
    },
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use shared::Problem;

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    detail: Option<String>,
}

pub type ApiResult<T> = Result<T, ApiError>;

impl ApiError {
    pub fn new(status: StatusCode, detail: impl Into<String>) -> Self {
        Self { status, detail: Some(detail.into()) }
    }

    pub fn bad_request(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, detail)
    }

    pub fn not_found() -> Self {
        Self { status: StatusCode::NOT_FOUND, detail: None }
    }

    pub fn unauthorized() -> Self {
        Self { status: StatusCode::UNAUTHORIZED, detail: None }
    }

    pub fn forbidden(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::FORBIDDEN, detail)
    }

    pub fn internal() -> Self {
        Self { status: StatusCode::INTERNAL_SERVER_ERROR, detail: None }
    }
}

impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        tracing::error!(error = %err, "database error");
        Self::internal()
    }
}

impl From<JsonRejection> for ApiError {
    fn from(rejection: JsonRejection) -> Self {
        Self::new(rejection.status(), rejection.body_text())
    }
}

impl From<PathRejection> for ApiError {
    fn from(rejection: PathRejection) -> Self {
        Self::new(rejection.status(), rejection.body_text())
    }
}

impl From<QueryRejection> for ApiError {
    fn from(rejection: QueryRejection) -> Self {
        Self::new(rejection.status(), rejection.body_text())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let problem = Problem {
            kind: "about:blank".into(),
            title: self.status.canonical_reason().unwrap_or("Error").into(),
            status: self.status.as_u16(),
            detail: self.detail,
        };
        let mut res = (self.status, Json(problem)).into_response();
        res.headers_mut().insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/problem+json"));
        res
    }
}

/// `axum::Json` with problem+json rejections.
#[derive(FromRequest)]
#[from_request(via(axum::Json), rejection(ApiError))]
pub struct ApiJson<T>(pub T);

impl<T: serde::Serialize> IntoResponse for ApiJson<T> {
    fn into_response(self) -> Response {
        Json(self.0).into_response()
    }
}

#[derive(FromRequestParts)]
#[from_request(via(axum::extract::Path), rejection(ApiError))]
pub struct ApiPath<T>(pub T);

#[derive(FromRequestParts)]
#[from_request(via(axum::extract::Query), rejection(ApiError))]
pub struct ApiQuery<T>(pub T);
