//! Captured requests: paged list, detail with body, delete one, clear all of an endpoint.

use axum::{extract::State, http::StatusCode};
use base64::{Engine, engine::general_purpose::STANDARD};
use shared::{Body, MAX_PAGE_SIZE, PageQuery, RequestDetail, RequestSummary};
use sqlx::{FromRow, types::Json};
use uuid::Uuid;

use crate::app::{
    error::{ApiError, ApiJson, ApiPath, ApiQuery, ApiResult},
    state::AppState,
};

const DEFAULT_PAGE_SIZE: u32 = 50;

// Literal fragment so composed queries stay `&'static str` (sqlx rejects dynamic SQL).
macro_rules! summary_cols {
    () => {
        "id, endpoint_id, method, path, query, content_type, ip, size,
       (extract(epoch FROM received_at) * 1000)::int8 AS received_ms"
    };
}

#[derive(FromRow)]
struct SummaryRow {
    id: i64,
    endpoint_id: Uuid,
    method: String,
    path: String,
    query: String,
    content_type: Option<String>,
    ip: Option<String>,
    size: i32,
    received_ms: i64,
}

impl From<SummaryRow> for RequestSummary {
    fn from(r: SummaryRow) -> Self {
        Self {
            id: r.id,
            endpoint_id: r.endpoint_id,
            method: r.method,
            path: r.path,
            query: r.query,
            content_type: r.content_type,
            ip: r.ip,
            size: r.size,
            received_ms: r.received_ms,
        }
    }
}

#[derive(FromRow)]
struct DetailRow {
    #[sqlx(flatten)]
    summary: SummaryRow,
    headers: Json<Vec<(String, String)>>,
    body: Vec<u8>,
}

/// Newest first; `before` is the id cursor for older pages.
pub async fn list(
    State(st): State<AppState>,
    ApiPath(endpoint_id): ApiPath<Uuid>,
    ApiQuery(page): ApiQuery<PageQuery>,
) -> ApiResult<ApiJson<Vec<RequestSummary>>> {
    let limit = page.limit.unwrap_or(DEFAULT_PAGE_SIZE).clamp(1, MAX_PAGE_SIZE);
    let rows: Vec<SummaryRow> = sqlx::query_as(concat!(
        "SELECT ",
        summary_cols!(),
        " FROM requests
         WHERE endpoint_id = $1 AND ($2::int8 IS NULL OR id < $2)
         ORDER BY id DESC LIMIT $3"
    ))
    .bind(endpoint_id)
    .bind(page.before)
    .bind(i64::from(limit))
    .fetch_all(&st.db)
    .await?;
    Ok(ApiJson(rows.into_iter().map(Into::into).collect()))
}

pub async fn clear(State(st): State<AppState>, ApiPath(endpoint_id): ApiPath<Uuid>) -> ApiResult<StatusCode> {
    sqlx::query("DELETE FROM requests WHERE endpoint_id = $1").bind(endpoint_id).execute(&st.db).await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Body as text when it is valid UTF-8, otherwise base64.
pub async fn get(State(st): State<AppState>, ApiPath(id): ApiPath<i64>) -> ApiResult<ApiJson<RequestDetail>> {
    let row: DetailRow =
        sqlx::query_as(concat!("SELECT ", summary_cols!(), ", headers, body FROM requests WHERE id = $1"))
            .bind(id)
            .fetch_optional(&st.db)
            .await?
            .ok_or_else(ApiError::not_found)?;
    let body = match String::from_utf8(row.body) {
        Ok(text) => Body::Text(text),
        Err(err) => Body::Base64(STANDARD.encode(err.as_bytes())),
    };
    Ok(ApiJson(RequestDetail { summary: row.summary.into(), headers: row.headers.0, body }))
}

pub async fn delete(State(st): State<AppState>, ApiPath(id): ApiPath<i64>) -> ApiResult<StatusCode> {
    let done = sqlx::query("DELETE FROM requests WHERE id = $1").bind(id).execute(&st.db).await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}
