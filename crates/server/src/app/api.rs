//! Panel JSON API: endpoints, captured requests, live stream.

use std::{convert::Infallible, time::Duration};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::{Stream, StreamExt};
use shared::{
    Body, EVENT_HIT, EVENT_RESYNC, Endpoint, MAX_PAGE_SIZE, NewEndpoint, PageQuery, RequestDetail, RequestSummary,
    ResponseSpec, UpdateEndpoint, validate_name,
};
use sqlx::{FromRow, types::Json};
use tokio_stream::wrappers::BroadcastStream;
use uuid::Uuid;

use crate::app::{
    auth,
    error::{ApiError, ApiJson, ApiPath, ApiQuery, ApiResult},
    state::AppState,
};

const DEFAULT_PAGE_SIZE: u32 = 50;
const SESSION_RECHECK: Duration = Duration::from_secs(30);

// Literal fragments so composed queries stay `&'static str` (sqlx rejects dynamic SQL).
macro_rules! endpoint_select {
    () => {
        "
SELECT e.id, e.name, e.resp_status, e.resp_content_type, e.resp_body, e.resp_delay_ms,
       (extract(epoch FROM e.created_at) * 1000)::int8 AS created_ms,
       (SELECT count(*) FROM requests r WHERE r.endpoint_id = e.id) AS request_count
FROM endpoints e"
    };
}

macro_rules! summary_cols {
    () => {
        "id, endpoint_id, method, path, query, content_type, ip, size,
       (extract(epoch FROM received_at) * 1000)::int8 AS received_ms"
    };
}

#[derive(FromRow)]
struct EndpointRow {
    id: Uuid,
    name: String,
    resp_status: i16,
    resp_content_type: String,
    resp_body: String,
    resp_delay_ms: i32,
    created_ms: i64,
    request_count: i64,
}

impl From<EndpointRow> for Endpoint {
    fn from(r: EndpointRow) -> Self {
        Self {
            id: r.id,
            name: r.name,
            response: ResponseSpec {
                // DB CHECKs guarantee the ranges.
                status: r.resp_status.unsigned_abs(),
                content_type: r.resp_content_type,
                body: r.resp_body,
                delay_ms: r.resp_delay_ms.unsigned_abs(),
            },
            created_ms: r.created_ms,
            request_count: r.request_count,
        }
    }
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

pub async fn list_endpoints(State(st): State<AppState>) -> ApiResult<ApiJson<Vec<Endpoint>>> {
    let rows: Vec<EndpointRow> =
        sqlx::query_as(concat!(endpoint_select!(), " ORDER BY e.created_at DESC")).fetch_all(&st.db).await?;
    Ok(ApiJson(rows.into_iter().map(Into::into).collect()))
}

pub async fn create_endpoint(State(st): State<AppState>, ApiJson(body): ApiJson<NewEndpoint>) -> ApiResult<Response> {
    validate_name(&body.name).map_err(ApiError::bad_request)?;
    // Cap check and insert in one statement.
    let created: Option<Uuid> = sqlx::query_scalar(
        "INSERT INTO endpoints (id, name) SELECT $1, $2
         WHERE (SELECT count(*) FROM endpoints) < $3 RETURNING id",
    )
    .bind(Uuid::new_v4())
    .bind(body.name.trim())
    .bind(st.cfg.max_endpoints)
    .fetch_optional(&st.db)
    .await?;

    let id = created.ok_or_else(|| ApiError::new(StatusCode::CONFLICT, "endpoint limit reached"))?;
    tracing::info!(audit = "endpoint_created", %id);
    Ok((StatusCode::CREATED, ApiJson(fetch_endpoint(&st, id).await?)).into_response())
}

pub async fn update_endpoint(
    State(st): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
    ApiJson(body): ApiJson<UpdateEndpoint>,
) -> ApiResult<ApiJson<Endpoint>> {
    body.validate().map_err(ApiError::bad_request)?;
    let spec = &body.response;
    let done = sqlx::query(
        "UPDATE endpoints SET name = $2, resp_status = $3, resp_content_type = $4,
                resp_body = $5, resp_delay_ms = $6
         WHERE id = $1",
    )
    .bind(id)
    .bind(body.name.trim())
    .bind(i16::try_from(spec.status).map_err(|_| ApiError::bad_request("bad status"))?)
    .bind(&spec.content_type)
    .bind(&spec.body)
    .bind(i32::try_from(spec.delay_ms).map_err(|_| ApiError::bad_request("bad delay"))?)
    .execute(&st.db)
    .await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::not_found());
    }
    Ok(ApiJson(fetch_endpoint(&st, id).await?))
}

pub async fn delete_endpoint(State(st): State<AppState>, ApiPath(id): ApiPath<Uuid>) -> ApiResult<StatusCode> {
    let done = sqlx::query("DELETE FROM endpoints WHERE id = $1").bind(id).execute(&st.db).await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::not_found());
    }
    tracing::info!(audit = "endpoint_deleted", %id);
    Ok(StatusCode::NO_CONTENT)
}

pub async fn list_requests(
    State(st): State<AppState>,
    ApiPath(id): ApiPath<Uuid>,
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
    .bind(id)
    .bind(page.before)
    .bind(i64::from(limit))
    .fetch_all(&st.db)
    .await?;
    Ok(ApiJson(rows.into_iter().map(Into::into).collect()))
}

pub async fn clear_requests(State(st): State<AppState>, ApiPath(id): ApiPath<Uuid>) -> ApiResult<StatusCode> {
    sqlx::query("DELETE FROM requests WHERE endpoint_id = $1").bind(id).execute(&st.db).await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn get_request(State(st): State<AppState>, ApiPath(id): ApiPath<i64>) -> ApiResult<ApiJson<RequestDetail>> {
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

pub async fn delete_request(State(st): State<AppState>, ApiPath(id): ApiPath<i64>) -> ApiResult<StatusCode> {
    let done = sqlx::query("DELETE FROM requests WHERE id = $1").bind(id).execute(&st.db).await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::not_found());
    }
    Ok(StatusCode::NO_CONTENT)
}

/// SSE: every captured request across all endpoints. Lag -> "resync" so the UI refetches.
/// Ends on shutdown or once the session is gone (logout, expiry, key rotation).
pub async fn stream(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mut shutdown = st.shutdown.clone();
    let session_gone = {
        let st = st.clone();
        async move {
            loop {
                tokio::time::sleep(SESSION_RECHECK).await;
                if !matches!(auth::is_authenticated(&st, &headers).await, Ok(true)) {
                    break;
                }
            }
        }
    };
    let events = BroadcastStream::new(st.hub.subscribe())
        .map(|msg| {
            let event = msg
                .ok()
                .and_then(|summary| Event::default().event(EVENT_HIT).json_data(summary).ok())
                .unwrap_or_else(|| Event::default().event(EVENT_RESYNC).data("lag"));
            Ok(event)
        })
        .take_until(async move {
            tokio::select! {
                _ = shutdown.wait_for(|stop| *stop) => {},
                () = session_gone => {},
            }
        });
    Sse::new(events).keep_alive(KeepAlive::new().interval(Duration::from_secs(15)))
}

async fn fetch_endpoint(st: &AppState, id: Uuid) -> ApiResult<Endpoint> {
    let row: EndpointRow = sqlx::query_as(concat!(endpoint_select!(), " WHERE e.id = $1"))
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or_else(ApiError::not_found)?;
    Ok(row.into())
}
