//! Hook endpoints: list, create, update response spec, delete.

use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use shared::{Endpoint, NewEndpoint, ResponseSpec, UpdateEndpoint, validate_name};
use sqlx::FromRow;
use uuid::Uuid;

use crate::app::{
    error::{ApiError, ApiJson, ApiPath, ApiResult},
    state::AppState,
};

// Literal fragment so composed queries stay `&'static str` (sqlx rejects dynamic SQL).
macro_rules! endpoint_select {
    () => {
        "
SELECT e.id, e.name, e.resp_status, e.resp_content_type, e.resp_body, e.resp_delay_ms,
       (extract(epoch FROM e.created_at) * 1000)::int8 AS created_ms,
       (SELECT count(*) FROM requests r WHERE r.endpoint_id = e.id) AS request_count
FROM endpoints e"
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

pub async fn list(State(st): State<AppState>) -> ApiResult<ApiJson<Vec<Endpoint>>> {
    let rows: Vec<EndpointRow> =
        sqlx::query_as(concat!(endpoint_select!(), " ORDER BY e.created_at DESC")).fetch_all(&st.db).await?;
    Ok(ApiJson(rows.into_iter().map(Into::into).collect()))
}

pub async fn create(State(st): State<AppState>, ApiJson(body): ApiJson<NewEndpoint>) -> ApiResult<Response> {
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
    Ok((StatusCode::CREATED, ApiJson(fetch(&st, id).await?)).into_response())
}

pub async fn update(
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
    Ok(ApiJson(fetch(&st, id).await?))
}

pub async fn delete(State(st): State<AppState>, ApiPath(id): ApiPath<Uuid>) -> ApiResult<StatusCode> {
    let done = sqlx::query("DELETE FROM endpoints WHERE id = $1").bind(id).execute(&st.db).await?;
    if done.rows_affected() == 0 {
        return Err(ApiError::not_found());
    }
    tracing::info!(audit = "endpoint_deleted", %id);
    Ok(StatusCode::NO_CONTENT)
}

async fn fetch(st: &AppState, id: Uuid) -> ApiResult<Endpoint> {
    let row: EndpointRow = sqlx::query_as(concat!(endpoint_select!(), " WHERE e.id = $1"))
        .bind(id)
        .fetch_optional(&st.db)
        .await?
        .ok_or_else(ApiError::not_found)?;
    Ok(row.into())
}
