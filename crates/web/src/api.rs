//! Thin fetch wrapper over the panel API.

use serde::{Serialize, de::DeserializeOwned};
use shared::{Endpoint, Login, NewEndpoint, Problem, RequestDetail, RequestSummary, SessionInfo, UpdateEndpoint};
use uuid::Uuid;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{Headers, RequestCredentials, RequestInit, Response};

pub const PAGE_SIZE: u32 = 50;

#[derive(Clone, Debug)]
pub struct ApiError {
    pub status: u16,
    pub message: String,
}

impl ApiError {
    pub fn is_unauthorized(&self) -> bool {
        self.status == 401
    }

    fn network(err: &JsValue) -> Self {
        Self { status: 0, message: err.as_string().unwrap_or_else(|| "network error".into()) }
    }
}

pub type ApiResult<T> = Result<T, ApiError>;

pub async fn session() -> ApiResult<SessionInfo> {
    json(send("GET", "/api/session", None).await?).await
}

pub async fn login(key: String) -> ApiResult<()> {
    send("POST", "/api/login", Some(body(&Login { key })?)).await.map(drop)
}

pub async fn logout() -> ApiResult<()> {
    send("POST", "/api/logout", None).await.map(drop)
}

pub async fn endpoints() -> ApiResult<Vec<Endpoint>> {
    json(send("GET", "/api/endpoints", None).await?).await
}

pub async fn create_endpoint(name: String) -> ApiResult<Endpoint> {
    json(send("POST", "/api/endpoints", Some(body(&NewEndpoint { name })?)).await?).await
}

pub async fn update_endpoint(id: Uuid, update: &UpdateEndpoint) -> ApiResult<Endpoint> {
    json(send("PUT", &format!("/api/endpoints/{id}"), Some(body(update)?)).await?).await
}

pub async fn delete_endpoint(id: Uuid) -> ApiResult<()> {
    send("DELETE", &format!("/api/endpoints/{id}"), None).await.map(drop)
}

pub async fn requests(id: Uuid, before: Option<i64>) -> ApiResult<Vec<RequestSummary>> {
    let cursor = before.map(|b| format!("&before={b}")).unwrap_or_default();
    json(send("GET", &format!("/api/endpoints/{id}/requests?limit={PAGE_SIZE}{cursor}"), None).await?).await
}

pub async fn clear_requests(id: Uuid) -> ApiResult<()> {
    send("DELETE", &format!("/api/endpoints/{id}/requests"), None).await.map(drop)
}

pub async fn request(id: i64) -> ApiResult<RequestDetail> {
    json(send("GET", &format!("/api/requests/{id}"), None).await?).await
}

pub async fn delete_request(id: i64) -> ApiResult<()> {
    send("DELETE", &format!("/api/requests/{id}"), None).await.map(drop)
}

fn body<T: Serialize>(value: &T) -> ApiResult<String> {
    serde_json::to_string(value).map_err(|e| ApiError { status: 0, message: e.to_string() })
}

async fn send(method: &str, url: &str, body: Option<String>) -> ApiResult<Response> {
    let init = RequestInit::new();
    init.set_method(method);
    init.set_credentials(RequestCredentials::SameOrigin);
    if let Some(body) = body {
        let headers = Headers::new().map_err(|e| ApiError::network(&e))?;
        headers.set("content-type", "application/json").map_err(|e| ApiError::network(&e))?;
        init.set_headers(&headers);
        init.set_body(&JsValue::from_str(&body));
    }
    let window = web_sys::window().ok_or_else(|| ApiError::network(&JsValue::NULL))?;
    let res: Response = JsFuture::from(window.fetch_with_str_and_init(url, &init))
        .await
        .and_then(|v| v.dyn_into())
        .map_err(|e| ApiError::network(&e))?;

    if res.ok() {
        return Ok(res);
    }
    let status = res.status();
    let text = text(&res).await.unwrap_or_default();
    let message = serde_json::from_str::<Problem>(&text)
        .map(|p| p.detail.unwrap_or(p.title))
        .unwrap_or_else(|_| format!("HTTP {status}"));
    Err(ApiError { status, message })
}

async fn text(res: &Response) -> ApiResult<String> {
    let promise = res.text().map_err(|e| ApiError::network(&e))?;
    let value = JsFuture::from(promise).await.map_err(|e| ApiError::network(&e))?;
    Ok(value.as_string().unwrap_or_default())
}

async fn json<T: DeserializeOwned>(res: Response) -> ApiResult<T> {
    let raw = text(&res).await?;
    serde_json::from_str(&raw).map_err(|e| ApiError { status: res.status(), message: e.to_string() })
}
