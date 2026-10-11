//! Router: panel (static + API) with strict headers, public hooks with sandbox headers.

use std::time::Duration;

use axum::{
    Router,
    extract::{DefaultBodyLimit, State},
    http::{HeaderName, HeaderValue, StatusCode, header},
    middleware,
    routing::{any, get, post, put},
};
use tower::limit::GlobalConcurrencyLimitLayer;
use tower_http::{
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    services::ServeDir,
    set_header::SetResponseHeaderLayer,
    timeout::TimeoutLayer,
    trace::TraceLayer,
};

use crate::{api, auth, hook, oidc, state::AppState};

const API_BODY_LIMIT: usize = 128 * 1024;
const API_TIMEOUT: Duration = Duration::from_secs(15);
// Hook delay is capped at 10s, leave room for DB.
const HOOK_TIMEOUT: Duration = Duration::from_secs(30);

// No inline script/style: everything is served from 'self'.
const PANEL_CSP: &str = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; \
    img-src 'self' data:; font-src 'self'; connect-src 'self'; manifest-src 'self'; \
    base-uri 'none'; form-action 'self'; frame-ancestors 'none'";

pub fn build(st: AppState) -> Router {
    let protected = Router::new()
        .route("/endpoints", get(api::list_endpoints).post(api::create_endpoint))
        .route("/endpoints/{id}", put(api::update_endpoint).delete(api::delete_endpoint))
        .route("/endpoints/{id}/requests", get(api::list_requests).delete(api::clear_requests))
        .route("/requests/{id}", get(api::get_request).delete(api::delete_request))
        .route_layer(middleware::from_fn_with_state(st.clone(), auth::require_session));

    // SSE is long-lived: auth yes, timeout no.
    let stream = Router::new()
        .route("/stream", get(api::stream))
        .route_layer(middleware::from_fn_with_state(st.clone(), auth::require_session));

    let short_lived = Router::new()
        .route("/session", get(auth::session_info))
        .route("/login", post(auth::login))
        .route("/logout", post(auth::logout))
        .route("/oidc/login", get(oidc::start))
        .route("/oidc/callback", get(oidc::callback))
        .merge(protected)
        .layer(TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT, API_TIMEOUT));

    let api = Router::new()
        .merge(short_lived)
        .merge(stream)
        .layer(middleware::from_fn(auth::same_origin_writes))
        .layer(DefaultBodyLimit::max(API_BODY_LIMIT))
        .layer(no_store());

    let static_files = ServeDir::new(&st.cfg.static_dir)
        .precompressed_br()
        .precompressed_gzip()
        .append_index_html_on_directories(true);

    let panel = Router::new()
        .nest("/api", api)
        .fallback_service(static_files)
        // Asset names are not hashed: always revalidate (cheap 304 via Last-Modified).
        .layer(header_layer(header::CACHE_CONTROL, "no-cache"))
        .layer(header_layer(header::CONTENT_SECURITY_POLICY, PANEL_CSP))
        .layer(header_layer(header::X_CONTENT_TYPE_OPTIONS, "nosniff"))
        .layer(header_layer(header::X_FRAME_OPTIONS, "DENY"))
        .layer(header_layer(header::REFERRER_POLICY, "no-referrer"))
        .layer(header_layer(header::STRICT_TRANSPORT_SECURITY, "max-age=31536000; includeSubDomains"))
        .layer(header_layer(HeaderName::from_static("cross-origin-opener-policy"), "same-origin"))
        .layer(header_layer(HeaderName::from_static("permissions-policy"), "camera=(), microphone=(), geolocation=()"))
        .layer(middleware::from_fn_with_state(st.clone(), auth::allowed_host));

    let hooks = Router::new()
        .route("/h/{id}", any(hook::capture))
        .route("/h/{id}/{*rest}", any(hook::capture))
        // Inner to outer: body cap, bounded in-flight hooks (bounds body memory), timeout, per-IP rate.
        .layer(DefaultBodyLimit::max(st.cfg.max_body_bytes))
        .layer(GlobalConcurrencyLimitLayer::new(st.cfg.hook_concurrency))
        .layer(TimeoutLayer::with_status_code(StatusCode::GATEWAY_TIMEOUT, HOOK_TIMEOUT))
        .layer(middleware::from_fn_with_state(st.clone(), hook::rate_limit));

    let request_id = HeaderName::from_static("x-request-id");
    Router::new()
        .route("/healthz", get(healthz))
        .merge(hooks)
        .merge(panel)
        .layer(TraceLayer::new_for_http())
        .layer(PropagateRequestIdLayer::new(request_id.clone()))
        .layer(SetRequestIdLayer::new(request_id, MakeRequestUuid))
        .with_state(st)
}

async fn healthz(State(st): State<AppState>) -> StatusCode {
    match sqlx::query("SELECT 1").execute(&st.db).await {
        Ok(_) => StatusCode::OK,
        Err(_) => StatusCode::SERVICE_UNAVAILABLE,
    }
}

fn header_layer(name: HeaderName, value: &'static str) -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::if_not_present(name, HeaderValue::from_static(value))
}

fn no_store() -> SetResponseHeaderLayer<HeaderValue> {
    SetResponseHeaderLayer::overriding(header::CACHE_CONTROL, HeaderValue::from_static("no-store"))
}
