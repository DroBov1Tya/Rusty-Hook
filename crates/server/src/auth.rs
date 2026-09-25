//! Panel auth: one admin key -> opaque session cookie. Open mode when no key is set.

use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use shared::{Login, SessionInfo};
use subtle::ConstantTimeEq;

use crate::{
    error::{ApiError, ApiJson, ApiResult},
    hook::client_ip,
    state::AppState,
};

const TOKEN_BYTES: usize = 32;
/// Base64url length of TOKEN_BYTES, used to reject junk before hitting the DB.
const TOKEN_LEN: usize = 43;
/// Cookies never stored with captured hooks (panel and oauth2-proxy sessions).
const SECRET_COOKIES: [&str; 2] = ["rh_session", "__Host-rh_session"];
const OAUTH2_PROXY_COOKIE_PREFIX: &str = "_oauth2_proxy";

pub async fn session_info(State(st): State<AppState>, headers: HeaderMap) -> ApiResult<ApiJson<SessionInfo>> {
    Ok(ApiJson(SessionInfo {
        auth_required: st.cfg.admin_key.is_some(),
        authenticated: is_authenticated(&st, &headers).await?,
        max_body_bytes: st.cfg.max_body_bytes,
    }))
}

pub async fn login(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ApiJson(body): ApiJson<Login>,
) -> ApiResult<Response> {
    let Some(admin_key) = &st.cfg.admin_key else {
        return Ok(StatusCode::NO_CONTENT.into_response());
    };
    let ip = client_ip(st.cfg.trust_forwarded, &headers, peer);
    if st.limits.login.check_key(&ip).is_err() {
        tracing::warn!(audit = "login_rate_limited", %ip);
        return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "too many login attempts, retry in a minute"));
    }

    // Hash both sides so the comparison is constant-time and length-independent.
    let given = Sha256::digest(body.key.as_bytes());
    let expected = Sha256::digest(admin_key.as_bytes());
    if !bool::from(given.as_slice().ct_eq(expected.as_slice())) {
        tracing::warn!(audit = "login_failed", %ip);
        return Err(ApiError::unauthorized());
    }

    let token = new_token()?;
    let ttl_secs = i64::try_from(st.cfg.session_ttl.as_secs()).map_err(|_| ApiError::internal())?;
    sqlx::query(
        "INSERT INTO sessions (token_hash, key_fp, expires_at) VALUES ($1, $2, now() + $3 * interval '1 second')",
    )
    .bind(hash_token(&token))
    .bind(key_fingerprint(admin_key))
    .bind(ttl_secs)
    .execute(&st.db)
    .await?;
    tracing::info!(audit = "login_ok", %ip);

    let cookie = session_cookie(&st, &token, ttl_secs);
    Ok((StatusCode::NO_CONTENT, [(header::SET_COOKIE, cookie)]).into_response())
}

pub async fn logout(State(st): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    if let Some(token) = session_token(&st, &headers) {
        sqlx::query("DELETE FROM sessions WHERE token_hash = $1").bind(hash_token(token)).execute(&st.db).await?;
        tracing::info!(audit = "logout");
    }
    let cookie = session_cookie(&st, "", 0);
    Ok((StatusCode::NO_CONTENT, [(header::SET_COOKIE, cookie)]).into_response())
}

/// Middleware: deny API access without a valid session (when a key is configured).
pub async fn require_session(State(st): State<AppState>, req: Request, next: Next) -> Result<Response, ApiError> {
    if is_authenticated(&st, req.headers()).await? { Ok(next.run(req).await) } else { Err(ApiError::unauthorized()) }
}

/// Middleware: CSRF defense via Fetch Metadata on state-changing calls.
pub async fn same_origin_writes(req: Request, next: Next) -> Result<Response, ApiError> {
    let safe = matches!(*req.method(), Method::GET | Method::HEAD | Method::OPTIONS);
    let cross_site =
        req.headers().get("sec-fetch-site").is_some_and(|v| v.as_bytes() != b"same-origin" && v.as_bytes() != b"none");
    if !safe && cross_site {
        return Err(ApiError::forbidden("cross-site request blocked"));
    }
    Ok(next.run(req).await)
}

/// Middleware: panel answers only on allowed Host names (blocks DNS rebinding).
pub async fn allowed_host(State(st): State<AppState>, req: Request, next: Next) -> Result<Response, ApiError> {
    if st.cfg.public_hosts.is_empty() {
        return Ok(next.run(req).await);
    }
    let host = req.headers().get(header::HOST).and_then(|h| h.to_str().ok()).map(strip_port);
    match host {
        Some(h) if st.cfg.public_hosts.iter().any(|allowed| h.eq_ignore_ascii_case(allowed)) => Ok(next.run(req).await),
        _ => Err(ApiError::forbidden("host not allowed")),
    }
}

/// Valid session, or always true in open mode. Keyed to the current ADMIN_KEY,
/// so rotating the key logs everyone out.
pub async fn is_authenticated(st: &AppState, headers: &HeaderMap) -> ApiResult<bool> {
    let Some(admin_key) = &st.cfg.admin_key else {
        return Ok(true);
    };
    let Some(token) = session_token(st, headers) else {
        return Ok(false);
    };
    let found: Option<i32> =
        sqlx::query_scalar("SELECT 1 FROM sessions WHERE token_hash = $1 AND key_fp = $2 AND expires_at > now()")
            .bind(hash_token(token))
            .bind(key_fingerprint(admin_key))
            .fetch_optional(&st.db)
            .await?;
    Ok(found.is_some())
}

/// True for cookies that must not be persisted with captured requests.
pub fn is_secret_cookie(name: &str) -> bool {
    SECRET_COOKIES.contains(&name) || name.starts_with(OAUTH2_PROXY_COOKIE_PREFIX)
}

fn strip_port(host: &str) -> &str {
    match host.strip_prefix('[') {
        Some(v6) => v6.split(']').next().unwrap_or(v6),
        None => host.split(':').next().unwrap_or(host),
    }
}

fn session_token<'a>(st: &AppState, headers: &'a HeaderMap) -> Option<&'a str> {
    let name = st.cfg.session_cookie_name();
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
        .filter(|v| v.len() == TOKEN_LEN)
}

fn new_token() -> ApiResult<String> {
    let mut buf = [0u8; TOKEN_BYTES];
    getrandom::fill(&mut buf).map_err(|err| {
        tracing::error!(error = %err, "rng failure");
        ApiError::internal()
    })?;
    Ok(URL_SAFE_NO_PAD.encode(buf))
}

fn hash_token(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

fn key_fingerprint(admin_key: &str) -> Vec<u8> {
    Sha256::digest(format!("rusty_hook/session-key/{admin_key}").as_bytes())[..8].to_vec()
}

fn session_cookie(st: &AppState, token: &str, max_age: i64) -> HeaderValue {
    let secure = if st.cfg.cookie_secure { "; Secure" } else { "" };
    let name = st.cfg.session_cookie_name();
    let raw = format!("{name}={token}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Strict{secure}");
    // Token is base64url, name is static: always a valid header value.
    HeaderValue::from_str(&raw).unwrap_or_else(|_| HeaderValue::from_static(""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_port_stripping() {
        assert_eq!(strip_port("hooks.example.com:8088"), "hooks.example.com");
        assert_eq!(strip_port("localhost"), "localhost");
        assert_eq!(strip_port("[::1]:8080"), "::1");
    }

    #[test]
    fn secret_cookie_names() {
        assert!(is_secret_cookie("rh_session"));
        assert!(is_secret_cookie("__Host-rh_session"));
        assert!(is_secret_cookie("_oauth2_proxy_csrf"));
        assert!(!is_secret_cookie("session"));
    }
}
