//! Panel auth: admin key and/or OIDC SSO -> opaque session cookie. Open mode: no login.

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
    config::Config,
    error::{ApiError, ApiJson, ApiResult},
    hook::client_ip,
    state::AppState,
};

const TOKEN_BYTES: usize = 32;
/// Base64url length of TOKEN_BYTES, used to reject junk before hitting the DB.
const TOKEN_LEN: usize = 43;
/// Cookies never stored with captured hooks: our session, SSO flow, auth proxies in front.
const SECRET_COOKIES: [&str; 4] = ["rh_session", "__Host-rh_session", "rh_oidc", "__Host-rh_oidc"];
const OAUTH2_PROXY_COOKIE_PREFIX: &str = "_oauth2_proxy";

#[derive(Clone, Copy)]
pub enum SameSite {
    Strict,
    /// Needed for cookies read on the cross-site IdP -> callback redirect.
    Lax,
}

pub async fn session_info(State(st): State<AppState>, headers: HeaderMap) -> ApiResult<ApiJson<SessionInfo>> {
    Ok(ApiJson(SessionInfo {
        auth_required: st.cfg.login_required,
        authenticated: is_authenticated(&st, &headers).await?,
        key_login: st.cfg.admin_key.is_some(),
        sso_login: st.cfg.oidc.is_some(),
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
        return Err(ApiError::not_found());
    };
    let ip = client_ip(st.cfg.trust_forwarded, &headers, peer);
    check_login_rate(&st, ip)?;

    // Hash both sides so the comparison is constant-time and length-independent.
    let given = Sha256::digest(body.key.as_bytes());
    let expected = Sha256::digest(admin_key.as_bytes());
    if !bool::from(given.as_slice().ct_eq(expected.as_slice())) {
        tracing::warn!(audit = "login_failed", %ip);
        return Err(ApiError::unauthorized());
    }

    let cookie = create_session(&st, key_fingerprint(admin_key)).await?;
    tracing::info!(audit = "login_ok", method = "key", %ip);
    Ok((StatusCode::NO_CONTENT, [(header::SET_COOKIE, cookie)]).into_response())
}

/// Per-IP limit for key logins.
fn check_login_rate(st: &AppState, ip: std::net::IpAddr) -> ApiResult<()> {
    if st.limits.login.check_key(&ip).is_err() {
        tracing::warn!(audit = "login_rate_limited", %ip);
        return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "too many login attempts, retry in a minute"));
    }
    Ok(())
}

/// New session bound to the login method fingerprint; returns its Set-Cookie value.
pub async fn create_session(st: &AppState, method_fp: Vec<u8>) -> ApiResult<HeaderValue> {
    let token = new_token()?;
    let ttl_secs = i64::try_from(st.cfg.session_ttl.as_secs()).map_err(|_| ApiError::internal())?;
    sqlx::query(
        "INSERT INTO sessions (token_hash, key_fp, expires_at) VALUES ($1, $2, now() + $3 * interval '1 second')",
    )
    .bind(hash_token(&token))
    .bind(method_fp)
    .bind(ttl_secs)
    .execute(&st.db)
    .await?;
    Ok(cookie(&st.cfg, st.cfg.session_cookie_name(), &token, ttl_secs, SameSite::Strict))
}

pub async fn logout(State(st): State<AppState>, headers: HeaderMap) -> ApiResult<Response> {
    if let Some(token) = session_token(&st, &headers) {
        sqlx::query("DELETE FROM sessions WHERE token_hash = $1").bind(hash_token(token)).execute(&st.db).await?;
        tracing::info!(audit = "logout");
    }
    let cookie = cookie(&st.cfg, st.cfg.session_cookie_name(), "", 0, SameSite::Strict);
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

/// Valid session, or always true in open mode. Sessions are bound to the login method
/// that issued them: rotating ADMIN_KEY or switching IdP/client logs those users out.
pub async fn is_authenticated(st: &AppState, headers: &HeaderMap) -> ApiResult<bool> {
    if !st.cfg.login_required {
        return Ok(true);
    }
    let Some(token) = session_token(st, headers) else {
        return Ok(false);
    };
    let found: Option<i32> =
        sqlx::query_scalar("SELECT 1 FROM sessions WHERE token_hash = $1 AND key_fp = ANY($2) AND expires_at > now()")
            .bind(hash_token(token))
            .bind(active_fingerprints(&st.cfg))
            .fetch_optional(&st.db)
            .await?;
    Ok(found.is_some())
}

/// Fingerprint of the SSO setup (issuer + client): sessions die if either changes.
pub fn oidc_fingerprint(issuer: &str, client_id: &str) -> Vec<u8> {
    fingerprint(&format!("oidc/{issuer}\n{client_id}"))
}

fn key_fingerprint(admin_key: &str) -> Vec<u8> {
    fingerprint(&format!("key/{admin_key}"))
}

fn fingerprint(input: &str) -> Vec<u8> {
    Sha256::digest(format!("rusty_hook/session/{input}").as_bytes())[..8].to_vec()
}

fn active_fingerprints(cfg: &Config) -> Vec<Vec<u8>> {
    let key = cfg.admin_key.as_deref().map(key_fingerprint);
    let sso = cfg.oidc.as_ref().map(|o| oidc_fingerprint(&o.issuer, &o.client_id));
    key.into_iter().chain(sso).collect()
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
    read_cookie(headers, st.cfg.session_cookie_name()).filter(|v| v.len() == TOKEN_LEN)
}

pub fn read_cookie<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(k, _)| *k == name)
        .map(|(_, v)| v)
}

/// 256-bit random, base64url.
pub fn new_token() -> ApiResult<String> {
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

/// HttpOnly cookie on Path=/. Name and value are ASCII token chars by construction.
pub fn cookie(cfg: &Config, name: &str, value: &str, max_age: i64, same_site: SameSite) -> HeaderValue {
    let secure = if cfg.cookie_secure { "; Secure" } else { "" };
    let same_site = match same_site {
        SameSite::Strict => "Strict",
        SameSite::Lax => "Lax",
    };
    let raw = format!("{name}={value}; Path=/; Max-Age={max_age}; HttpOnly; SameSite={same_site}{secure}");
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
