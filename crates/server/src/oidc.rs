//! SSO via any external OIDC provider: authorization code + PKCE + nonce.
//! The IdP is not part of this stack; it plugs in through OIDC_* env.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Mutex, PoisonError},
    time::{Duration, Instant},
};

use axum::{
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl,
    Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
};
use serde::Deserialize;
use subtle::ConstantTimeEq;

use crate::{
    auth::{SameSite, check_login_rate, cookie, create_session, oidc_fingerprint, read_cookie},
    config::OidcConfig,
    error::{ApiError, ApiResult},
    hook::client_ip,
    state::AppState,
};

type Client =
    CoreClient<EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointMaybeSet, EndpointMaybeSet>;

const FLOW_TTL: Duration = Duration::from_secs(600);
/// Pending sign-ins kept in memory; start is rate-limited per IP on top of this.
const MAX_FLOWS: usize = 10_000;
/// Re-discover periodically to pick up IdP key rotation.
const METADATA_TTL: Duration = Duration::from_secs(3600);
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const SCOPES: [&str; 2] = ["email", "profile"];

struct Flow {
    pkce_verifier: String,
    nonce: String,
    created: Instant,
}

pub struct Oidc {
    cfg: OidcConfig,
    http: reqwest::Client,
    client: tokio::sync::Mutex<Option<(Instant, Client)>>,
    flows: Mutex<HashMap<String, Flow>>,
}

impl Oidc {
    pub fn new(cfg: OidcConfig) -> Result<Self, String> {
        let http = reqwest::Client::builder()
            // No redirects: the IdP endpoints must answer directly (SSRF guard).
            .redirect(reqwest::redirect::Policy::none())
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(|e| format!("oidc http client: {e}"))?;
        Ok(Self { cfg, http, client: tokio::sync::Mutex::new(None), flows: Mutex::new(HashMap::new()) })
    }

    /// Discovered client, cached for METADATA_TTL. Lazy so an IdP outage never blocks hooks.
    pub async fn client(&self) -> Result<Client, String> {
        let mut cached = self.client.lock().await;
        if let Some((at, client)) = cached.as_ref()
            && at.elapsed() < METADATA_TTL
        {
            return Ok(client.clone());
        }
        let issuer = IssuerUrl::new(self.cfg.issuer.clone()).map_err(|e| format!("issuer url: {e}"))?;
        let metadata =
            CoreProviderMetadata::discover_async(issuer, &self.http).await.map_err(|e| format!("discovery: {e}"))?;
        let redirect = RedirectUrl::new(self.cfg.redirect_url.clone()).map_err(|e| format!("redirect url: {e}"))?;
        let client = CoreClient::from_provider_metadata(
            metadata,
            ClientId::new(self.cfg.client_id.clone()),
            self.cfg.client_secret.clone().map(ClientSecret::new),
        )
        .set_redirect_uri(redirect);
        *cached = Some((Instant::now(), client.clone()));
        Ok(client)
    }

    fn put_flow(&self, state: String, flow: Flow) -> bool {
        let mut flows = self.flows.lock().unwrap_or_else(PoisonError::into_inner);
        flows.retain(|_, f| f.created.elapsed() < FLOW_TTL);
        if flows.len() >= MAX_FLOWS {
            return false;
        }
        flows.insert(state, flow);
        true
    }

    /// Single use: a state can be redeemed once.
    fn take_flow(&self, state: &str) -> Option<Flow> {
        let mut flows = self.flows.lock().unwrap_or_else(PoisonError::into_inner);
        flows.remove(state).filter(|f| f.created.elapsed() < FLOW_TTL)
    }

    fn allowed(&self, email: &str) -> bool {
        let domain = email.rsplit_once('@').map(|(_, d)| d);
        self.cfg.allowed_emails.iter().any(|e| e == email)
            || domain.is_some_and(|d| self.cfg.allowed_domains.iter().any(|a| a == d))
    }
}

/// GET /api/oidc/login: redirect to the IdP, bind the flow to this browser via cookie.
pub async fn start(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let Some(oidc) = st.oidc.as_ref() else {
        return Err(ApiError::not_found());
    };
    check_login_rate(&st, client_ip(st.cfg.trust_forwarded, &headers, peer))?;
    let client = oidc.client().await.map_err(|err| {
        tracing::warn!(error = %err, "oidc provider unavailable");
        ApiError::new(StatusCode::BAD_GATEWAY, "identity provider unavailable")
    })?;

    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (url, state, nonce) = client
        .authorize_url(CoreAuthenticationFlow::AuthorizationCode, CsrfToken::new_random, Nonce::new_random)
        .add_scopes(SCOPES.iter().map(|s| Scope::new((*s).to_owned())))
        .set_pkce_challenge(challenge)
        .url();
    let flow =
        Flow { pkce_verifier: verifier.secret().clone(), nonce: nonce.secret().clone(), created: Instant::now() };
    if !oidc.put_flow(state.secret().clone(), flow) {
        return Err(ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "too many pending sign-ins"));
    }

    let location = HeaderValue::from_str(url.as_str()).map_err(|_| ApiError::internal())?;
    let flow_cookie = cookie(&st.cfg, st.cfg.flow_cookie_name(), state.secret(), ttl_secs(FLOW_TTL), SameSite::Lax);
    Ok((StatusCode::SEE_OTHER, [(header::LOCATION, location), (header::SET_COOKIE, flow_cookie)]).into_response())
}

/// IdP redirect parameters. Unknown fields allowed: IdPs add their own (session_state, ...).
#[derive(Deserialize)]
pub struct Callback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    /// RFC 9207 issuer identification.
    iss: Option<String>,
}

/// GET /api/oidc/callback: verify everything, open a session, go back to the panel.
pub async fn callback(
    State(st): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(params): Query<Callback>,
) -> Response {
    let ip = client_ip(st.cfg.trust_forwarded, &headers, peer);
    let (target, session) = match finish(&st, &headers, params).await {
        Ok((subject, session)) => {
            tracing::info!(audit = "login_ok", method = "sso", %ip, sub = %subject);
            ("/", Some(session))
        }
        Err(reason) => {
            tracing::warn!(audit = "sso_failed", %ip, reason = %reason);
            ("/?sso_error=1", None)
        }
    };

    let mut res = StatusCode::SEE_OTHER.into_response();
    let h = res.headers_mut();
    h.insert(header::LOCATION, HeaderValue::from_static(target));
    h.append(header::SET_COOKIE, cookie(&st.cfg, st.cfg.flow_cookie_name(), "", 0, SameSite::Lax));
    if let Some(session) = session {
        h.append(header::SET_COOKIE, session);
    }
    res
}

/// Returns (subject, session cookie). Errors are short reasons for the audit log.
async fn finish(st: &AppState, headers: &HeaderMap, params: Callback) -> Result<(String, HeaderValue), String> {
    let oidc = st.oidc.as_ref().ok_or("sso disabled")?;
    if let Some(err) = params.error {
        // IdP-provided text: Debug-escape and cap before logging.
        return Err(format!("idp error {:?}", err.chars().take(64).collect::<String>()));
    }

    // Login CSRF guard: state must come back to the same browser that started the flow.
    let state = params.state.ok_or("missing state")?;
    let bound = read_cookie(headers, st.cfg.flow_cookie_name()).ok_or("missing flow cookie")?;
    if !bool::from(state.as_bytes().ct_eq(bound.as_bytes())) {
        return Err("state mismatch".into());
    }
    let flow = oidc.take_flow(&state).ok_or("unknown or expired state")?;
    if let Some(iss) = params.iss
        && iss.trim_end_matches('/') != oidc.cfg.issuer.trim_end_matches('/')
    {
        return Err("issuer mismatch".into());
    }
    let code = params.code.ok_or("missing code")?;

    let client = oidc.client().await?;
    let token = client
        .exchange_code(AuthorizationCode::new(code))
        .map_err(|e| format!("token endpoint: {e}"))?
        .set_pkce_verifier(PkceCodeVerifier::new(flow.pkce_verifier))
        .request_async(&oidc.http)
        .await
        .map_err(|e| format!("token exchange: {e}"))?;

    // Signature, iss, aud, exp and nonce are checked by the library.
    let id_token = token.id_token().ok_or("no id_token")?;
    let claims =
        id_token.claims(&client.id_token_verifier(), &Nonce::new(flow.nonce)).map_err(|e| format!("id_token: {e}"))?;

    let email = claims.email().map(|e| e.as_str().to_ascii_lowercase()).ok_or("no email claim")?;
    if claims.email_verified() == Some(false) {
        return Err("email not verified".into());
    }
    if !oidc.allowed(&email) {
        return Err("account not in allowlist".into());
    }

    let session = create_session(st, oidc_fingerprint(&oidc.cfg.issuer, &oidc.cfg.client_id))
        .await
        .map_err(|_| "session store failed")?;
    Ok((claims.subject().as_str().to_owned(), session))
}

fn ttl_secs(d: Duration) -> i64 {
    i64::try_from(d.as_secs()).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn oidc(emails: &[&str], domains: &[&str]) -> Option<Oidc> {
        Oidc::new(OidcConfig {
            issuer: "https://idp.example.com".into(),
            client_id: "c".into(),
            client_secret: None,
            redirect_url: "https://h.example.com/api/oidc/callback".into(),
            allowed_emails: emails.iter().map(|s| (*s).to_owned()).collect(),
            allowed_domains: domains.iter().map(|s| (*s).to_owned()).collect(),
        })
        .ok()
    }

    #[test]
    fn allowlist_is_exact() {
        let o = oidc(&["boss@other.org"], &["example.com"]);
        let ok = |e: &str| o.as_ref().is_some_and(|o| o.allowed(e));
        assert!(ok("alice@example.com"));
        assert!(ok("boss@other.org"));
        assert!(!ok("eve@evil.example.com"), "subdomain must not match");
        assert!(!ok("eve@example.com.evil.io"));
        assert!(!ok("x@other.org"));
        assert!(!ok("no-at-sign"));
    }

    #[test]
    fn flows_are_single_use() {
        let Some(o) = oidc(&[], &["example.com"]) else { unreachable!("http client builds") };
        let flow = || Flow { pkce_verifier: "v".into(), nonce: "n".into(), created: Instant::now() };
        assert!(o.put_flow("s1".into(), flow()));
        assert!(o.take_flow("s1").is_some());
        assert!(o.take_flow("s1").is_none());
        assert!(o.take_flow("nope").is_none());
    }
}
