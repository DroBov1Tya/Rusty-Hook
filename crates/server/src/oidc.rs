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
    AdditionalClaims, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields, EndpointMaybeSet,
    EndpointNotSet, EndpointSet, IdTokenFields, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl,
    Scope, StandardErrorResponse, StandardTokenResponse, TokenResponse as _,
    core::{
        CoreAuthDisplay, CoreAuthPrompt, CoreAuthenticationFlow, CoreErrorResponseType, CoreGenderClaim,
        CoreJsonWebKey, CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm, CoreProviderMetadata,
        CoreRevocableToken, CoreRevocationErrorResponse, CoreTokenIntrospectionResponse, CoreTokenType,
    },
};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

use crate::{
    auth::{SameSite, cookie, create_session, oidc_fingerprint, read_cookie},
    config::OidcConfig,
    error::{ApiError, ApiResult},
    hook::client_ip,
    state::AppState,
};

/// Non-standard `groups` claim (Authentik, Keycloak with a groups mapper, ...).
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct GroupsClaim {
    #[serde(default)]
    groups: Vec<String>,
}

impl AdditionalClaims for GroupsClaim {}

type TokenResponse = StandardTokenResponse<
    IdTokenFields<
        GroupsClaim,
        EmptyExtraTokenFields,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
    >,
    CoreTokenType,
>;

/// CoreClient with the groups claim; endpoints as set by discovery.
type Client = openidconnect::Client<
    GroupsClaim,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    TokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

const FLOW_TTL: Duration = Duration::from_secs(600);
/// Pending sign-ins kept in memory; start is rate-limited per IP on top of this.
const MAX_FLOWS: usize = 10_000;
/// Re-discover periodically to pick up IdP key rotation.
const METADATA_TTL: Duration = Duration::from_secs(3600);
/// Forced refresh (unknown signing key) at most this often.
const MIN_REFRESH: Duration = Duration::from_secs(60);
/// After a failed discovery, answer from cache/error instead of hammering the IdP.
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(10);
const MAX_LOGGED_SUB: usize = 128;
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const SCOPES: [&str; 2] = ["email", "profile"];

struct Flow {
    pkce_verifier: String,
    nonce: String,
    created: Instant,
}

#[derive(Default)]
struct Cache {
    client: Option<(Instant, Client)>,
    failed_at: Option<Instant>,
}

pub struct Oidc {
    cfg: OidcConfig,
    http: reqwest::Client,
    cache: tokio::sync::Mutex<Cache>,
    flows: Mutex<HashMap<String, Flow>>,
}

impl Oidc {
    pub fn new(cfg: OidcConfig) -> Result<Self, String> {
        let mut builder = reqwest::Client::builder()
            // No redirects: the IdP endpoints must answer directly (SSRF guard).
            .redirect(reqwest::redirect::Policy::none())
            .timeout(HTTP_TIMEOUT);
        // Self-hosted IdP behind a private CA: trust it in addition to public roots.
        if let Some(path) = &cfg.ca_file {
            let pem = std::fs::read(path).map_err(|e| format!("OIDC_CA_FILE {}: {e}", path.display()))?;
            let certs = reqwest::Certificate::from_pem_bundle(&pem).map_err(|e| format!("OIDC_CA_FILE: {e}"))?;
            if certs.is_empty() {
                return Err("OIDC_CA_FILE has no certificates".into());
            }
            builder = certs.into_iter().fold(builder, reqwest::ClientBuilder::add_root_certificate);
        }
        let http = builder.build().map_err(|e| format!("oidc http client: {e}"))?;
        Ok(Self { cfg, http, cache: tokio::sync::Mutex::default(), flows: Mutex::new(HashMap::new()) })
    }

    /// Fetch provider metadata ahead of the first login.
    pub async fn warm_up(&self) -> Result<(), String> {
        self.client().await.map(drop)
    }

    /// Discovered client, cached for METADATA_TTL. Lazy so an IdP outage never blocks hooks.
    async fn client(&self) -> Result<Client, String> {
        self.load(METADATA_TTL).await
    }

    /// Re-discover now (new JWKS after key rotation), unless refreshed within MIN_REFRESH.
    async fn refreshed(&self) -> Result<Client, String> {
        self.load(MIN_REFRESH).await
    }

    async fn load(&self, max_age: Duration) -> Result<Client, String> {
        let mut cache = self.cache.lock().await;
        let cached = cache.client.as_ref().map(|(at, client)| (at.elapsed(), client.clone()));
        if let Some((age, client)) = &cached
            && *age < max_age
        {
            return Ok(client.clone());
        }
        if cache.failed_at.is_some_and(|t| t.elapsed() < RETRY_AFTER_FAILURE) {
            return cached.map(|(_, c)| c).ok_or_else(|| "discovery failed recently, retrying soon".into());
        }
        match self.discover().await {
            Ok(client) => {
                *cache = Cache { client: Some((Instant::now(), client.clone())), failed_at: None };
                Ok(client)
            }
            Err(err) => {
                cache.failed_at = Some(Instant::now());
                // Stale metadata beats no login while the IdP is briefly unreachable.
                match cached {
                    Some((_, client)) => {
                        tracing::warn!(error = %err, "oidc refresh failed, using cached metadata");
                        Ok(client)
                    }
                    None => Err(err),
                }
            }
        }
    }

    async fn discover(&self) -> Result<Client, String> {
        let issuer = IssuerUrl::new(self.cfg.issuer.clone()).map_err(|e| format!("issuer url: {e}"))?;
        let metadata =
            CoreProviderMetadata::discover_async(issuer, &self.http).await.map_err(|e| format!("discovery: {e}"))?;
        let redirect = RedirectUrl::new(self.cfg.redirect_url.clone()).map_err(|e| format!("redirect url: {e}"))?;
        let client = Client::from_provider_metadata(
            metadata,
            ClientId::new(self.cfg.client_id.clone()),
            self.cfg.client_secret.clone().map(ClientSecret::new),
        )
        .set_redirect_uri(redirect);
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

    /// Groups are admin-managed, so they need no extra proof. Emails count only when the
    /// IdP says they are verified: some IdPs let users edit their own email.
    fn allowed(&self, email: Option<&str>, email_verified: bool, groups: &[String]) -> bool {
        let by_group = groups.iter().any(|g| self.cfg.allowed_groups.iter().any(|a| a.eq_ignore_ascii_case(g)));
        // Exactly one '@': quoted local parts like "a@b"@c are not worth the ambiguity.
        let well_formed = |e: &&str| e.matches('@').count() == 1;
        let by_email = email.filter(|_| email_verified).filter(well_formed).is_some_and(|email| {
            let domain = email.rsplit_once('@').map(|(_, d)| d);
            self.cfg.allowed_emails.iter().any(|e| e == email)
                || domain.is_some_and(|d| self.cfg.allowed_domains.iter().any(|a| a == d))
        });
        by_group || by_email
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
    // Own bucket: flooding SSO start must not lock out key logins from the same IP.
    let ip = client_ip(st.cfg.trust_forwarded, &headers, peer);
    if st.limits.sso_start.check_key(&ip).is_err() {
        return Err(ApiError::new(StatusCode::TOO_MANY_REQUESTS, "too many sign-in attempts, retry in a minute"));
    }
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
            // IdP-controlled: Debug-escaped and capped against log injection.
            let sub: String = subject.chars().take(MAX_LOGGED_SUB).collect();
            tracing::info!(audit = "login_ok", method = "sso", %ip, sub = ?sub);
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
    let nonce = Nonce::new(flow.nonce);
    let claims = match id_token.claims(&client.id_token_verifier(), &nonce) {
        Ok(claims) => claims,
        Err(first) => {
            // Maybe the IdP rotated its signing key: fetch fresh JWKS once, verify the same token.
            let fresh = oidc.refreshed().await?;
            id_token.claims(&fresh.id_token_verifier(), &nonce).map_err(|_| format!("id_token: {first}"))?
        }
    };

    let email = claims.email().map(|e| e.as_str().to_ascii_lowercase());
    let verified = claims.email_verified() == Some(true);
    if !oidc.allowed(email.as_deref(), verified, &claims.additional_claims().groups) {
        let why = if email.is_some() && !verified { "no allowed group and email not verified" } else { "not allowed" };
        return Err(format!("account {why}"));
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

    fn oidc(emails: &[&str], domains: &[&str], groups: &[&str]) -> Option<Oidc> {
        let own = |v: &[&str]| v.iter().map(|s| (*s).to_owned()).collect();
        Oidc::new(OidcConfig {
            issuer: "https://idp.example.com".into(),
            client_id: "c".into(),
            client_secret: None,
            redirect_url: "https://h.example.com/api/oidc/callback".into(),
            allowed_emails: own(emails),
            allowed_domains: own(domains),
            allowed_groups: own(groups),
            ca_file: None,
        })
        .ok()
    }

    #[test]
    fn email_allowlist_is_exact_and_needs_verification() {
        let o = oidc(&["boss@other.org"], &["example.com"], &[]);
        let ok = |e: &str, verified| o.as_ref().is_some_and(|o| o.allowed(Some(e), verified, &[]));
        assert!(ok("alice@example.com", true));
        assert!(ok("boss@other.org", true));
        assert!(!ok("alice@example.com", false), "unverified email must not count");
        assert!(!ok("eve@evil.example.com", true), "subdomain must not match");
        assert!(!ok("eve@example.com.evil.io", true));
        assert!(!ok("x@other.org", true));
        assert!(!ok("no-at-sign", true));
        assert!(!ok("\"a@evil.com\"@example.com", true), "ambiguous address");
    }

    #[tokio::test]
    async fn failed_discovery_is_not_retried_immediately() {
        let Some(mut o) = oidc(&[], &["example.com"], &[]) else { unreachable!("http client builds") };
        // Nothing listens on port 9: fails fast without real network.
        o.cfg.issuer = "http://127.0.0.1:9/".into();
        assert!(o.client().await.is_err_and(|e| e.starts_with("discovery")));
        assert!(o.client().await.is_err_and(|e| e.contains("retrying soon")), "second call must not hit the IdP");
    }

    /// In-process IdP serving discovery; counts how often it is asked.
    async fn fake_idp() -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>, tokio::task::JoinHandle<()>) {
        use std::sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap_or_else(|e| unreachable!("{e}"));
        let base = format!("http://{}", listener.local_addr().unwrap_or_else(|e| unreachable!("{e}")));
        let hits = Arc::new(AtomicUsize::new(0));
        let doc = serde_json::json!({
            "issuer": base,
            "authorization_endpoint": format!("{base}/authorize"),
            "token_endpoint": format!("{base}/token"),
            "jwks_uri": format!("{base}/jwks"),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        });
        let counter = Arc::clone(&hits);
        let app = axum::Router::new()
            .route(
                "/.well-known/openid-configuration",
                axum::routing::get(move || {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let doc = doc.clone();
                    async move { axum::Json(doc) }
                }),
            )
            .route("/jwks", axum::routing::get(|| async { axum::Json(serde_json::json!({ "keys": [] })) }));
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        (base, hits, server)
    }

    #[tokio::test]
    async fn metadata_cache_refresh_and_stale_fallback() {
        use std::sync::atomic::Ordering;
        let (base, hits, server) = fake_idp().await;
        let Some(mut o) = oidc(&[], &["example.com"], &[]) else { unreachable!("http client builds") };
        o.cfg.issuer = base;

        assert!(o.client().await.is_ok());
        assert!(o.client().await.is_ok());
        assert_eq!(hits.load(Ordering::SeqCst), 1, "fresh cache must not re-discover");

        // Forced refresh (what an unknown signing key triggers) fetches again.
        assert!(o.load(Duration::ZERO).await.is_ok());
        assert_eq!(hits.load(Ordering::SeqCst), 2);

        // IdP gone: stale metadata keeps logins working, and failures are not retried at once.
        server.abort();
        let _ = server.await;
        assert!(o.load(Duration::ZERO).await.is_ok(), "stale client expected");
        assert!(o.load(Duration::ZERO).await.is_ok());
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn group_allowlist() {
        let o = oidc(&[], &[], &["rusty-hook-users"]);
        let ok = |groups: &[&str]| {
            let groups: Vec<String> = groups.iter().map(|g| (*g).to_owned()).collect();
            o.as_ref().is_some_and(|o| o.allowed(None, false, &groups))
        };
        assert!(ok(&["staff", "Rusty-Hook-Users"]));
        assert!(!ok(&["staff"]));
        assert!(!ok(&[]));
    }

    #[test]
    fn flows_are_single_use() {
        let Some(o) = oidc(&[], &["example.com"], &[]) else { unreachable!("http client builds") };
        let flow = || Flow { pkce_verifier: "v".into(), nonce: "n".into(), created: Instant::now() };
        assert!(o.put_flow("s1".into(), flow()));
        assert!(o.take_flow("s1").is_some());
        assert!(o.take_flow("s1").is_none());
        assert!(o.take_flow("nope").is_none());
    }
}
