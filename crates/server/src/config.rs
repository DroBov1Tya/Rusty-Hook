//! Runtime config from env. Fails fast on bad values.

use std::{env, net::SocketAddr, num::NonZeroU32, path::PathBuf, str::FromStr, time::Duration};

const MIN_ADMIN_KEY_LEN: usize = 16;

#[derive(Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub db: DbConfig,
    /// Login required (AUTH_MODE=login). False = open panel.
    pub login_required: bool,
    /// Admin key login; None = disabled.
    pub admin_key: Option<String>,
    /// SSO login; None = disabled.
    pub oidc: Option<OidcConfig>,
    pub cookie_secure: bool,
    pub session_ttl: Duration,
    /// Panel Host allowlist (DNS rebinding). Empty = any host.
    pub public_hosts: Vec<String>,
    pub max_body_bytes: usize,
    pub max_requests_per_endpoint: i64,
    pub max_endpoints: i64,
    pub max_connections: usize,
    pub hook_concurrency: usize,
    pub hook_rate_per_minute: NonZeroU32,
    pub retention: Duration,
    pub trust_forwarded: bool,
    pub static_dir: PathBuf,
}

#[derive(Clone)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    /// Exact callback URL registered at the IdP: https://<host>/api/oidc/callback
    pub redirect_url: String,
    /// Deny by default: a user must match one of these. Emails/domains need email_verified=true.
    pub allowed_emails: Vec<String>,
    pub allowed_domains: Vec<String>,
    /// Matched against the `groups` claim, case-insensitive.
    pub allowed_groups: Vec<String>,
    /// Extra PEM roots for an IdP behind a private CA.
    pub ca_file: Option<PathBuf>,
}

#[derive(Clone)]
pub struct DbConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub database: String,
    pub max_connections: u32,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Self {
            bind: parse("APP_BIND", "0.0.0.0:8080")?,
            db: DbConfig {
                host: string("PG_HOST", "db"),
                port: parse("PG_PORT", "5432")?,
                user: required("POSTGRES_USER")?,
                password: required("POSTGRES_PASSWORD")?,
                database: required("POSTGRES_DB")?,
                max_connections: parse("PG_MAX_CONNECTIONS", "16")?,
            },
            login_required: login_required()?,
            admin_key: admin_key()?,
            oidc: oidc()?,
            cookie_secure: parse("COOKIE_SECURE", "true")?,
            session_ttl: secs("SESSION_TTL_HOURS", "24", 3600)?,
            public_hosts: list("PUBLIC_HOSTS"),
            max_body_bytes: parse("MAX_BODY_BYTES", "1048576")?,
            max_requests_per_endpoint: positive("MAX_REQUESTS_PER_ENDPOINT", "500")?,
            max_endpoints: positive("MAX_ENDPOINTS", "100")?,
            max_connections: parse("MAX_CONNECTIONS", "1024")?,
            hook_concurrency: parse("HOOK_CONCURRENCY", "64")?,
            hook_rate_per_minute: parse("HOOK_RATE_PER_MINUTE", "600")?,
            retention: secs("RETENTION_DAYS", "7", 86_400)?,
            trust_forwarded: parse("TRUST_FORWARDED", "false")?,
            static_dir: string("STATIC_DIR", "/dist").into(),
        }
        .check()
    }

    pub fn session_cookie_name(&self) -> &'static str {
        // __Host- prefix requires Secure, so plain-http deploys use a bare name.
        if self.cookie_secure { "__Host-rh_session" } else { "rh_session" }
    }

    /// Short-lived cookie binding an SSO flow to the browser that started it.
    pub fn flow_cookie_name(&self) -> &'static str {
        if self.cookie_secure { "__Host-rh_oidc" } else { "rh_oidc" }
    }
}

impl Config {
    /// Cross-field checks: login mode needs at least one method, open mode none.
    fn check(self) -> Result<Self, String> {
        let methods = self.admin_key.is_some() || self.oidc.is_some();
        match (self.login_required, methods) {
            (true, false) => {
                Err("AUTH_MODE=login needs ADMIN_KEY and/or OIDC_ISSUER_URL (or set AUTH_MODE=open)".into())
            }
            (false, true) => {
                Err("AUTH_MODE=open but ADMIN_KEY or OIDC_* is set; clear them or use AUTH_MODE=login".into())
            }
            _ => Ok(self),
        }
    }
}

/// Login is the default; an open panel must be asked for explicitly.
fn login_required() -> Result<bool, String> {
    match string("AUTH_MODE", "login").as_str() {
        "login" => Ok(true),
        "open" => Ok(false),
        other => Err(format!("AUTH_MODE: expected login|open, got {other:?}")),
    }
}

fn admin_key() -> Result<Option<String>, String> {
    match env::var("ADMIN_KEY").unwrap_or_default() {
        key if key.is_empty() => Ok(None),
        key if key.len() < MIN_ADMIN_KEY_LEN => Err(format!("ADMIN_KEY must be at least {MIN_ADMIN_KEY_LEN} chars")),
        key => Ok(Some(key)),
    }
}

/// OIDC is on when OIDC_ISSUER_URL is set; then the rest is mandatory.
fn oidc() -> Result<Option<OidcConfig>, String> {
    let issuer = string("OIDC_ISSUER_URL", "");
    if issuer.is_empty() {
        return Ok(None);
    }
    let allow_http: bool = parse("OIDC_ALLOW_HTTP", "false")?;
    let cfg = OidcConfig {
        issuer: secure_url("OIDC_ISSUER_URL", issuer, allow_http)?,
        client_id: required("OIDC_CLIENT_ID")?,
        client_secret: env::var("OIDC_CLIENT_SECRET").ok().filter(|s| !s.is_empty()),
        redirect_url: secure_url("OIDC_REDIRECT_URL", required("OIDC_REDIRECT_URL")?, allow_http)?,
        allowed_emails: list("OIDC_ALLOWED_EMAILS"),
        allowed_domains: list("OIDC_ALLOWED_DOMAINS"),
        allowed_groups: list("OIDC_ALLOWED_GROUPS"),
        ca_file: env::var("OIDC_CA_FILE").ok().filter(|p| !p.is_empty()).map(PathBuf::from),
    };
    if cfg.allowed_emails.is_empty() && cfg.allowed_domains.is_empty() && cfg.allowed_groups.is_empty() {
        return Err("set OIDC_ALLOWED_GROUPS, OIDC_ALLOWED_EMAILS or OIDC_ALLOWED_DOMAINS (deny by default)".into());
    }
    Ok(Some(cfg))
}

/// https only; plain http just for local test IdPs (OIDC_ALLOW_HTTP=true).
fn secure_url(key: &str, url: String, allow_http: bool) -> Result<String, String> {
    match url.split_once("://") {
        Some(("https", _)) => Ok(url),
        Some(("http", _)) if allow_http => Ok(url),
        _ => Err(format!("{key} must be an https:// URL")),
    }
}

/// Comma separated, trimmed, lowercased, empties dropped.
fn list(key: &str) -> Vec<String> {
    string(key, "").split(',').map(|v| v.trim().to_ascii_lowercase()).filter(|v| !v.is_empty()).collect()
}

fn string(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_owned())
}

fn required(key: &str) -> Result<String, String> {
    env::var(key).ok().filter(|v| !v.is_empty()).ok_or_else(|| format!("{key} is required"))
}

fn parse<T: FromStr>(key: &str, default: &str) -> Result<T, String> {
    let raw = string(key, default);
    raw.trim().parse().map_err(|_| format!("{key}: invalid value {raw:?}"))
}

fn positive(key: &str, default: &str) -> Result<i64, String> {
    match parse::<i64>(key, default)? {
        n if n > 0 => Ok(n),
        _ => Err(format!("{key} must be > 0")),
    }
}

fn secs(key: &str, default: &str, unit: u64) -> Result<Duration, String> {
    let n: u64 = parse(key, default)?;
    n.checked_mul(unit).map(Duration::from_secs).ok_or_else(|| format!("{key} is too large"))
}
