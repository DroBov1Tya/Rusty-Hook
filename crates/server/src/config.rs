//! Runtime config from env. Fails fast on bad values.

use std::{env, net::SocketAddr, num::NonZeroU32, path::PathBuf, str::FromStr, time::Duration};

const MIN_ADMIN_KEY_LEN: usize = 16;

#[derive(Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub db: DbConfig,
    /// None = open panel (AUTH_MODE=open), no login.
    pub admin_key: Option<String>,
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
        Ok(Self {
            bind: parse("APP_BIND", "0.0.0.0:8080")?,
            db: DbConfig {
                host: string("PG_HOST", "db"),
                port: parse("PG_PORT", "5432")?,
                user: required("POSTGRES_USER")?,
                password: required("POSTGRES_PASSWORD")?,
                database: required("POSTGRES_DB")?,
                max_connections: parse("PG_MAX_CONNECTIONS", "16")?,
            },
            admin_key: admin_key()?,
            cookie_secure: parse("COOKIE_SECURE", "true")?,
            session_ttl: secs("SESSION_TTL_HOURS", "24", 3600)?,
            public_hosts: string("PUBLIC_HOSTS", "")
                .split(',')
                .map(|h| h.trim().to_ascii_lowercase())
                .filter(|h| !h.is_empty())
                .collect(),
            max_body_bytes: parse("MAX_BODY_BYTES", "1048576")?,
            max_requests_per_endpoint: positive("MAX_REQUESTS_PER_ENDPOINT", "500")?,
            max_endpoints: positive("MAX_ENDPOINTS", "100")?,
            max_connections: parse("MAX_CONNECTIONS", "1024")?,
            hook_concurrency: parse("HOOK_CONCURRENCY", "64")?,
            hook_rate_per_minute: parse("HOOK_RATE_PER_MINUTE", "600")?,
            retention: secs("RETENTION_DAYS", "7", 86_400)?,
            trust_forwarded: parse("TRUST_FORWARDED", "false")?,
            static_dir: string("STATIC_DIR", "/dist").into(),
        })
    }

    pub fn session_cookie_name(&self) -> &'static str {
        // __Host- prefix requires Secure, so plain-http deploys use a bare name.
        if self.cookie_secure { "__Host-rh_session" } else { "rh_session" }
    }
}

/// Key mode is the default; an open panel must be asked for explicitly.
fn admin_key() -> Result<Option<String>, String> {
    let key = env::var("ADMIN_KEY").unwrap_or_default();
    match string("AUTH_MODE", "key").as_str() {
        "open" if key.is_empty() => Ok(None),
        "open" => Err("AUTH_MODE=open but ADMIN_KEY is set; clear one of them".into()),
        "key" if key.len() >= MIN_ADMIN_KEY_LEN => Ok(Some(key)),
        "key" => Err(format!("ADMIN_KEY must be at least {MIN_ADMIN_KEY_LEN} chars (or set AUTH_MODE=open)")),
        other => Err(format!("AUTH_MODE: expected key|open, got {other:?}")),
    }
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
