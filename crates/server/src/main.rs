//! rusty_hook: self-hosted webhook inspector.

mod api;
mod auth;
mod config;
mod error;
mod health;
mod hook;
mod limits;
mod routes;
mod serve;
mod state;

use std::{process::ExitCode, time::Duration};

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use tokio::sync::watch;
use tracing_subscriber::EnvFilter;

use crate::{config::Config, state::AppState};

// musl's allocator is slow under concurrency.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

const CLEANUP_EVERY: Duration = Duration::from_secs(60);

fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        return health::probe();
    }
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("runtime: {err}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(run()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!("fatal: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with_target(false)
        // Plain text in docker logs, colors only on a real terminal.
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stdout()))
        .init();

    let cfg = Config::from_env()?;
    let db = connect(&cfg, "rusty_hook_panel").await?;
    let hook_db = connect(&cfg, "rusty_hook_hooks").await?;
    let (stop_tx, stop_rx) = watch::channel(false);
    let st = AppState::new(db, hook_db, cfg, stop_rx);
    if st.cfg.admin_key.is_none() {
        tracing::warn!("AUTH_MODE=open: anyone who reaches this port can use the panel");
        if st.cfg.public_hosts.is_empty() {
            tracing::warn!("PUBLIC_HOSTS is empty: open panel is exposed to DNS rebinding");
        }
    }

    tokio::spawn(cleanup_loop(st.clone()));

    let bind = st.cfg.bind;
    let listener = tokio::net::TcpListener::bind(bind).await.map_err(|e| format!("bind {bind}: {e}"))?;
    tracing::info!(
        %bind,
        auth = if st.cfg.admin_key.is_some() { "admin_key" } else { "open" },
        "listening"
    );

    let max_connections = st.cfg.max_connections;
    let app = routes::build(st);
    serve::run(listener, app, max_connections, async move {
        shutdown_signal().await;
        let _ = stop_tx.send(true);
    })
    .await;
    Ok(())
}

async fn connect(cfg: &Config, name: &str) -> Result<sqlx::PgPool, String> {
    let opts = PgConnectOptions::new()
        .host(&cfg.db.host)
        .port(cfg.db.port)
        .username(&cfg.db.user)
        .password(&cfg.db.password)
        .database(&cfg.db.database)
        .application_name(name);
    PgPoolOptions::new()
        .max_connections(cfg.db.max_connections)
        .acquire_timeout(Duration::from_secs(5))
        .connect_with(opts)
        .await
        .map_err(|e| format!("database: {e}"))
}

/// Drops requests past retention, expired sessions and idle rate-limit keys.
async fn cleanup_loop(st: AppState) {
    let retention_secs = i64::try_from(st.cfg.retention.as_secs()).unwrap_or(i64::MAX);
    let mut tick = tokio::time::interval(CLEANUP_EVERY);
    loop {
        tick.tick().await;
        st.limits.prune();
        let old = sqlx::query("DELETE FROM requests WHERE received_at < now() - $1 * interval '1 second'")
            .bind(retention_secs)
            .execute(&st.db)
            .await;
        let sessions = sqlx::query("DELETE FROM sessions WHERE expires_at < now()").execute(&st.db).await;
        match (old, sessions) {
            (Ok(r), Ok(s)) => {
                if r.rows_affected() + s.rows_affected() > 0 {
                    tracing::info!(requests = r.rows_affected(), sessions = s.rows_affected(), "cleanup");
                }
            }
            (Err(err), _) | (_, Err(err)) => tracing::warn!(error = %err, "cleanup failed"),
        }
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = term => {},
    }
    tracing::info!("shutting down");
}
