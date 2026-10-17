//! Application: wires storage, state, auth and the HTTP server; owns startup and shutdown.

mod api;
mod auth;
mod error;
mod health;
mod hooks;
mod limits;
mod routes;
mod server;
mod state;
mod storage;

use tokio::{net::TcpListener, sync::watch};

use crate::{app::state::AppState, config::Config};

pub use health::probe as healthcheck;

pub struct Application {
    state: AppState,
    listener: TcpListener,
    stop: watch::Sender<bool>,
}

impl Application {
    /// Connect to Postgres, build shared state and bind the port. Fails fast on any error.
    pub async fn build(cfg: Config) -> Result<Self, String> {
        let db = storage::connect(&cfg, "rusty_hook_panel").await?;
        let hook_db = storage::connect(&cfg, "rusty_hook_hooks").await?;
        let (stop, stop_rx) = watch::channel(false);
        let state = AppState::new(db, hook_db, cfg, stop_rx)?;
        warn_if_open(&state.cfg);

        let bind = state.cfg.bind;
        let listener = TcpListener::bind(bind).await.map_err(|e| format!("bind {bind}: {e}"))?;
        Ok(Self { state, listener, stop })
    }

    /// Serve until SIGTERM/Ctrl+C, then drain connections and end live streams.
    pub async fn run(self) {
        let Self { state, listener, stop } = self;

        if let Some(oidc) = state.oidc.clone() {
            // Warm the discovery cache; failure is only logged, login retries lazily.
            tokio::spawn(async move {
                match oidc.warm_up().await {
                    Ok(()) => tracing::info!("oidc provider discovered"),
                    Err(err) => tracing::warn!(error = %err, "oidc discovery failed, will retry on login"),
                }
            });
        }
        tokio::spawn(storage::cleanup_loop(state.clone()));

        tracing::info!(
            bind = %state.cfg.bind,
            key_login = state.cfg.admin_key.is_some(),
            sso_login = state.cfg.oidc.is_some(),
            open = !state.cfg.login_required,
            "listening"
        );
        let max_connections = state.cfg.max_connections;
        server::run(listener, routes::build(state), max_connections, async move {
            server::shutdown_signal().await;
            let _ = stop.send(true);
        })
        .await;
    }
}

fn warn_if_open(cfg: &Config) {
    if cfg.login_required {
        return;
    }
    tracing::warn!("AUTH_MODE=open: anyone who reaches this port can use the panel");
    if cfg.public_hosts.is_empty() {
        tracing::warn!("PUBLIC_HOSTS is empty: open panel is exposed to DNS rebinding");
    }
}
