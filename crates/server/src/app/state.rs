//! Shared app state and the live event hub.

use std::sync::Arc;

use shared::RequestSummary;
use sqlx::PgPool;
use tokio::sync::{broadcast, watch};

use crate::{
    app::{auth::oidc::Oidc, limits::Limits},
    config::Config,
};

const HUB_CAPACITY: usize = 1024;

#[derive(Clone)]
pub struct AppState {
    /// Panel queries.
    pub db: PgPool,
    /// Hook inserts; separate so a hook flood can't starve the panel.
    pub hook_db: PgPool,
    pub cfg: Arc<Config>,
    pub limits: Arc<Limits>,
    /// SSO; None when OIDC is not configured.
    pub oidc: Option<Arc<Oidc>>,
    pub hub: broadcast::Sender<RequestSummary>,
    /// Flips once on shutdown so SSE streams end and the server can drain.
    pub shutdown: watch::Receiver<bool>,
}

impl AppState {
    pub async fn new(
        db: PgPool,
        hook_db: PgPool,
        cfg: Config,
        shutdown: watch::Receiver<bool>,
    ) -> Result<Self, String> {
        let (hub, _) = broadcast::channel(HUB_CAPACITY);
        let limits = Arc::new(Limits::new(cfg.hook_rate_per_minute));
        let oidc = match cfg.oidc.clone() {
            Some(oidc_cfg) => Some(Arc::new(Oidc::from_config(oidc_cfg).await?)),
            None => None,
        };
        Ok(Self { db, hook_db, cfg: Arc::new(cfg), limits, oidc, hub, shutdown })
    }
}
