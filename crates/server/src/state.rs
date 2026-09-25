//! Shared app state and the live event hub.

use std::sync::Arc;

use shared::RequestSummary;
use sqlx::PgPool;
use tokio::sync::{broadcast, watch};

use crate::{config::Config, limits::Limits};

const HUB_CAPACITY: usize = 1024;

#[derive(Clone)]
pub struct AppState {
    /// Panel queries.
    pub db: PgPool,
    /// Hook inserts; separate so a hook flood can't starve the panel.
    pub hook_db: PgPool,
    pub cfg: Arc<Config>,
    pub limits: Arc<Limits>,
    pub hub: broadcast::Sender<RequestSummary>,
    /// Flips once on shutdown so SSE streams end and the server can drain.
    pub shutdown: watch::Receiver<bool>,
}

impl AppState {
    pub fn new(db: PgPool, hook_db: PgPool, cfg: Config, shutdown: watch::Receiver<bool>) -> Self {
        let (hub, _) = broadcast::channel(HUB_CAPACITY);
        let limits = Arc::new(Limits::new(cfg.hook_rate_per_minute));
        Self { db, hook_db, cfg: Arc::new(cfg), limits, hub, shutdown }
    }
}
