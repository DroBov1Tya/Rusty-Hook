//! Postgres pools and the periodic retention cleanup.

use std::time::Duration;

use sqlx::{
    PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};

use crate::{app::state::AppState, config::Config};

const CLEANUP_EVERY: Duration = Duration::from_secs(60);
const ACQUIRE_TIMEOUT: Duration = Duration::from_secs(5);

/// One pool per role (panel / hooks); `name` shows up in pg_stat_activity.
pub async fn connect(cfg: &Config, name: &str) -> Result<PgPool, String> {
    let opts = PgConnectOptions::new()
        .host(&cfg.db.host)
        .port(cfg.db.port)
        .username(&cfg.db.user)
        .password(&cfg.db.password)
        .database(&cfg.db.database)
        .application_name(name);
    PgPoolOptions::new()
        .max_connections(cfg.db.max_connections)
        .acquire_timeout(ACQUIRE_TIMEOUT)
        .connect_with(opts)
        .await
        .map_err(|e| format!("database: {e}"))
}

/// Drops requests past retention, expired sessions and idle rate-limit keys.
pub async fn cleanup_loop(st: AppState) {
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
