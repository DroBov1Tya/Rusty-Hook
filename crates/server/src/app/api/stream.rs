//! Live feed (SSE) of every captured request across all endpoints.

use std::{convert::Infallible, time::Duration};

use axum::{
    extract::State,
    http::HeaderMap,
    response::sse::{Event, KeepAlive, Sse},
};
use futures_util::{Stream, StreamExt};
use shared::{EVENT_HIT, EVENT_RESYNC};
use tokio_stream::wrappers::BroadcastStream;

use crate::app::{auth, state::AppState};

const SESSION_RECHECK: Duration = Duration::from_secs(30);
const KEEP_ALIVE: Duration = Duration::from_secs(15);

/// Lag -> "resync" so the UI refetches. Ends on shutdown or once the session is gone
/// (logout, expiry, key rotation).
pub async fn events(
    State(st): State<AppState>,
    headers: HeaderMap,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let mut shutdown = st.shutdown.clone();
    let session_gone = {
        let st = st.clone();
        async move {
            loop {
                tokio::time::sleep(SESSION_RECHECK).await;
                if !matches!(auth::is_authenticated(&st, &headers).await, Ok(true)) {
                    break;
                }
            }
        }
    };
    let events = BroadcastStream::new(st.hub.subscribe())
        .map(|msg| {
            let event = msg
                .ok()
                .and_then(|summary| Event::default().event(EVENT_HIT).json_data(summary).ok())
                .unwrap_or_else(|| Event::default().event(EVENT_RESYNC).data("lag"));
            Ok(event)
        })
        .take_until(async move {
            tokio::select! {
                _ = shutdown.wait_for(|stop| *stop) => {},
                () = session_gone => {},
            }
        });
    Sse::new(events).keep_alive(KeepAlive::new().interval(KEEP_ALIVE))
}
