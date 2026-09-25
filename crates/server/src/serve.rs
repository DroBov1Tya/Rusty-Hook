//! HTTP accept loop. Replaces `axum::serve` to get a header-read timeout (slowloris)
//! and a hard cap on open connections.

use std::{future::Future, net::SocketAddr, sync::Arc, time::Duration};

use axum::{Router, extract::ConnectInfo, http::Request};
use hyper::body::Incoming;
use hyper_util::{
    rt::{TokioExecutor, TokioIo, TokioTimer},
    server::{conn::auto::Builder, graceful::GracefulShutdown},
    service::TowerToHyperService,
};
use tokio::{net::TcpListener, sync::Semaphore};
use tower::ServiceExt;

const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

pub async fn run(listener: TcpListener, app: Router, max_connections: usize, shutdown: impl Future<Output = ()>) {
    let mut builder = Builder::new(TokioExecutor::new());
    builder.http1().timer(TokioTimer::new()).header_read_timeout(HEADER_READ_TIMEOUT);
    builder.http2().timer(TokioTimer::new());

    let slots = Arc::new(Semaphore::new(max_connections));
    let graceful = GracefulShutdown::new();
    tokio::pin!(shutdown);

    loop {
        // Wait for a free slot first: excess clients queue in the kernel backlog.
        let permit = tokio::select! {
            permit = Arc::clone(&slots).acquire_owned() => match permit {
                Ok(p) => p,
                Err(_) => break,
            },
            () = &mut shutdown => break,
        };
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(conn) => conn,
                Err(err) => {
                    tracing::warn!(error = %err, "accept failed");
                    continue;
                }
            },
            () = &mut shutdown => break,
        };

        let svc = app.clone().map_request(move |mut req: Request<Incoming>| {
            req.extensions_mut().insert(ConnectInfo::<SocketAddr>(peer));
            req
        });
        let conn = builder.serve_connection_with_upgrades(TokioIo::new(stream), TowerToHyperService::new(svc));
        let conn = graceful.watch(conn.into_owned());
        tokio::spawn(async move {
            // Client resets and timeouts are routine; not worth logging.
            let _ = conn.await;
            drop(permit);
        });
    }

    if tokio::time::timeout(DRAIN_TIMEOUT, graceful.shutdown()).await.is_err() {
        tracing::warn!("drain timed out, closing remaining connections");
    }
}
