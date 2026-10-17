//! rusty_hook: self-hosted webhook inspector. Global init only; the app lives in `app`.

mod app;
mod config;

use std::process::ExitCode;

// musl's allocator is slow under concurrency.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> ExitCode {
    // Docker HEALTHCHECK runs the same binary (scratch image has no curl).
    if std::env::args().nth(1).as_deref() == Some("healthcheck") {
        return app::healthcheck();
    }
    config::init_logger();

    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(err) => {
            tracing::error!("runtime: {err}");
            return ExitCode::FAILURE;
        }
    };
    match rt.block_on(start()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!("fatal: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn start() -> Result<(), String> {
    let cfg = config::Config::from_env()?;
    app::Application::build(cfg).await?.run().await;
    Ok(())
}
