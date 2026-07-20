//! `canaryd` — the in-enclave Canary service (Phase 2).

use std::future::IntoFuture as _;

use canaryd::{
    api::router,
    runtime::{Runtime, RuntimeOptions},
};
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let runtime = Runtime::initialize(RuntimeOptions::from_environment()?).await?;
    let cancellation = CancellationToken::new();
    let signal = cancellation.clone();
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        signal.cancel();
    });
    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    let monitor = runtime.clone();
    let monitor_token = cancellation.clone();
    let mut monitor_task =
        tokio::spawn(async move { monitor.run_until_cancelled(monitor_token).await });
    let server = axum::serve(listener, router(runtime.api_state()))
        .with_graceful_shutdown(cancellation.clone().cancelled_owned())
        .into_future();
    tokio::pin!(server);

    // Either component ending must stop the other.  In particular, a monitor
    // failure cancels HTTP serving and propagates a non-zero process result
    // rather than leaving stale readiness visible behind a live listener.
    tokio::select! {
        monitor_result = &mut monitor_task => {
            cancellation.cancel();
            server.await?;
            monitor_result??;
        }
        server_result = &mut server => {
            cancellation.cancel();
            server_result?;
            monitor_task.await??;
        }
    }
    Ok(())
}
