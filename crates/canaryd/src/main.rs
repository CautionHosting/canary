//! `canaryd` — the in-enclave Canary service (Phase 2).

use std::{future::IntoFuture as _, process::ExitCode};

use canaryd::{
    api::router,
    runtime::{Runtime, RuntimeOptions},
};
use clap::Parser as _;
use tokio_util::sync::CancellationToken;

#[derive(clap::Parser)]
#[command(name = "canaryd", version, about = "Caution Canary monitor")]
struct Cli {
    /// Generate a fresh in-enclave signing identity on every daemon start.
    /// Conflicts with CANARY_MASTER_SEED.
    #[arg(long)]
    ephemeral_identity: bool,
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("canaryd=info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    if let Err(error) = run(cli).await {
        tracing::error!(error = ?error, "canaryd terminated with an error");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    tracing::info!("starting canaryd");
    let runtime =
        Runtime::initialize(RuntimeOptions::from_environment(cli.ephemeral_identity)?).await?;
    let config = runtime.config_document();
    let runtime_identity = runtime.snapshot().await.runtime;
    tracing::info!(
        node_id = %config.config.node_id,
        config_digest = %config.config_digest,
        execution_environment = ?runtime_identity.environment,
        identity_mode = ?runtime_identity.identity_mode,
        binary_digest = %runtime_identity.binary_digest,
        target_count = config.config.targets.len(),
        probe_interval_seconds = config.config.probe_interval_seconds,
        history_limit = config.config.history_limit,
        "runtime initialized"
    );
    let cancellation = CancellationToken::new();
    let signal = cancellation.clone();
    tokio::spawn(async move {
        match tokio::signal::ctrl_c().await {
            Ok(()) => {
                tracing::info!("shutdown signal received");
                signal.cancel();
            }
            Err(error) => {
                tracing::error!(%error, "failed to install shutdown signal handler");
                signal.cancel();
            }
        }
    });
    const LISTEN_ADDRESS: &str = "0.0.0.0:8080";
    let listener = tokio::net::TcpListener::bind(LISTEN_ADDRESS).await?;
    tracing::info!(listen_address = LISTEN_ADDRESS, "HTTP listener bound");
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
    tracing::info!("canaryd shutdown complete");
    Ok(())
}
