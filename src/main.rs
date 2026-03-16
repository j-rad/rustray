// src/main.rs
//! RustRay Server Binary
//!
//! Production-ready entry point with signal handling for graceful shutdown.

use clap::Parser;
use rustray::config;
use rustray::error::Result;
use tokio::sync::broadcast;
use tracing::{debug, error, info, warn};

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static ALLOC: jemallocator::Jemalloc = jemallocator::Jemalloc;

/// RustRay: A high-performance proxy core.
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Path to the configuration file
    #[arg(short, long, required = true)]
    config: String,
}

/// Wait for shutdown signals (SIGTERM, SIGINT) and send shutdown notification.
async fn shutdown_signal(shutdown_tx: broadcast::Sender<()>) {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut sigterm =
            signal(SignalKind::terminate()).expect("Failed to register SIGTERM handler");
        let mut sigint =
            signal(SignalKind::interrupt()).expect("Failed to register SIGINT handler");

        tokio::select! {
            _ = sigterm.recv() => {
                info!("Received SIGTERM, initiating graceful shutdown...");
            }
            _ = sigint.recv() => {
                info!("Received SIGINT, initiating graceful shutdown...");
            }
        }
    }

    #[cfg(not(unix))]
    {
        // Windows: use ctrl_c which handles CTRL+C
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to register Ctrl+C handler");
        info!("Received Ctrl+C, initiating graceful shutdown...");
    }

    // Notify all listeners that shutdown is requested
    let _ = shutdown_tx.send(());
}

#[actix_web::main]
async fn main() -> Result<()> {
    // Initialize the tracing subscriber for logging
    rustray::init_logging();

    // Parse command-line arguments
    let args = Args::parse();
    info!("Starting RustRay v{}...", env!("CARGO_PKG_VERSION"));

    // Load the configuration file
    let config = match config::load(&args.config) {
        Ok(cfg) => {
            info!("Successfully loaded configuration from: {}", args.config);
            debug!("Loaded config: {:#?}", cfg);
            cfg
        }
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            return Err(e);
        }
    };

    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = broadcast::channel::<()>(1);

    // Spawn signal handler task
    let signal_tx = shutdown_tx.clone();
    tokio::spawn(async move {
        shutdown_signal(signal_tx).await;
    });

    // Run server with shutdown receiver
    let result = rustray::run_server(config, shutdown_rx).await;

    info!("RustRay shutdown complete.");
    result
}
