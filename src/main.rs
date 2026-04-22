use actix_web::{web, App, HttpServer};
use clap::Parser;
use rustray::app::state::GlobalState;
use rustray::config;
use rustray::db::DbManager;
use rustray::error::Result;
use rustray::api::handlers::create_user;
use std::sync::Arc;
use tokio::sync::{broadcast, watch};
use tracing::{debug, error, info};

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
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to register Ctrl+C handler");
        info!("Received Ctrl+C, initiating graceful shutdown...");
    }

    let _ = shutdown_tx.send(());
}

#[actix_web::main]
async fn main() -> Result<()> {
    // 1. Initialize logging
    rustray::init_logging();

    // 2. Parse arguments and load initial config
    let args = Args::parse();
    info!("Starting RustRay Unified Process v{}...", env!("CARGO_PKG_VERSION"));

    let config = match config::load(&args.config) {
        Ok(cfg) => {
            info!("Initial configuration loaded from: {}", args.config);
            cfg
        }
        Err(e) => {
            error!("Failed to load configuration: {}", e);
            return Err(e);
        }
    };

    // 3. Initialize Embedded SurrealDB (SurrealKV)
    let db_path = "database/rustray.db";
    let db_manager = DbManager::new(db_path).await?;
    let db = db_manager.db.clone();
    info!("SurrealDB initialized at {}.", db_path);

    // 4. Initialize Watch Channel for real-time config updates
    let (config_tx, mut config_rx) = watch::channel(config.clone());

    // 5. Initialize Global Application State
    let global_state = GlobalState::new(db.clone(), config_tx);
    let shared_state = web::Data::new(global_state);

    // 6. Create shutdown channel
    let (shutdown_tx, mut shutdown_rx) = broadcast::channel::<()>(1);

    // 7. Spawn Proxy Engine Task
    let engine_config = config.clone();
    tokio::spawn(async move {
        info!("Proxy engine worker started with zero-copy watch channel.");
        
        // Initial engine startup would go here
        // For this task, we simulate the engine listening for changes
        while config_rx.changed().await.is_ok() {
            let new_cfg = config_rx.borrow().clone();
            info!("Engine received configuration update! Hot-reloading transport settings...");
            // Logic to update InboundManager/OutboundManager would be triggered here
            debug!("New config tag: {:?}", new_cfg.api.as_ref().map(|a| &a.tag));
        }
        info!("Proxy engine worker shut down.");
    });

    // 8. Spawn Signal Handler
    let signal_tx = shutdown_tx.clone();
    tokio::spawn(async move {
        shutdown_signal(signal_tx).await;
    });

    // 9. Start Actix-web Management Panel
    let api_addr = "127.0.0.1:8081";
    info!("Management Panel API starting on {}...", api_addr);

    let server = HttpServer::new(move || {
        App::new()
            .app_data(shared_state.clone())
            .service(create_user)
            // Other existing routes could be added here
    })
    .bind(api_addr)?
    .run();

    // 10. Wait for shutdown
    tokio::select! {
        _ = server => {
            info!("API server stopped.");
        }
        _ = shutdown_rx.recv() => {
            info!("Shutdown signal received, stopping services...");
        }
    }

    // 11. Graceful Shutdown: Flush SurrealDB RocksDB/SurrealKV cache
    info!("Flushing database caches and terminating...");
    // SurrealDB handle drop usually handles this, but we ensure a clean exit
    drop(db_manager); 
    
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    info!("RustRay shutdown complete.");
    Ok(())
}
