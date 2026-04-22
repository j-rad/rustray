// src/lib.rs
/// Public module for application-wide error types and results.
pub mod error;

#[cfg(not(target_arch = "wasm32"))]
pub mod config;

// use mimalloc::MiMalloc; // Disabled to avoid warning if not used or duplicate.
// Actually, it IS used in global_allocator below if features match.
// The warning was `unused import: mimalloc::MiMalloc`.
// This means `mimalloc` crate is present but `MiMalloc` struct is not used?
// Or maybe the `global_allocator` block is cfg-gated differently?
// Line 8-11 cfg: not(msvc) AND (linux OR windows)
// Line 14-18 cfg: feature="jemalloc" AND not(msvc) AND (linux OR windows)
// Ah! If `feature="jemalloc"` is NOT enabled, the `global_allocator` block is skipped.
// But the `use` statement is NOT gated by `feature="jemalloc"`.
// So if I don't use jemalloc, `MiMalloc` is imported but not used.
// Wait, `mimalloc` is `mimalloc` crate. `jemalloc` is `jemallocator`.
// The code is using `MiMalloc` if `jemalloc` feature is enabled? That's confusing naming.
// Let's look at `rustray/src/lib.rs` again.
// Line 12: `use mimalloc::MiMalloc;`
// Line 20: `static GLOBAL: MiMalloc = MiMalloc;` inside `cfg(feature="jemalloc", ...)`
// NO! `jemalloc` feature implies `jemallocator` usually.
// If I use `mimalloc`, I should use `mimalloc` feature.
// But the `Cargo.toml` has `mimalloc` dependency for linux/windows.
// And `jemallocator` for not(wasm32).
// The code `static GLOBAL: MiMalloc = MiMalloc;` sets `MiMalloc` as allocator.
// But it is guarded by `feature = "jemalloc"`.
// This looks like a copy-paste error where `jemalloc` feature guards `MiMalloc`.
// Unless `MiMalloc` is being used as a fallback or substitution.
// BUT `replacement` content:
// I will gate the import with `feature = "jemalloc"` as well, OR fix the feature name.
// Since `mimalloc` dependency exists, maybe `feature = "mimalloc"` is intended?
// `rustray/Cargo.toml` doesn't show a `mimalloc` feature.
// It shows `mimalloc` dependency for linux/windows.
// I will assume `feature = "jemalloc"` was supposed to be `feature = "mimalloc"` or just always on for linux/windows.
// However, to fix the warning "unused import", I should gate the `use` with the same cfg as the usage.
// global_allocator removed from lib.rs to avoid conflict with main.rs

#[cfg(not(target_arch = "wasm32"))]
pub mod inbounds;

#[cfg(not(target_arch = "wasm32"))]
pub mod adapters;

#[cfg(not(target_arch = "wasm32"))]
pub mod outbounds;

#[cfg(not(target_arch = "wasm32"))]
pub mod router;

#[cfg(not(target_arch = "wasm32"))]
pub mod protocols;

#[cfg(not(target_arch = "wasm32"))]
pub mod transport;

#[cfg(not(target_arch = "wasm32"))]
pub mod fec;

#[cfg(not(target_arch = "wasm32"))]
pub mod p2p;

#[cfg(not(target_arch = "wasm32"))]
pub mod orchestrator;

#[cfg(not(target_arch = "wasm32"))]
pub mod plugin;

#[cfg(not(target_arch = "wasm32"))]
pub mod api;

#[cfg(not(target_arch = "wasm32"))]
pub mod scanner;

#[allow(dead_code)]
const TROJAN_HASH_LEN: usize = 56;
#[cfg(not(target_arch = "wasm32"))]
pub mod app;

/// Public module for Android-specific native integration
#[cfg(target_os = "android")]
pub mod android;

/// Public module for iOS-specific native integration
#[cfg(target_os = "ios")]
pub mod ios;

#[cfg(not(target_arch = "wasm32"))]
pub mod panic_handler;

#[cfg(not(target_arch = "wasm32"))]
pub mod tun;

/// Kernel-level eBPF subsystem for packet mutation (Linux only).
#[cfg(target_os = "linux")]
pub mod kernel;

#[cfg(not(target_arch = "wasm32"))]
pub mod ffi;
#[cfg(not(target_arch = "wasm32"))]
pub use ffi::RustRayResult;

/// Public module for shared types (migrated from shared-types crate)
pub mod types;

#[cfg(not(target_arch = "wasm32"))]
pub mod speedtest;

#[cfg(not(target_arch = "wasm32"))]
pub mod db;

#[cfg(not(target_arch = "wasm32"))]
pub mod jobs;

#[cfg(not(target_arch = "wasm32"))]
pub mod security;

#[cfg(not(target_arch = "wasm32"))]
uniffi::setup_scaffolding!("rustray");

#[cfg(all(not(target_arch = "wasm32"), feature = "tonic"))]
use crate::api::server::run_grpc_server;
#[cfg(not(target_arch = "wasm32"))]
use crate::app::dns::DnsServer;
#[cfg(not(target_arch = "wasm32"))]
use crate::app::metrics;
#[cfg(not(target_arch = "wasm32"))]
use crate::app::observatory::Observatory;
#[cfg(not(target_arch = "wasm32"))]
use crate::app::reverse::ReverseManager;
#[cfg(not(target_arch = "wasm32"))]
use crate::app::stats::StatsManager;
use crate::error::Result;
#[cfg(not(target_arch = "wasm32"))]
use crate::inbounds::InboundManager;
#[cfg(not(target_arch = "wasm32"))]
use crate::outbounds::OutboundManager;
#[cfg(not(target_arch = "wasm32"))]
use crate::router::Router;
#[cfg(all(feature = "minimal-server", not(target_arch = "wasm32")))]
use actix_web::HttpResponse;
#[cfg(not(target_arch = "wasm32"))]
use crate::db::DbManager;
#[cfg(not(target_arch = "wasm32"))]
use actix_web::{App, HttpServer, web};
use std::sync::Arc;
#[cfg(not(target_arch = "wasm32"))]
use tokio::sync::broadcast;

// ============================================================================
// Logging Initialization
// ============================================================================

/// Initialize the logging system with optional file appender support.
///
/// In production (when `RUSTRAY_LOG_FILE` is set), logs are written to file with rotation.
/// Otherwise, logs are written to stdout.
#[cfg(not(target_arch = "wasm32"))]
pub fn init_logging() {
    use tracing_subscriber::{EnvFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt};

    let env_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info,rustray=debug"));

    #[cfg(feature = "minimal-server")]
    {
        use tracing_appender::rolling;

        if let Ok(log_dir) = std::env::var("RUSTRAY_LOG_DIR") {
            // Production: file-based logging with daily rotation
            let file_appender = rolling::daily(&log_dir, "rustray.log");
            let (non_blocking, _guard) = tracing_appender::non_blocking(file_appender);

            // Store guard in a static to keep it alive
            static LOG_GUARD: std::sync::OnceLock<tracing_appender::non_blocking::WorkerGuard> =
                std::sync::OnceLock::new();
            let _ = LOG_GUARD.set(_guard);

            tracing_subscriber::registry()
                .with(env_filter)
                .with(fmt::layer().with_writer(non_blocking))
                .init();
            return;
        }
    }

    // Default: stdout logging with pretty format
    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt::layer())
        .init();
}

#[cfg(target_arch = "wasm32")]
pub fn init_logging() {
    // No-op for WASM
}

/// Helper to serve stats to the dashboard from the native StatsManager
#[cfg(all(not(target_arch = "wasm32"), feature = "minimal-server"))]
async fn handle_dashboard_stats(_data: web::Data<Arc<StatsManager>>) -> HttpResponse {
    // Construct snapshot compatible with dashboard expectations
    // We map StatsManager data to the expected JSON structure
    use crate::app::connection_tracker::global_tracker;
    let tracker = global_tracker();
    let stats = tracker.get_stats();

    // We can recycle StatsSnapshot from FFI if available, or define a local anonymous struct
    // Reusing FFI struct for consistency
    let snap = crate::ffi::StatsSnapshot {
        bytes_uploaded: stats.bytes_uploaded,
        bytes_downloaded: stats.bytes_downloaded,
        active_connections: stats.active_connections as u64, // StatsManager tracks this differently? Tracker has it.
        total_connections: 0,                                // Not tracked; using 0 as default
        last_update: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64,
        connection_state: if crate::tun::tun2socks::is_core_healthy() {
            2
        } else {
            0
        },
        errors: 0,
    };

    HttpResponse::Ok().json(snap)
}

/// Helper to serve active sessions list
#[cfg(all(not(target_arch = "wasm32"), feature = "minimal-server"))]
async fn handle_active_sessions(_data: web::Data<Arc<StatsManager>>) -> HttpResponse {
    use crate::app::connection_tracker::global_tracker;
    let tracker = global_tracker();
    let sessions = tracker.get_active_sessions();
    HttpResponse::Ok().json(sessions)
}

/// Main entry point for the library to run the proxy server.
///
/// Accepts a shutdown receiver for graceful termination coordination.
#[cfg(not(target_arch = "wasm32"))]
pub async fn run_server(
    mut config: config::Config,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> Result<()> {
    let api_listen_addr = if let Some(api) = &config.api {
        let host = api.listen.as_deref().unwrap_or("127.0.0.1");
        let port = api.port.unwrap_or(8081) + 1;
        format!("{}:{}", host, port)
    } else {
        "127.0.0.1:8081".to_string()
    };

    // Extract gRPC port from config (default to 10085 if not specified)
    let grpc_port = config
        .api
        .as_ref()
        .and_then(|api| api.port)
        .unwrap_or(10085);

    // --- SECURITY: HARD KILL SWITCH ---
    // Ensure immediate process termination on panic to prevent leaks.
    // The OS will clean up the TUN interface (file descriptor) automatically on exit.
    std::panic::set_hook(Box::new(|info| {
        tracing::error!(
            "CRITICAL PANIC: {:?}. Hard Kill Switch activated. Terminating immediately.",
            info
        );
        std::process::abort();
    }));

    // --- SECURE STORAGE ---
    // Storage is initialized via FFI or external caller.
    // We assume it's ready if needed, or we rely on passed-in Config.
    tracing::info!("Secure Storage should be initialized externally.");

    // --- DNS Server Init ---
    let dns_config = config.dns.take().unwrap_or_default();
    let dns_server = Arc::new(DnsServer::new(dns_config)?);
    tracing::info!("Internal DNS server initialized.");

    // --- DATABASE INIT ---
    let db_path = "database/rustray.db";
    let db_manager = Arc::new(DbManager::new(db_path).await?);
    tracing::info!("Embedded SurrealDB (SurrealKV) initialized at {}.", db_path);

    // --- APPLICATION INIT ---

    // 1. Create StatsManager (Unified State)
    let stats_manager = Arc::new(StatsManager::new(config, dns_server.clone()));
    tracing::info!("StatsManager and PolicyManager initialized.");

    // 2. Initialize ReverseManager
    let reverse_manager = Arc::new(ReverseManager::new());
    tracing::info!("ReverseManager (bridge/portal) initialized.");

    // 3. Initialize OutboundManager
    let outbound_manager =
        Arc::new(OutboundManager::new(stats_manager.clone(), reverse_manager.clone()).await?);
    tracing::info!("OutboundManager initialized.");

    // 4. Initialize Router
    let router = Arc::new(Router::new(stats_manager.clone(), outbound_manager.clone()).await?);
    router.start_monitor();
    tracing::info!("Router initialized with rules.");

    // 5. Initialize InboundManager
    let inbound_manager = InboundManager::new(
        router.clone(),
        dns_server.clone(),
        stats_manager.clone(),
        reverse_manager.clone(),
    );
    tracing::info!("InboundManager initialized.");

    // 6. Initialize and run Observatory
    if let Some(obs_config) = stats_manager.config.load().observatory.clone()
        && !obs_config.probe_interval.is_empty() && obs_config.probe_interval != "0" {
            tracing::info!("Observatory module is enabled.");
            let observatory = Arc::new(Observatory::new(
                obs_config,
                outbound_manager.clone(),
                stats_manager.clone(),
            ));
            observatory.run();
        }

    // 7. Spawn InboundManager as a background task
    let inbound_stats = stats_manager.clone();
    tokio::spawn(async move {
        tracing::info!("InboundManager task started.");
        if let Err(e) = inbound_manager.run(inbound_stats).await {
            tracing::error!("InboundManager failed: {}", e);
        } else {
            tracing::info!("InboundManager shut down cleanly.");
        }
    });

    // 8. Spawn gRPC server as a background task
    #[cfg(feature = "tonic")]
    {
        let grpc_stats = stats_manager.clone();
        tokio::spawn(async move {
            tracing::info!("gRPC server task started on port {}.", grpc_port);
            if let Err(e) = run_grpc_server(grpc_port, grpc_stats).await {
                tracing::error!("gRPC server failed: {}", e);
            } else {
                tracing::info!("gRPC server shut down cleanly.");
            }
        });
    }

    // 9. Check metrics
    let metrics_enabled = stats_manager.config.load().metrics.is_some();

    // --- Start Actix-Web Server (for metrics endpoint) ---
    tracing::info!("Starting metrics API server on {}...", api_listen_addr);

    let server = HttpServer::new(move || {
        let app_data = web::Data::new(stats_manager.clone());
        let db_data = web::Data::new(db_manager.clone());

        let mut app = App::new()
            .app_data(app_data.clone())
            .app_data(db_data.clone());

        if metrics_enabled {
            app = app.route("/metrics", web::get().to(metrics::handle_metrics_request));
        }

        #[cfg(feature = "minimal-server")]
        {
            // Serve Dashboard Data
            app = app.route("/node/stats", web::get().to(handle_dashboard_stats));
            app = app.route("/node/sessions", web::get().to(handle_active_sessions));

            // Serve Dashboard UI (must be last as includes catch-all)
            app = app
                .route("/", web::get().to(crate::api::headless::serve_index))
                // Note: We use a scoped service or manual matching to avoid conflict if possible,
                // but here we just append. Routes are matched in order.
                .route(
                    "/{path:.*}",
                    web::get().to(crate::api::headless::serve_static_asset),
                );
        }

        // --- New Monolithic REST API ---
        app = app
            .service(crate::api::server::get_inbounds)
            .service(crate::api::server::create_user)
            .service(crate::api::server::get_stats);

        app
    })
    .bind(api_listen_addr)?
    .run();

    tracing::info!("RustRay is running. (Proxy and gRPC tasks in background).");

    // Wait for either server completion or shutdown signal
    tokio::select! {
        result = server => {
            if let Err(e) = result {
                tracing::error!("Server error: {}", e);
            }
        }
        _ = shutdown_rx.recv() => {
            tracing::info!("Shutdown signal received, stopping server...");
        }
    }

    // Graceful shutdown: give tasks time to complete
    tracing::info!("Initiating graceful shutdown (5 second timeout)...");
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // TUN cleanup happens automatically when runtime drops
    // smoltcp buffers flush on socket close
    tracing::info!("RustRay shutting down gracefully.");
    Ok(())
}
