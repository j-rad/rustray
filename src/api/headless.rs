// src/api/headless.rs
//! Minimalist Headless Control Plane with Embedded Dashboard
//!
//! Provides a lightweight HTTP server for headless systems (OpenWrt, Linux servers).
//!
//! Features:
//! - Embedded Wasm Dashboard served at `/`
//! - POST /node/apply: Hot-reload configuration (PSK protected)
//! - GET /node/stats: Real-time traffic stats (PSK protected)
//! - PSK Authentication for API endpoints only

use actix_web::http::header;
use actix_web::{
    App, Error, HttpRequest, HttpResponse, HttpServer, dev::ServiceRequest, dev::ServiceResponse,
    web,
};
use futures::Future;
use futures::future::{Ready, ok};
use std::pin::Pin;
use std::sync::Arc;

use crate::api::embedded_assets;
use crate::ffi::EngineManager;

/// State for the headless API
pub struct HeadlessState {
    pub psk: String,
    pub engine: Arc<EngineManager>,
}

/// PSK Middleware - only applies to /node/* routes
pub struct PskMiddleware {
    pub psk: String,
}

impl<S, B> actix_web::dev::Transform<S, ServiceRequest> for PskMiddleware
where
    S: actix_web::dev::Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<actix_web::body::EitherBody<B>>;
    type Error = Error;
    type Transform = PskService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(PskService {
            service,
            psk: self.psk.clone(),
        })
    }
}

pub struct PskService<S> {
    service: S,
    psk: String,
}

impl<S, B> actix_web::dev::Service<ServiceRequest> for PskService<S>
where
    S: actix_web::dev::Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<actix_web::body::EitherBody<B>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(
        &self,
        ctx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        // Only require PSK for /node/* endpoints
        let path = req.path();
        let requires_auth = path.starts_with("/node/") || path.starts_with("/api/");

        if requires_auth {
            let auth_header = req.headers().get("X-RUSTRAY-PSK");
            let valid = if let Some(val) = auth_header {
                if let Ok(v_str) = val.to_str() {
                    v_str == self.psk
                } else {
                    false
                }
            } else {
                false
            };

            if !valid {
                return Box::pin(async {
                    Ok(req
                        .into_response(HttpResponse::Unauthorized().finish().map_into_right_body()))
                });
            }
        }

        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res.map_into_left_body())
        })
    }
}

// ============================================================================
// API Handlers (PSK Protected)
// ============================================================================

#[derive(serde::Deserialize)]
pub struct UpdateCoreQuery {
    pub core_type: String,
}

pub async fn update_core_handler(
    state: web::Data<HeadlessState>,
    query: web::Query<UpdateCoreQuery>,
) -> HttpResponse {
    match state.engine.update_core(query.core_type.clone()) {
        Ok(version) => HttpResponse::Ok().json(serde_json::json!({
            "status": "ok",
            "version": version
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "status": "error",
            "message": e.to_string()
        })),
    }
}

pub async fn apply_config(
    state: web::Data<HeadlessState>,
    config_json: web::Json<serde_json::Value>,
) -> HttpResponse {
    let config_str = config_json.to_string();

    // Try atomic update first (hot reload)
    match state.engine.apply_routing_config(config_str.clone()) {
        crate::ffi::RayResult::Ok => {
            return HttpResponse::Ok().json(
                serde_json::json!({"status": "ok", "message": "Configuration updated atomically"}),
            );
        }
        crate::ffi::RayResult::NotRunning => {
            // Engine not running, fall through to start
        }
        err => {
            return HttpResponse::BadRequest()
                .json(serde_json::json!({"status": "error", "message": err.to_string()}));
        }
    }

    // Stop existing (just in case, though NotRunning implies it)
    let _ = state.engine.stop_engine();

    // Start new
    match state.engine.start_engine(config_str, None) {
        crate::ffi::RayResult::Ok => HttpResponse::Ok()
            .json(serde_json::json!({"status": "ok", "message": "Engine started"})),
        err => HttpResponse::BadRequest()
            .json(serde_json::json!({"status": "error", "message": err.to_string()})),
    }
}

pub async fn get_stats(state: web::Data<HeadlessState>) -> HttpResponse {
    let stats = state.engine.get_stats_json();
    HttpResponse::Ok()
        .content_type("application/json")
        .body(stats)
}

#[derive(serde::Deserialize)]
pub struct ConnectionMetricsQuery {
    pub conn_id: String,
}

pub async fn get_connection_metrics(
    _state: web::Data<HeadlessState>,
    query: web::Query<ConnectionMetricsQuery>,
) -> HttpResponse {
    use crate::app::stats::StatsManager;

    if let Some(stats_manager) = StatsManager::global() {
        let metrics = stats_manager.get_connection_metrics(&query.conn_id);
        HttpResponse::Ok().json(metrics)
    } else {
        HttpResponse::InternalServerError().json(serde_json::json!({
            "status": "error",
            "message": "Stats manager not initialized"
        }))
    }
}

/// Health check endpoint (no auth required)
pub async fn health_check() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

// ============================================================================
// Static Asset Handlers
// ============================================================================

/// Serve embedded static assets (index.html, wasm, js, css)
pub async fn serve_static_asset(req: HttpRequest, path: web::Path<String>) -> HttpResponse {
    let path_str = path.into_inner();

    // Try to serve the requested path
    if let Some(response) = embedded_assets::serve_asset(&req, &path_str) {
        return response;
    }

    // SPA fallback: return index.html for unknown paths (client-side routing)
    if let Some(index_content) = embedded_assets::get_index_html() {
        return HttpResponse::Ok()
            .content_type("text/html; charset=utf-8")
            .insert_header((header::CACHE_CONTROL, "no-cache"))
            .body(index_content);
    }

    HttpResponse::NotFound().body("Not Found")
}

/// Serve index.html for root path
pub async fn serve_index(req: HttpRequest) -> HttpResponse {
    if let Some(response) = embedded_assets::serve_asset(&req, "index.html") {
        return response;
    }

    // Fallback if embedded assets are missing
    HttpResponse::ServiceUnavailable().json(serde_json::json!({
        "error": "Dashboard assets not embedded. Build with: dx build --release --platform web"
    }))
}

// ============================================================================
// TLS Configuration
// ============================================================================

/// TLS configuration for the headless server
pub struct TlsConfig {
    pub cert_path: String,
    pub key_path: String,
}

impl TlsConfig {
    /// Load TLS configuration from files
    pub fn load(&self) -> std::io::Result<rustls::ServerConfig> {
        use rustls_pemfile::{certs, private_key};
        use std::fs::File;
        use std::io::BufReader;

        let cert_file = File::open(&self.cert_path)?;
        let key_file = File::open(&self.key_path)?;

        let cert_reader = &mut BufReader::new(cert_file);
        let key_reader = &mut BufReader::new(key_file);

        let cert_chain: Vec<_> = certs(cert_reader).filter_map(|c| c.ok()).collect();

        let key = private_key(key_reader)
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid private key")
            })?
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::NotFound, "No private key found")
            })?;

        let config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;

        Ok(config)
    }
}

// ============================================================================
// Log Streaming API
// ============================================================================

/// Get recent log entries
pub async fn get_logs(query: web::Query<LogsQuery>) -> HttpResponse {
    use crate::app::logging::LogBuffer;
    use std::sync::OnceLock;

    static LOG_BUFFER: OnceLock<std::sync::Arc<LogBuffer>> = OnceLock::new();
    let buffer = LOG_BUFFER.get_or_init(|| std::sync::Arc::new(LogBuffer::new(1000)));

    let lines = buffer.get_recent(query.limit.unwrap_or(100));
    HttpResponse::Ok().json(serde_json::json!({
        "logs": lines,
        "count": lines.len(),
    }))
}

#[derive(serde::Deserialize)]
pub struct LogsQuery {
    pub limit: Option<usize>,
    pub since: Option<usize>,
}

// ============================================================================
// Server Entry Point
// ============================================================================

/// Run the headless server with embedded dashboard
pub async fn run_headless_server(bind_addr: String, psk: String) -> std::io::Result<()> {
    run_headless_server_with_tls(bind_addr, psk, None).await
}

/// Run the headless server with optional TLS
pub async fn run_headless_server_with_tls(
    bind_addr: String,
    psk: String,
    tls_config: Option<TlsConfig>,
) -> std::io::Result<()> {
    use crate::api::auth_middleware::{
        AuthConfig, AuthMiddleware, SessionStore, login, logout, refresh,
    };

    let is_tls = tls_config.is_some();
    tracing::info!(
        "Starting Headless Control Plane on {} (TLS: {}, Dashboard + Auth)",
        bind_addr,
        is_tls
    );

    // Log embedded asset count for verification
    let asset_count = embedded_assets::list_assets().len();
    if asset_count > 0 {
        tracing::info!("Embedded {} static assets for dashboard", asset_count);
    } else {
        tracing::warn!("No embedded assets found! Dashboard will be unavailable.");
    }

    // Initialize session store
    let session_store = std::sync::Arc::new(SessionStore::new(&psk));
    let auth_config = std::sync::Arc::new(AuthConfig {
        session_store: session_store.clone(),
        psk: psk.clone(),
    });

    let engine = EngineManager::new();
    let state = web::Data::new(HeadlessState {
        psk: psk.clone(),
        engine,
    });

    let auth_config_data = web::Data::new(auth_config.clone());

    let server = HttpServer::new(move || {
        App::new()
            .wrap(AuthMiddleware {
                config: auth_config.clone(),
            })
            .app_data(state.clone())
            .app_data(auth_config_data.clone())
            // Health check (no auth)
            .route("/health", web::get().to(health_check))
            // Authentication endpoints
            .route("/api/auth/login", web::post().to(login))
            .route("/api/auth/refresh", web::post().to(refresh))
            .route("/api/auth/logout", web::post().to(logout))
            // Protected API routes
            // Protected API routes
            .route("/node/apply", web::post().to(apply_config))
            .route("/node/stats", web::get().to(get_stats))
            .route(
                "/node/connection_metrics",
                web::get().to(get_connection_metrics),
            )
            .route("/api/logs", web::get().to(get_logs))
            .route("/node/update_core", web::post().to(update_core_handler))
            .route(
                "/api/diagnostics/report",
                web::get().to(crate::api::diagnostics_api::get_diagnostic_report),
            )
            .service(crate::api::speedtest_api::trigger_speed_test)
            // Serve index.html at root
            .route("/", web::get().to(serve_index))
            // Serve all other static assets with SPA fallback
            .route("/{path:.*}", web::get().to(serve_static_asset))
    });

    // Bind with or without TLS
    if let Some(tls) = tls_config {
        let rustls_config = tls.load()?;
        tracing::info!("TLS 1.3 enabled for administrative traffic");
        server
            .bind_rustls_0_23(bind_addr, rustls_config)?
            .run()
            .await
    } else {
        tracing::warn!("Running without TLS - NOT RECOMMENDED for production");
        server.bind(bind_addr)?.run().await
    }
}

/// Create TLS config from environment or paths
pub fn tls_config_from_env() -> Option<TlsConfig> {
    let cert_path = std::env::var("RUSTRAY_TLS_CERT").ok()?;
    let key_path = std::env::var("RUSTRAY_TLS_KEY").ok()?;
    Some(TlsConfig {
        cert_path,
        key_path,
    })
}
