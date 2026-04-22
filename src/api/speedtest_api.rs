// src/api/speedtest_api.rs
use crate::app::stats::StatsManager;
use crate::speedtest::SpeedTestEngine;
use crate::types::ServerConfig;
use actix_web::{HttpResponse, Responder, post, web};
// use std::sync::Arc;
use tracing::error;

#[post("/diagnostics/speed-test")]
pub async fn trigger_speed_test(server_config: web::Json<ServerConfig>) -> impl Responder {
    let stats = match StatsManager::global() {
        Some(s) => s,
        None => return HttpResponse::InternalServerError().body("StatsManager not initialized"),
    };

    let dns = stats.dns_server.clone();
    let engine = SpeedTestEngine::new(dns);

    match engine.run_comprehensive_test(&server_config).await {
        Ok(results) => HttpResponse::Ok().json(results),
        Err(e) => {
            error!("Speed test failed: {}", e);
            HttpResponse::InternalServerError().body(format!("Speed test failed: {}", e))
        }
    }
}
