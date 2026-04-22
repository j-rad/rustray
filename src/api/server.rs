// src/api/server.rs
use crate::api::handler::HandlerServiceImpl;
use crate::api::rustray::app::proxyman::command::handler_service_server::HandlerServiceServer;
use crate::api::rustray::app::stats::command::stats_service_server::StatsServiceServer;
use crate::api::stats::StatsServiceImpl;
use crate::app::stats::StatsManager;
use crate::db::DbManager;
use crate::error::Result;
use actix_files as fs;
use actix_web::{get, post, web, App, HttpResponse, HttpServer, Responder};
use std::sync::Arc;
use tonic::transport::Server;
use tracing::info;

/// Runs the gRPC server for RustRay API compatibility
pub async fn run_grpc_server(port: u16, stats_manager: Arc<StatsManager>) -> Result<()> {
    let addr = format!("0.0.0.0:{}", port).parse()?;

    info!("Starting gRPC API server on {}", addr);

    // Create service implementations
    let handler_service = HandlerServiceImpl::new(stats_manager.clone());
    let stats_service = StatsServiceImpl::new(stats_manager);

    // Initialize health reporter
    let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
    health_reporter
        .set_serving::<HandlerServiceServer<HandlerServiceImpl>>()
        .await;
    health_reporter
        .set_serving::<StatsServiceServer<StatsServiceImpl>>()
        .await;

    // Build and run the tonic server
    Server::builder()
        .add_service(health_service)
        .add_service(HandlerServiceServer::new(handler_service))
        .add_service(StatsServiceServer::new(stats_service))
        .serve(addr)
        .await?;

    Ok(())
}

#[get("/api/inbounds")]
async fn get_inbounds(db: web::Data<Arc<DbManager>>) -> impl Responder {
    match db.get_all_inbounds().await {
        Ok(inbounds) => HttpResponse::Ok().json(inbounds),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[derive(serde::Deserialize)]
struct CreateUserRequest {
    id: String,
    email: String,
}

#[post("/api/users")]
async fn create_user(
    db: web::Data<Arc<DbManager>>,
    req: web::Json<CreateUserRequest>,
) -> impl Responder {
    match db.add_user(&req.id, &req.email).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "success"})),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

#[get("/api/stats")]
async fn get_stats(db: web::Data<Arc<DbManager>>) -> impl Responder {
    match db.get_all_users().await {
        Ok(users) => HttpResponse::Ok().json(users),
        Err(e) => HttpResponse::InternalServerError().body(e.to_string()),
    }
}

/// Runs the Actix-web server for the management panel and REST operations
pub async fn run_actix_server(port: u16, db: Arc<DbManager>) -> std::io::Result<()> {
    let addr = format!("0.0.0.0:{}", port);
    info!("Starting Actix-web API server on {}", addr);

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(db.clone()))
            .service(get_inbounds)
            .service(create_user)
            .service(get_stats)
            .service(fs::Files::new("/", "./web").index_file("index.html"))
    })
    .bind(addr)?
    .run()
    .await
}
