// src/api/server.rs
use crate::api::handler::HandlerServiceImpl;
use crate::api::rustray::app::proxyman::command::handler_service_server::HandlerServiceServer;
use crate::api::rustray::app::stats::command::stats_service_server::StatsServiceServer;
use crate::api::stats::StatsServiceImpl;
use crate::app::stats::StatsManager;
use crate::error::Result;
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
