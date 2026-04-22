use crate::app::state::GlobalState;
use actix_web::{post, web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use tracing::{info, error};

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateUserRequest {
    pub id: String,
    pub email: String,
}

/// POST /api/users
/// Creates a new user in SurrealDB and triggers a hot-reload of the engine config.
#[post("/api/users")]
pub async fn create_user(
    state: web::Data<GlobalState>,
    req: web::Json<CreateUserRequest>,
) -> impl Responder {
    info!("Received request to create user: {}", req.email);

    // 1. Update SurrealDB
    // We use the raw DB handle from GlobalState for direct control
    let db = &state.db;
    let user_id = format!("user:{}", req.id);
    
    let result: Result<Option<serde_json::Value>, _> = db.upsert(("user", &req.id))
        .content(serde_json::json!({
            "email": req.email,
            "traffic": 0,
        }))
        .await;

    if let Err(e) = result {
        error!("Failed to update SurrealDB: {}", e);
        return HttpResponse::InternalServerError().body(e.to_string());
    }

    // 2. Notify the engine to hot-reload transport settings
    // In a real scenario, we might rebuild the full Config struct from DB
    // For this bridge, we'll fetch the current config, modify it, and send it.
    let mut current_config = state.config_tx.borrow().clone();
    
    // Example: Triggering transport reload by bumping a version or similar
    // Here we just re-send the config to signal a change.
    if let Err(e) = state.config_tx.send(current_config) {
        error!("Failed to notify engine of config change: {}", e);
        return HttpResponse::InternalServerError().body("Failed to notify proxy engine");
    }

    info!("User {} created and engine notified.", req.email);
    HttpResponse::Ok().json(serde_json::json!({"status": "success", "user": req.email}))
}
