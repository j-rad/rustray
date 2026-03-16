// rustray/src/api/users.rs
//! User Management API
//!
//! Provides CRUD operations for user management:
//! - List/Search users with pagination
//! - Create/Update/Delete users
//! - Quota management
//! - Bulk operations

use actix_web::{HttpResponse, web};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// User data transfer object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserDto {
    pub id: String,
    pub email: String,
    pub inbound_tag: String,
    pub enabled: bool,
    pub upload_bytes: i64,
    pub download_bytes: i64,
    pub total_limit_gb: Option<i64>,
    pub expiry_time: Option<i64>,
    pub created_at: i64,
}

/// User creation request
#[derive(Debug, Clone, Deserialize)]
pub struct CreateUserRequest {
    pub email: String,
    pub inbound_tag: String,
    pub total_limit_gb: Option<i64>,
    pub expiry_time: Option<i64>,
}

/// User update request
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateUserRequest {
    pub email: Option<String>,
    pub enabled: Option<bool>,
    pub total_limit_gb: Option<i64>,
    pub expiry_time: Option<i64>,
    pub reset_traffic: Option<bool>,
}

/// Pagination query parameters
#[derive(Debug, Clone, Deserialize)]
pub struct PaginationQuery {
    #[serde(default = "default_page")]
    pub page: u32,
    #[serde(default = "default_limit")]
    pub limit: u32,
    pub search: Option<String>,
    pub inbound_tag: Option<String>,
    pub enabled: Option<bool>,
}

fn default_page() -> u32 {
    1
}
fn default_limit() -> u32 {
    50
}

/// Paginated response
#[derive(Debug, Clone, Serialize)]
pub struct PaginatedResponse<T> {
    pub data: Vec<T>,
    pub page: u32,
    pub limit: u32,
    pub total: u64,
    pub total_pages: u32,
}

/// User management state
pub struct UserManagementState {
    pub db: Arc<surrealdb::Surreal<surrealdb::engine::local::Db>>,
    pub traffic_store: Arc<crate::jobs::billing::TrafficStore>,
}

// ============================================================================
// API Handlers
// ============================================================================

/// List users with pagination and filtering
pub async fn list_users(
    state: web::Data<Arc<UserManagementState>>,
    query: web::Query<PaginationQuery>,
) -> HttpResponse {
    let offset = (query.page.saturating_sub(1)) * query.limit;

    // Build query based on filters
    let mut where_clauses = Vec::new();
    let mut params: Vec<(&str, serde_json::Value)> = Vec::new();

    if let Some(tag) = &query.inbound_tag {
        where_clauses.push("tag = $tag");
        params.push(("tag", serde_json::json!(tag)));
    }

    if let Some(search) = &query.search {
        where_clauses.push("settings.clients[*].email CONTAINS $search");
        params.push(("search", serde_json::json!(search)));
    }

    let where_clause = if where_clauses.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", where_clauses.join(" AND "))
    };

    // Execute query
    let query_str = format!(
        "SELECT * FROM inbound {} LIMIT {} START {}",
        where_clause, query.limit, offset
    );

    match state.db.query(&query_str).await {
        Ok(mut result) => {
            let inbounds: Vec<serde_json::Value> = result.take(0).unwrap_or_default();

            // Extract users from inbounds
            let mut users = Vec::new();
            for inbound in inbounds {
                let tag = inbound.get("tag").and_then(|v| v.as_str()).unwrap_or("");
                if let Some(settings) = inbound.get("settings") {
                    if let Some(clients) = settings.get("clients").and_then(|c| c.as_array()) {
                        for client in clients {
                            let user = UserDto {
                                id: client
                                    .get("id")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                email: client
                                    .get("email")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                inbound_tag: tag.to_string(),
                                enabled: client
                                    .get("enable")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(true),
                                upload_bytes: client
                                    .get("up")
                                    .and_then(|v| v.as_i64())
                                    .unwrap_or(0),
                                download_bytes: client
                                    .get("down")
                                    .and_then(|v| v.as_i64())
                                    .unwrap_or(0),
                                total_limit_gb: client
                                    .get("total_flow_limit")
                                    .and_then(|v| v.as_i64()),
                                expiry_time: client.get("expiry_time").and_then(|v| v.as_i64()),
                                created_at: 0,
                            };
                            users.push(user);
                        }
                    }
                }
            }

            let total = users.len() as u64;
            let total_pages = ((total as f64) / (query.limit as f64)).ceil() as u32;

            HttpResponse::Ok().json(PaginatedResponse {
                data: users,
                page: query.page,
                limit: query.limit,
                total,
                total_pages,
            })
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Get a single user by ID
pub async fn get_user(
    state: web::Data<Arc<UserManagementState>>,
    path: web::Path<String>,
) -> HttpResponse {
    let user_id = path.into_inner();

    let query = format!(
        "SELECT * FROM inbound WHERE settings.clients[*].id CONTAINS '{}'",
        user_id
    );

    match state.db.query(&query).await {
        Ok(mut result) => {
            let inbounds: Vec<serde_json::Value> = result.take(0).unwrap_or_default();

            for inbound in inbounds {
                let tag = inbound.get("tag").and_then(|v| v.as_str()).unwrap_or("");
                if let Some(settings) = inbound.get("settings") {
                    if let Some(clients) = settings.get("clients").and_then(|c| c.as_array()) {
                        for client in clients {
                            let id = client.get("id").and_then(|v| v.as_str()).unwrap_or("");
                            if id == user_id {
                                let user = UserDto {
                                    id: id.to_string(),
                                    email: client
                                        .get("email")
                                        .and_then(|v| v.as_str())
                                        .unwrap_or("")
                                        .to_string(),
                                    inbound_tag: tag.to_string(),
                                    enabled: client
                                        .get("enable")
                                        .and_then(|v| v.as_bool())
                                        .unwrap_or(true),
                                    upload_bytes: client
                                        .get("up")
                                        .and_then(|v| v.as_i64())
                                        .unwrap_or(0),
                                    download_bytes: client
                                        .get("down")
                                        .and_then(|v| v.as_i64())
                                        .unwrap_or(0),
                                    total_limit_gb: client
                                        .get("total_flow_limit")
                                        .and_then(|v| v.as_i64()),
                                    expiry_time: client.get("expiry_time").and_then(|v| v.as_i64()),
                                    created_at: 0,
                                };
                                return HttpResponse::Ok().json(user);
                            }
                        }
                    }
                }
            }

            HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"}))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Database error: {}", e)
        })),
    }
}

/// Create a new user
pub async fn create_user(
    state: web::Data<Arc<UserManagementState>>,
    body: web::Json<CreateUserRequest>,
) -> HttpResponse {
    let user_id = uuid::Uuid::new_v4().to_string();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let client = serde_json::json!({
        "id": user_id,
        "email": body.email,
        "enable": true,
        "up": 0,
        "down": 0,
        "total_flow_limit": body.total_limit_gb.unwrap_or(0),
        "expiry_time": body.expiry_time.unwrap_or(0),
    });

    let query = format!(
        "UPDATE inbound SET settings.clients += $client WHERE tag = '{}'",
        body.inbound_tag
    );

    match state.db.query(&query).bind(("client", client)).await {
        Ok(_) => {
            // Initialize traffic counter
            state.traffic_store.set_limits(
                &user_id,
                &body.inbound_tag,
                body.total_limit_gb.unwrap_or(0) * 1024 * 1024 * 1024,
                body.expiry_time.unwrap_or(0),
            );

            HttpResponse::Created().json(serde_json::json!({
                "id": user_id,
                "email": body.email,
                "inbound_tag": body.inbound_tag,
                "created_at": now,
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to create user: {}", e)
        })),
    }
}

/// Update a user
pub async fn update_user(
    state: web::Data<Arc<UserManagementState>>,
    path: web::Path<String>,
    body: web::Json<UpdateUserRequest>,
) -> HttpResponse {
    let user_id = path.into_inner();

    // Build update fields
    let mut updates = Vec::new();

    if let Some(email) = &body.email {
        updates.push(format!(
            "settings.clients[WHERE id = '{}'].email = '{}'",
            user_id, email
        ));
    }
    if let Some(enabled) = body.enabled {
        updates.push(format!(
            "settings.clients[WHERE id = '{}'].enable = {}",
            user_id, enabled
        ));
    }
    if let Some(limit) = body.total_limit_gb {
        updates.push(format!(
            "settings.clients[WHERE id = '{}'].total_flow_limit = {}",
            user_id, limit
        ));
    }
    if let Some(expiry) = body.expiry_time {
        updates.push(format!(
            "settings.clients[WHERE id = '{}'].expiry_time = {}",
            user_id, expiry
        ));
    }
    if body.reset_traffic == Some(true) {
        updates.push(format!("settings.clients[WHERE id = '{}'].up = 0", user_id));
        updates.push(format!(
            "settings.clients[WHERE id = '{}'].down = 0",
            user_id
        ));
    }

    if updates.is_empty() {
        return HttpResponse::BadRequest()
            .json(serde_json::json!({"error": "No fields to update"}));
    }

    let query = format!("UPDATE inbound SET {}", updates.join(", "));

    match state.db.query(&query).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "updated", "id": user_id})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to update user: {}", e)
        })),
    }
}

/// Delete a user
pub async fn delete_user(
    state: web::Data<Arc<UserManagementState>>,
    path: web::Path<String>,
) -> HttpResponse {
    let user_id = path.into_inner();

    let query = format!(
        "UPDATE inbound SET settings.clients -= settings.clients[WHERE id = '{}']",
        user_id
    );

    match state.db.query(&query).await {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "deleted", "id": user_id})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to delete user: {}", e)
        })),
    }
}

/// Bulk enable/disable users
#[derive(Debug, Deserialize)]
pub struct BulkUpdateRequest {
    pub user_ids: Vec<String>,
    pub enabled: bool,
}

pub async fn bulk_update_users(
    state: web::Data<Arc<UserManagementState>>,
    body: web::Json<BulkUpdateRequest>,
) -> HttpResponse {
    let mut success_count = 0;
    let mut error_count = 0;

    for user_id in &body.user_ids {
        let query = format!(
            "UPDATE inbound SET settings.clients[WHERE id = '{}'].enable = {}",
            user_id, body.enabled
        );

        match state.db.query(&query).await {
            Ok(_) => success_count += 1,
            Err(_) => error_count += 1,
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "success_count": success_count,
        "error_count": error_count,
    }))
}

/// Configure user routes
pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/api/users")
            .route("", web::get().to(list_users))
            .route("", web::post().to(create_user))
            .route("/bulk", web::post().to(bulk_update_users))
            .route("/{id}", web::get().to(get_user))
            .route("/{id}", web::put().to(update_user))
            .route("/{id}", web::delete().to(delete_user)),
    );
}
