// rustray/src/api/audit_middleware.rs
//! Audit Logging Middleware
//!
//! Logs all administrative actions for security auditing.
//! Records are stored in SurrealDB and can be queried via API.

use actix_web::{
    Error, HttpResponse,
    dev::{ServiceRequest, ServiceResponse},
    http::Method,
    web,
};
use dashmap::DashMap;
use futures::Future;
use futures::future::{Ready, ok};
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Audit log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: String,
    pub timestamp: i64,
    pub user_id: String,
    pub action: String,
    pub path: String,
    pub method: String,
    pub status: u16,
    pub ip_address: String,
    pub user_agent: Option<String>,
    pub request_body: Option<String>,
    pub duration_ms: u64,
}

/// Audit log store
pub struct AuditStore {
    entries: DashMap<String, AuditEntry>,
    max_entries: usize,
    db: Option<Arc<surrealdb::Surreal<surrealdb::engine::local::Db>>>,
}

impl AuditStore {
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: DashMap::new(),
            max_entries,
            db: None,
        }
    }

    pub fn with_db(mut self, db: Arc<surrealdb::Surreal<surrealdb::engine::local::Db>>) -> Self {
        self.db = Some(db);
        self
    }

    /// Log an audit entry
    pub async fn log(&self, entry: AuditEntry) {
        let id = entry.id.clone();

        // Log to memory
        if self.entries.len() >= self.max_entries {
            // Remove oldest entries (simple eviction)
            let mut oldest_key = None;
            let mut oldest_time = i64::MAX;
            for entry in self.entries.iter() {
                if entry.timestamp < oldest_time {
                    oldest_time = entry.timestamp;
                    oldest_key = Some(entry.key().clone());
                }
            }
            if let Some(key) = oldest_key {
                self.entries.remove(&key);
            }
        }
        self.entries.insert(id.clone(), entry.clone());

        // Persist to database
        if let Some(db) = &self.db {
            let _ = db
                .query("CREATE audit_log CONTENT $entry")
                .bind(("entry", entry))
                .await;
        }
    }

    /// Get recent entries
    pub fn get_recent(&self, count: usize) -> Vec<AuditEntry> {
        let mut entries: Vec<_> = self.entries.iter().map(|e| e.value().clone()).collect();
        entries.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        entries.truncate(count);
        entries
    }

    /// Search entries
    pub fn search(
        &self,
        user_id: Option<&str>,
        action: Option<&str>,
        limit: usize,
    ) -> Vec<AuditEntry> {
        let mut results: Vec<_> = self
            .entries
            .iter()
            .filter(|e| {
                let user_match = user_id.map_or(true, |u| e.user_id == u);
                let action_match = action.map_or(true, |a| e.action.contains(a));
                user_match && action_match
            })
            .map(|e| e.value().clone())
            .collect();

        results.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));
        results.truncate(limit);
        results
    }
}

/// Audit middleware
pub struct AuditMiddleware {
    pub store: Arc<AuditStore>,
}

impl<S, B> actix_web::dev::Transform<S, ServiceRequest> for AuditMiddleware
where
    S: actix_web::dev::Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<actix_web::body::EitherBody<B>>;
    type Error = Error;
    type Transform = AuditService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuditService {
            service,
            store: self.store.clone(),
        })
    }
}

pub struct AuditService<S> {
    service: S,
    store: Arc<AuditStore>,
}

impl<S, B> actix_web::dev::Service<ServiceRequest> for AuditService<S>
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
        let path = req.path().to_string();
        let method = req.method().clone();

        // Only audit write operations on API endpoints
        let should_audit = path.starts_with("/api/")
            && (method == Method::POST || method == Method::PUT || method == Method::DELETE);

        if !should_audit {
            let fut = self.service.call(req);
            return Box::pin(async move {
                let res = fut.await?;
                Ok(res.map_into_left_body())
            });
        }

        let start = std::time::Instant::now();
        let store = self.store.clone();

        // Extract request info before calling service
        let user_id = req
            .headers()
            .get("X-User-ID")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("anonymous")
            .to_string();

        let ip_address = req
            .connection_info()
            .peer_addr()
            .unwrap_or("unknown")
            .to_string();

        let user_agent = req
            .headers()
            .get("User-Agent")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let method_str = method.to_string();

        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;
            let status = res.status().as_u16();
            let duration = start.elapsed().as_millis() as u64;

            let action = match method_str.as_str() {
                "POST" => "create",
                "PUT" => "update",
                "DELETE" => "delete",
                _ => "unknown",
            };

            let entry = AuditEntry {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64,
                user_id,
                action: action.to_string(),
                path,
                method: method_str,
                status,
                ip_address,
                user_agent,
                request_body: None,
                duration_ms: duration,
            };

            store.log(entry).await;

            Ok(res.map_into_left_body())
        })
    }
}

// ============================================================================
// Audit API Handlers
// ============================================================================

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    #[serde(default = "default_limit")]
    pub limit: usize,
    pub user_id: Option<String>,
    pub action: Option<String>,
}

fn default_limit() -> usize {
    100
}

pub async fn get_audit_logs(
    store: web::Data<Arc<AuditStore>>,
    query: web::Query<AuditQuery>,
) -> HttpResponse {
    let entries = store.search(
        query.user_id.as_deref(),
        query.action.as_deref(),
        query.limit,
    );

    HttpResponse::Ok().json(serde_json::json!({
        "entries": entries,
        "count": entries.len(),
    }))
}

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(web::scope("/api/audit").route("", web::get().to(get_audit_logs)));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_store() {
        let store = AuditStore::new(100);

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            store
                .log(AuditEntry {
                    id: "test1".to_string(),
                    timestamp: 1000,
                    user_id: "admin".to_string(),
                    action: "create".to_string(),
                    path: "/api/users".to_string(),
                    method: "POST".to_string(),
                    status: 201,
                    ip_address: "127.0.0.1".to_string(),
                    user_agent: None,
                    request_body: None,
                    duration_ms: 50,
                })
                .await;
        });

        let recent = store.get_recent(10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].user_id, "admin");
    }
}
