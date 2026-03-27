// rustray/src/api/auth_middleware.rs
//! JWT-Based Session Authentication Middleware
//!
//! Provides secure session management for the headless API:
//! - JWT token generation and validation
//! - Session storage with configurable expiry
//! - Token refresh mechanism
//! - Thread-safe session tracking via dashmap

use actix_web::{
    Error, HttpRequest, HttpResponse,
    dev::{ServiceRequest, ServiceResponse},
    http::header,
    web,
};
use dashmap::DashMap;
use futures::Future;
use futures::future::{Ready, ok};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use base64::{Engine as _, engine::general_purpose};

type HmacSha256 = Hmac<Sha256>;

/// Session token with metadata
#[derive(Clone, Debug)]
pub struct Session {
    pub user_id: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub refresh_token: String,
}

/// Thread-safe session store
pub struct SessionStore {
    sessions: DashMap<String, Session>,
    secret_key: Vec<u8>,
    token_ttl: Duration,
    refresh_ttl: Duration,
}

impl SessionStore {
    pub fn new(secret_key: &str) -> Self {
        Self {
            sessions: DashMap::new(),
            secret_key: secret_key.as_bytes().to_vec(),
            token_ttl: Duration::from_secs(3600), // 1 hour
            refresh_ttl: Duration::from_secs(86400 * 7), // 7 days
        }
    }

    /// Generate a new session token for authenticated user
    pub fn create_session(&self, user_id: &str) -> Result<(String, String), AuthError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AuthError::InternalError)?
            .as_secs();

        let token = self.generate_token(user_id, now, self.token_ttl.as_secs())?;
        let refresh = self.generate_refresh_token(user_id, now)?;

        let session = Session {
            user_id: user_id.to_string(),
            created_at: now,
            expires_at: now + self.token_ttl.as_secs(),
            refresh_token: refresh.clone(),
        };

        self.sessions.insert(token.clone(), session);
        Ok((token, refresh))
    }

    /// Validate an access token and return the session
    pub fn validate_token(&self, token: &str) -> Result<Session, AuthError> {
        let session = self.sessions.get(token).ok_or(AuthError::InvalidToken)?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| AuthError::InternalError)?
            .as_secs();

        if now > session.expires_at {
            self.sessions.remove(token);
            return Err(AuthError::TokenExpired);
        }

        Ok(session.clone())
    }

    /// Refresh an expired token using refresh token
    pub fn refresh_session(&self, refresh_token: &str) -> Result<(String, String), AuthError> {
        // Find session by refresh token
        let mut found_key = None;
        let mut user_id = String::new();

        for entry in self.sessions.iter() {
            if entry.value().refresh_token == refresh_token {
                found_key = Some(entry.key().clone());
                user_id = entry.value().user_id.clone();
                break;
            }
        }

        if let Some(old_token) = found_key {
            self.sessions.remove(&old_token);
            self.create_session(&user_id)
        } else {
            Err(AuthError::InvalidRefreshToken)
        }
    }

    /// Revoke a session
    pub fn revoke_session(&self, token: &str) {
        self.sessions.remove(token);
    }

    /// Clean up expired sessions (call periodically)
    pub fn cleanup_expired(&self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.sessions.retain(|_, session| session.expires_at > now);
    }

    fn generate_token(&self, user_id: &str, timestamp: u64, ttl: u64) -> Result<String, AuthError> {
        let payload = format!("{}:{}:{}", user_id, timestamp, timestamp + ttl);
        let mut mac =
            HmacSha256::new_from_slice(&self.secret_key).map_err(|_| AuthError::InternalError)?;
        mac.update(payload.as_bytes());
        let signature = mac.finalize().into_bytes();
        Ok(format!(
            "{}.{}",
            general_purpose::STANDARD.encode(&payload),
            general_purpose::STANDARD.encode(signature)
        ))
    }

    fn generate_refresh_token(&self, user_id: &str, timestamp: u64) -> Result<String, AuthError> {
        let payload = format!("refresh:{}:{}", user_id, timestamp);
        let mut mac =
            HmacSha256::new_from_slice(&self.secret_key).map_err(|_| AuthError::InternalError)?;
        mac.update(payload.as_bytes());
        let signature = mac.finalize().into_bytes();
        Ok(general_purpose::STANDARD.encode(signature))
    }
}

/// Authentication errors
#[derive(Debug, Clone)]
pub enum AuthError {
    InvalidToken,
    TokenExpired,
    InvalidRefreshToken,
    InvalidCredentials,
    InternalError,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::InvalidToken => write!(f, "Invalid authentication token"),
            AuthError::TokenExpired => write!(f, "Token has expired"),
            AuthError::InvalidRefreshToken => write!(f, "Invalid refresh token"),
            AuthError::InvalidCredentials => write!(f, "Invalid credentials"),
            AuthError::InternalError => write!(f, "Internal authentication error"),
        }
    }
}

/// Auth configuration for the API
pub struct AuthConfig {
    pub session_store: Arc<SessionStore>,
    pub psk: String, // Legacy PSK for initial login
}

/// JWT Authentication Middleware
pub struct AuthMiddleware {
    pub config: Arc<AuthConfig>,
}

impl<S, B> actix_web::dev::Transform<S, ServiceRequest> for AuthMiddleware
where
    S: actix_web::dev::Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<actix_web::body::EitherBody<B>>;
    type Error = Error;
    type Transform = AuthService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(AuthService {
            service,
            config: self.config.clone(),
        })
    }
}

pub struct AuthService<S> {
    service: S,
    config: Arc<AuthConfig>,
}

impl<S, B> actix_web::dev::Service<ServiceRequest> for AuthService<S>
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

        // Skip auth for public endpoints
        let is_public = path == "/health"
            || path == "/"
            || path.starts_with("/assets")
            || path.ends_with(".js")
            || path.ends_with(".css")
            || path.ends_with(".wasm")
            || path.ends_with(".html")
            || path == "/api/auth/login";

        if is_public {
            let fut = self.service.call(req);
            return Box::pin(async move {
                let res = fut.await?;
                Ok(res.map_into_left_body())
            });
        }

        // Check for Bearer token or legacy PSK
        let auth_header = req.headers().get(header::AUTHORIZATION);
        let psk_header = req.headers().get("X-RUSTRAY-PSK");

        let is_authenticated = if let Some(auth_val) = auth_header {
            if let Ok(auth_str) = auth_val.to_str() {
                if let Some(token) = auth_str.strip_prefix("Bearer ") {
                    self.config.session_store.validate_token(token).is_ok()
                } else {
                    false
                }
            } else {
                false
            }
        } else if let Some(psk_val) = psk_header {
            // Legacy PSK support
            if let Ok(psk_str) = psk_val.to_str() {
                psk_str == self.config.psk
            } else {
                false
            }
        } else {
            false
        };

        if !is_authenticated {
            return Box::pin(async {
                Ok(req.into_response(
                    HttpResponse::Unauthorized()
                        .json(serde_json::json!({"error": "Authentication required"}))
                        .map_into_right_body(),
                ))
            });
        }

        let fut = self.service.call(req);
        Box::pin(async move {
            let res = fut.await?;
            Ok(res.map_into_left_body())
        })
    }
}

// ============================================================================
// Auth API Handlers
// ============================================================================

#[derive(serde::Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(serde::Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
}

#[derive(serde::Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

/// Login endpoint - authenticates with username/password or PSK
pub async fn login(
    config: web::Data<Arc<AuthConfig>>,
    credentials: web::Json<LoginRequest>,
) -> HttpResponse {
    // Validate credentials against PSK (username is ignored for now)
    // In production, this would check against a user database
    if credentials.password != config.psk {
        return HttpResponse::Unauthorized()
            .json(serde_json::json!({"error": "Invalid credentials"}));
    }

    match config.session_store.create_session(&credentials.username) {
        Ok((access_token, refresh_token)) => HttpResponse::Ok().json(LoginResponse {
            access_token,
            refresh_token,
            expires_in: 3600,
        }),
        Err(e) => {
            HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}))
        }
    }
}

/// Refresh token endpoint
pub async fn refresh(
    config: web::Data<Arc<AuthConfig>>,
    body: web::Json<RefreshRequest>,
) -> HttpResponse {
    match config.session_store.refresh_session(&body.refresh_token) {
        Ok((access_token, refresh_token)) => HttpResponse::Ok().json(LoginResponse {
            access_token,
            refresh_token,
            expires_in: 3600,
        }),
        Err(e) => HttpResponse::Unauthorized().json(serde_json::json!({"error": e.to_string()})),
    }
}

/// Logout endpoint - revokes session
pub async fn logout(req: HttpRequest, config: web::Data<Arc<AuthConfig>>) -> HttpResponse {
    if let Some(auth_val) = req.headers().get(header::AUTHORIZATION)
        && let Ok(auth_str) = auth_val.to_str()
            && let Some(token) = auth_str.strip_prefix("Bearer ") {
                config.session_store.revoke_session(token);
            }
    HttpResponse::Ok().json(serde_json::json!({"status": "logged_out"}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_lifecycle() {
        let store = SessionStore::new("test_secret_key_32_bytes_long!!");

        // Create session
        let (token, refresh) = store.create_session("admin").unwrap();
        assert!(!token.is_empty());
        assert!(!refresh.is_empty());

        // Validate token
        let session = store.validate_token(&token).unwrap();
        assert_eq!(session.user_id, "admin");

        // Revoke session
        store.revoke_session(&token);
        assert!(store.validate_token(&token).is_err());
    }

    #[test]
    fn test_invalid_token() {
        let store = SessionStore::new("test_secret_key_32_bytes_long!!");
        assert!(store.validate_token("invalid_token").is_err());
    }
}
