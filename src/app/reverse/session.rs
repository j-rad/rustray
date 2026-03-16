// src/app/reverse/session.rs
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// Session Token for Resumption
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionToken {
    pub id: Uuid,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
}

impl SessionToken {
    /// Create a new session token with a given Time-To-Live (TTL)
    pub fn new(ttl: Duration) -> Self {
        let now = SystemTime::now();
        Self {
            id: Uuid::new_v4(),
            created_at: now,
            expires_at: now + ttl,
        }
    }

    /// Check if the token is still valid (not expired)
    pub fn is_valid(&self) -> bool {
        SystemTime::now() < self.expires_at
    }
}
