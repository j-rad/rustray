// src/transport/manager.rs
//! Connection Manager with Happy Eyeballs v3
//!
//! Orchestrates multiple transport attempts and selects the most viable one.
//! Uses DashMap for thread-safe session tracking.

use crate::error::Result;
use crate::protocols::flow_trait::BoxedTrinityTransport;
use dashmap::DashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use tracing::{debug, info};

pub struct ConnectionManager {
    sessions: Arc<DashMap<String, BoxedTrinityTransport>>,
}

impl ConnectionManager {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
        }
    }

    /// Register a session
    pub fn register(&self, session_id: String, transport: BoxedTrinityTransport) {
        self.sessions.insert(session_id, transport);
    }

    /// Retrieve a session
    pub fn get_session(&self, session_id: &str) -> Option<BoxedTrinityTransport> {
        self.sessions.remove(session_id).map(|(_, v)| v)
    }

    /// Happy Eyeballs v3: Attempt multiple transports and return the first successful one.
    /// 
    /// Logic:
    /// 1. Start primary transport attempt.
    /// 2. If it doesn't succeed within `stagger_delay`, start secondary transport.
    /// 3. Return the first one that completes the handshake.
    pub async fn dial_happy_eyeballs<F1, F2>(
        &self,
        f1: F1,
        f2: F2,
        stagger_delay: Duration,
    ) -> Result<BoxedTrinityTransport>
    where
        F1: std::future::Future<Output = Result<BoxedTrinityTransport>> + Send + 'static,
        F2: std::future::Future<Output = Result<BoxedTrinityTransport>> + Send + 'static,
    {
        debug!("VTM: Starting Happy Eyeballs v3 dialing");

        let mut t1 = tokio::spawn(f1);
        
        // Wait for stagger delay or primary success
        let t1_res = tokio::select! {
            res = &mut t1 => Some(res),
            _ = tokio::time::sleep(stagger_delay) => None,
        };

        if let Some(Ok(Ok(transport))) = t1_res {
            info!("VTM: Primary transport succeeded immediately");
            return Ok(transport);
        }

        debug!("VTM: Stagger delay reached or primary failed, starting secondary transport");
        let mut t2 = tokio::spawn(f2);

        // Race them
        tokio::select! {
            res1 = &mut t1 => {
                match res1 {
                    Ok(Ok(transport)) => {
                        info!("VTM: Primary transport won the race");
                        Ok(transport)
                    }
                    _ => {
                        debug!("VTM: Primary failed, waiting for secondary");
                        match t2.await {
                            Ok(res) => res,
                            Err(e) => Err(anyhow::anyhow!("Secondary task joined with error: {}", e)),
                        }
                    }
                }
            }
            res2 = &mut t2 => {
                match res2 {
                    Ok(Ok(transport)) => {
                        info!("VTM: Secondary transport won the race");
                        Ok(transport)
                    }
                    _ => {
                        debug!("VTM: Secondary failed, waiting for primary");
                        match t1.await {
                            Ok(res) => res,
                            Err(e) => Err(anyhow::anyhow!("Primary task joined with error: {}", e)),
                        }
                    }
                }
            }
        }
    }
}
