// src/core/instance.rs
use crate::core::registry::GLOBAL_REGISTRY;
use crate::inbounds::Inbound;
use crate::error::Result;
use std::sync::Arc;
use tracing::{info, error};
use tokio::task::JoinHandle;

pub struct RustrayInstance {
    tasks: Vec<JoinHandle<Result<()>>>,
}

impl RustrayInstance {
    pub fn new() -> Self {
        Self { tasks: Vec::new() }
    }

    pub async fn start(&mut self, config: crate::config::Config) -> Result<()> {
        info!("Rustray: Starting instance with modular core");

        // 1. Initialize Inbounds
        if let Some(inbounds) = config.inbounds {
            for inbound_conf in inbounds {
                let registry = GLOBAL_REGISTRY.clone();
                // Convert config to JSON value for factory
                let conf_val = serde_json::to_value(&inbound_conf)?;
                let inbound_name = inbound_conf.protocol.clone();

                let task = tokio::spawn(async move {
                    let inbound = registry.create_inbound(&inbound_name, conf_val)?;
                    inbound.listen().await
                });
                self.tasks.push(task);
            }
        }

        info!("Rustray: {} inbounds active", self.tasks.len());
        Ok(())
    }

    pub async fn wait_for_shutdown(&mut self) {
        for task in self.tasks.drain(..) {
            if let Err(e) = task.await {
                error!("Instance task panicked or failed: {:?}", e);
            }
        }
    }
}
