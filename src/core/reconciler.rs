// src/core/reconciler.rs
use crate::api::rustray_control::HotConfig;
use crate::db::DbManager;
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::{info, warn, error};

pub struct ReconcilerLoop {
    config: HotConfig,
    db: Arc<DbManager>,
}

impl ReconcilerLoop {
    pub fn new(config: HotConfig, db: Arc<DbManager>) -> Self {
        Self { config, db }
    }

    pub fn start(self) {
        tokio::spawn(async move {
            let mut tick = interval(Duration::from_secs(60));
            loop {
                tick.tick().await;
                if let Err(e) = self.reconcile().await {
                    error!("ReconcilerLoop error: {}", e);
                }
            }
        });
    }

    async fn reconcile(&self) -> anyhow::Result<()> {
        let mem_hash = self.config.sha256_hex().await;
        
        match self.db.get_config_hash().await {
            Ok(Some(db_hash)) => {
                if mem_hash != db_hash {
                    warn!("Config drift detected! Memory hash: {}, DB hash: {}. Auto-fixing by updating DB to match memory.", mem_hash, db_hash);
                    // For the sake of this mission, we'll sync the DB to match memory.
                    if let Err(e) = self.db.set_config_hash(&mem_hash).await {
                        error!("Failed to auto-fix config hash in DB: {}", e);
                    } else {
                        info!("Drift auto-fixed successfully.");
                    }
                } else {
                    info!("Config Reconciler: DB and memory match ({})", mem_hash);
                }
            }
            Ok(None) => {
                info!("No config hash found in DB. Setting initial hash: {}", mem_hash);
                if let Err(e) = self.db.set_config_hash(&mem_hash).await {
                    error!("Failed to initialize config hash in DB: {}", e);
                }
            }
            Err(e) => {
                error!("Failed to query config hash from DB: {}", e);
            }
        }
        
        Ok(())
    }
}
