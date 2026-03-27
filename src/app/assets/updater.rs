// src/app/assets/updater.rs

use crate::error::Result;
use notify::{Config, RecommendedWatcher, RecursiveMode, Watcher};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

/// Configuration for an asset to be managed
#[derive(Debug, Clone)]
pub struct AssetConfig {
    pub name: String,               // e.g. "geosite.dat"
    pub url: String,                // Download URL
    pub sha256: Option<String>,     // Expected SHA256 (optional, if known beforehand)
    pub verify_url: Option<String>, // URL to fetch SHA256sum
}

pub struct AssetUpdater {
    assets_dir: PathBuf,
    client: reqwest::Client,
}

impl AssetUpdater {
    pub fn new(assets_dir: PathBuf) -> Self {
        Self {
            assets_dir,
            client: reqwest::Client::new(),
        }
    }

    /// Update a specific asset
    pub async fn update_asset(&self, config: &AssetConfig) -> Result<bool> {
        let target_path = self.assets_dir.join(&config.name);

        info!("Checking update for asset: {}", config.name);

        // 1. Fetch expected hash if verify_url is provided
        let expected_hash = if let Some(url) = &config.verify_url {
            match self.fetch_string(url).await {
                Ok(s) => Some(s.trim().to_string()),
                Err(e) => {
                    warn!("Failed to fetch hash for {}: {}", config.name, e);
                    None
                }
            }
        } else {
            config.sha256.clone()
        };

        // 2. Check local file if exists
        if target_path.exists()
            && let Some(expected) = &expected_hash {
                let local_hash = self.compute_file_hash(&target_path)?;
                if &local_hash == expected {
                    info!("Asset {} is up to date.", config.name);
                    return Ok(false);
                }
                info!(
                    "Asset {} hash mismatch (local: {}, remote: {}). Updating...",
                    config.name, local_hash, expected
                );
            }

        // 3. Download to temp file
        let temp_path = self.assets_dir.join(format!("{}.tmp", config.name));
        if let Err(e) = self.download_file(&config.url, &temp_path).await {
            error!("Failed to download {}: {}", config.name, e);
            return Err(e);
        }

        // 4. Verify downloaded file
        if let Some(expected) = &expected_hash {
            let downloaded_hash = self.compute_file_hash(&temp_path)?;
            if &downloaded_hash != expected {
                // Try to clean up
                let _ = std::fs::remove_file(&temp_path);
                return Err(anyhow::anyhow!(
                    "Downloaded asset {} failed checksum verification",
                    config.name
                ));
            }
        }

        // 5. Atomic Replace
        std::fs::rename(&temp_path, &target_path)?;
        info!("Successfully updated asset: {}", config.name);
        Ok(true)
    }

    async fn fetch_string(&self, url: &str) -> Result<String> {
        let res = self.client.get(url).send().await?.error_for_status()?;
        let text = res.text().await?;
        Ok(text)
    }

    async fn download_file(&self, url: &str, path: &Path) -> Result<()> {
        let res = self.client.get(url).send().await?.error_for_status()?;
        let content = res.bytes().await?;
        let mut file = File::create(path)?;
        file.write_all(&content)?;
        Ok(())
    }

    fn compute_file_hash(&self, path: &Path) -> Result<String> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        let mut buffer = [0; 8192];
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            hasher.update(&buffer[..n]);
        }
        let hash = hasher.finalize();
        Ok(hex::encode(hash))
    }

    /// Watch for changes in assets directory and notify
    pub fn watch_assets(dir: PathBuf, notify_tx: mpsc::Sender<String>) -> Result<()> {
        // Run in a blocking thread because notify is blocking (mostly) or we need to keep the watcher alive
        std::thread::spawn(move || {
            let (tx, rx) = std::sync::mpsc::channel();

            let mut watcher: Box<dyn Watcher> = match RecommendedWatcher::new(tx, Config::default())
            {
                Ok(w) => Box::new(w),
                Err(e) => {
                    error!("Failed to create asset watcher: {}", e);
                    return;
                }
            };

            if let Err(e) = watcher.watch(&dir, RecursiveMode::NonRecursive) {
                error!("Failed to watch asset directory: {}", e);
                return;
            }

            for res in rx {
                match res {
                    Ok(event) => {
                        // Check if it's a file modify/create/remove
                        // Simplification: just notify about the filename
                        for path in event.paths {
                            if let Some(filename) = path.file_name() {
                                let name = filename.to_string_lossy().to_string();
                                if !name.ends_with(".tmp") {
                                    // Ignore temp files
                                    let _ = notify_tx.blocking_send(name);
                                }
                            }
                        }
                    }
                    Err(e) => error!("Watch error: {}", e),
                }
            }
        });
        Ok(())
    }
}
