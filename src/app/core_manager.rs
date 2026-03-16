// src/app/core_manager.rs
//! Core Manager for RustRay
//!
//! Handles lifecycle, updates, and asset management for the RustRay engine.

use crate::app::platform_paths;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
use tracing::info;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CoreType {
    RustRay,
}

impl CoreType {
    pub fn repo(&self) -> &str {
        match self {
            CoreType::RustRay => "FaezBarghasa/rustray",
        }
    }

    pub fn binary_name(&self) -> &str {
        match self {
            CoreType::RustRay => "rustray",
        }
    }
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

pub struct CoreManager {
    app_id: String,
    client: reqwest::Client,
}

impl CoreManager {
    pub fn new(app_id: impl Into<String>) -> Self {
        Self {
            app_id: app_id.into(),
            client: reqwest::Client::builder()
                .user_agent("EdgeRay-CoreManager/1.0")
                .build()
                .unwrap_or_default(),
        }
    }

    /// Get current local version of a core
    pub async fn get_local_version(&self, core_type: CoreType) -> Option<String> {
        let bin_path = platform_paths::get_bin_path(&self.app_id, core_type.binary_name());
        if !bin_path.exists() {
            return None;
        }

        // We could run `core --version` here, but for simplicity we rely on stored metadata
        // For now, let's just check if it exists
        Some("installed".to_string())
    }

    /// Fetch latest version tag from GitHub
    pub async fn fetch_latest_version(&self, core_type: CoreType) -> Result<String> {
        let url = format!(
            "https://api.github.com/repos/{}/releases/latest",
            core_type.repo()
        );
        let release: GithubRelease = self.client.get(url).send().await?.json().await?;
        Ok(release.tag_name)
    }

    /// Download and update a core to the latest version
    pub async fn update_core(&self, core_type: CoreType) -> Result<String> {
        info!("Checking for {} updates...", core_type.binary_name());

        let url = format!(
            "https://api.github.com/repos/{}/releases/latest",
            core_type.repo()
        );
        let release: GithubRelease = self.client.get(url).send().await?.json().await?;

        let asset = self
            .select_asset(core_type, &release.assets)
            .context("No suitable asset found for current platform")?;

        info!(
            "Downloading {} from {}...",
            release.tag_name, asset.browser_download_url
        );

        let response = self.client.get(&asset.browser_download_url).send().await?;
        let bytes = response.bytes().await?;

        let temp_dir = tempfile::tempdir()?;
        let archive_path = temp_dir.path().join(&asset.name);
        std::fs::write(&archive_path, bytes)?;

        let dest_path = platform_paths::get_bin_path(&self.app_id, core_type.binary_name());
        self.extract_and_install(&archive_path, &dest_path, core_type)?;

        info!(
            "{} updated to {}",
            core_type.binary_name(),
            release.tag_name
        );
        Ok(release.tag_name)
    }

    fn select_asset<'a>(
        &self,
        core_type: CoreType,
        assets: &'a [GithubAsset],
    ) -> Option<&'a GithubAsset> {
        let os = std::env::consts::OS;
        let arch = std::env::consts::ARCH;

        // Simplify arch naming
        let rustray_arch = match arch {
            "x86_64" => "64",
            "aarch64" => "arm64-v8a",
            "arm" => "arm32-v7a",
            _ => arch,
        };

        match core_type {
            CoreType::RustRay => {
                // RustRay naming: rustray-linux-64.zip, rustray-windows-64.zip, rustray-android-arm64-v8a.zip
                let target = format!("{}-{}", os, rustray_arch);
                assets.iter().find(|a| {
                    a.name.to_lowercase().contains(&target.to_lowercase())
                        && a.name.ends_with(".zip")
                })
            }
        }
    }

    fn extract_and_install(&self, archive: &Path, dest: &Path, core_type: CoreType) -> Result<()> {
        let bin_name = core_type.binary_name();
        let _parent = dest.parent().context("Invalid dest path")?;

        if archive.extension().map_or(false, |e| e == "zip") {
            let file = std::fs::File::open(archive)?;
            let mut zip = zip::ZipArchive::new(file)?;

            for i in 0..zip.len() {
                let mut file = zip.by_index(i)?;
                if file.name().ends_with(bin_name)
                    || file.name().ends_with(&format!("{}.exe", bin_name))
                {
                    let mut out = std::fs::File::create(dest)?;
                    std::io::copy(&mut file, &mut out)?;

                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o755))?;
                    }
                    return Ok(());
                }
            }
        } else if archive.extension().map_or(false, |e| e == "gz") {
            // Assume .tar.gz
            let file = std::fs::File::open(archive)?;
            let tar = flate2::read::GzDecoder::new(file);
            let mut archive = tar::Archive::new(tar);

            for entry in archive.entries()? {
                let mut entry: tar::Entry<_> = entry?;
                let path = entry.path()?.to_path_buf();
                if path.file_name().map_or(false, |f| f == bin_name) {
                    entry.unpack(dest)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(dest, std::fs::Permissions::from_mode(0o755))?;
                    }
                    return Ok(());
                }
            }
        }

        Err(anyhow::anyhow!("Binary not found in archive"))
    }
}
