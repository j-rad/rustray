// src/adapters/uds_manager.rs

use std::fs;
use std::path::{Path, PathBuf};
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tracing::{debug, info, warn};

/// Manages Unix Domain Sockets with self-healing rebinding.
pub struct UdsManager {
    socket_path: PathBuf,
}

impl UdsManager {
    /// Create a new UDS string, checking for and removing stale sockets on startup.
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            socket_path: path.as_ref().to_path_buf(),
        }
    }

    /// Bind to the Unix socket, unlinking any stale socket file that prevents binding.
    pub fn bind(&self) -> std::io::Result<UnixListenerStream> {
        let path = &self.socket_path;

        // Self-healing: Pre-flight check for stale socket
        if path.exists()
            && let Ok(_metadata) = fs::metadata(path) {
                // If it's a socket or even a regular file that shouldn't be here, try to remove it
                debug!("Stale socket found at {:?}, unlinking...", path);
                if let Err(e) = fs::remove_file(path) {
                    warn!("Failed to unlink stale socket at {:?}: {}", path, e);
                } else {
                    info!("Successfully unlinked stale socket at {:?}", path);
                }
            }

        // Ensure parent directory exists
        if let Some(parent) = path.parent()
            && !parent.exists() {
                fs::create_dir_all(parent)?;
            }

        let listener = UnixListener::bind(path)?;
        info!("UDS Listener successfully bound to {:?}", path);

        Ok(UnixListenerStream::new(listener))
    }
}
