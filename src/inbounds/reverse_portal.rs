// src/inbounds/reverse_portal.rs
use crate::app::reverse::ReverseManager;
use crate::config::ReversePortalSettings;
use crate::error::Result;
use crate::transport::BoxedStream;
use std::sync::Arc;

pub async fn listen_stream_tcp(
    reverse_manager: Arc<ReverseManager>,
    client_stream: BoxedStream,
    _settings: ReversePortalSettings,
    tag: &str,
    source: String,
) -> Result<()> {
    reverse_manager.register_portal(tag, client_stream);
    // Keep the task alive?
    // register_portal spawns a tokio task.
    // The scope here returns immediately.
    // If we return, the connection (client_stream) is moved into register_portal.
    // So we just return Ok(()).
    Ok(())
}
