// src/transport/fragmentation.rs
use crate::error::Result;
use crate::transport::flow_trait::TrinityTransport;
use tokio::io::AsyncWriteExt;
use std::time::Duration;
use rand::Rng;

/// 1-byte fragmentation to defeat stateful SNI inspection.
pub async fn split_handshake<T: TrinityTransport>(mut stream: T, handshake_data: &[u8]) -> Result<T> {
    if handshake_data.is_empty() {
        return Ok(stream);
    }

    // 1. Write exactly 1 byte
    stream.write_all(&handshake_data[..1]).await?;
    stream.flush().await?;

    // 2. Wait for a randomized delay (5-15ms)
    let delay = rand::thread_rng().gen_range(5..=15);
    tokio::time::sleep(Duration::from_millis(delay)).await;

    // 3. Write the rest
    if handshake_data.len() > 1 {
        stream.write_all(&handshake_data[1..]).await?;
        stream.flush().await?;
    }

    Ok(stream)
}
