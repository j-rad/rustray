// src/p2p/conduit.rs
//! Conduit Bridge — Zero-copy bidirectional relay between two streams.
//!
//! Bridges an incoming peer connection to an outgoing target connection,
//! using a fixed-size buffer for minimal allocation and maximum throughput.

use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::debug;

/// Buffer size for each direction of the bridge (64 KiB).
const BRIDGE_BUF_SIZE: usize = 65536;

/// Bidirectional bridge that relays data between two async streams.
pub struct ConduitBridge;

impl ConduitBridge {
    /// Bridge two streams bidirectionally until either side closes or errors.
    /// Returns the total bytes transferred in each direction (a_to_b, b_to_a).
    pub async fn bridge<A, B>(a: A, b: B) -> io::Result<(u64, u64)>
    where
        A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
        B: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut a_read, mut a_write) = tokio::io::split(a);
        let (mut b_read, mut b_write) = tokio::io::split(b);

        let a_to_b = tokio::spawn(async move {
            let mut buf = vec![0u8; BRIDGE_BUF_SIZE];
            let mut total: u64 = 0;
            loop {
                match a_read.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if b_write.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                        total += n as u64;
                    }
                    Err(_) => break,
                }
            }
            let _ = b_write.shutdown().await;
            total
        });

        let b_to_a = tokio::spawn(async move {
            let mut buf = vec![0u8; BRIDGE_BUF_SIZE];
            let mut total: u64 = 0;
            loop {
                match b_read.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        if a_write.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                        total += n as u64;
                    }
                    Err(_) => break,
                }
            }
            let _ = a_write.shutdown().await;
            total
        });

        let (a2b_result, b2a_result) = tokio::join!(a_to_b, b_to_a);
        let a2b = a2b_result.unwrap_or(0);
        let b2a = b2a_result.unwrap_or(0);

        debug!("ConduitBridge: A->B={} bytes, B->A={} bytes", a2b, b2a);
        Ok((a2b, b2a))
    }
}
