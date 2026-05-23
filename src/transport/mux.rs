use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use serde::{Serialize, Deserialize};
use chacha20poly1305::{XChaCha20Poly1305, Key, XNonce};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use crate::error::Result;
use crate::transport::BoxedStream;
use tracing::{debug, error};

#[derive(Serialize, Deserialize, Debug)]
pub enum MuxFrame {
    OpenStream { id: u32, host: String, port: u16 },
    Data { id: u32, payload: Vec<u8> },
    CloseStream { id: u32 },
}

pub struct Mux2Session {
    cipher: XChaCha20Poly1305,
    rx_nonce: u64,
    tx_nonce: u64,
}

impl Mux2Session {
    pub fn new(key: [u8; 32]) -> Self {
        Self {
            cipher: XChaCha20Poly1305::new(Key::from_slice(&key)),
            rx_nonce: 0,
            tx_nonce: 0,
        }
    }

    fn generate_nonce(counter: u64) -> XNonce {
        let mut nonce_bytes = [0u8; 24];
        nonce_bytes[16..24].copy_from_slice(&counter.to_le_bytes());
        *XNonce::from_slice(&nonce_bytes)
    }

    pub async fn read_frame(&mut self, stream: &mut BoxedStream) -> Result<MuxFrame> {
        let mut len_buf = [0u8; 2];
        stream.read_exact(&mut len_buf).await?;
        let len = u16::from_be_bytes(len_buf) as usize;

        let mut cipher_buf = vec![0u8; len];
        stream.read_exact(&mut cipher_buf).await?;

        let nonce = Self::generate_nonce(self.rx_nonce);
        self.rx_nonce += 1;

        let plain_bytes = self.cipher.decrypt(&nonce, cipher_buf.as_ref())
            .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;

        let frame: MuxFrame = postcard::from_bytes(&plain_bytes)
            .map_err(|e| anyhow::anyhow!("Postcard deserialization failed: {:?}", e))?;

        Ok(frame)
    }

    pub async fn write_frame(&mut self, stream: &mut BoxedStream, frame: &MuxFrame) -> Result<()> {
        let plain_bytes = postcard::to_allocvec(frame)
            .map_err(|e| anyhow::anyhow!("Postcard serialization failed: {:?}", e))?;

        let nonce = Self::generate_nonce(self.tx_nonce);
        self.tx_nonce += 1;

        let cipher_bytes = self.cipher.encrypt(&nonce, plain_bytes.as_ref())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;

        let len = cipher_bytes.len() as u16;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&cipher_bytes).await?;

        Ok(())
    }
}

pub async fn accept_mux_connection(
    mut stream: BoxedStream,
    router: Arc<crate::router::Router>,
    policy: Arc<crate::config::LevelPolicy>,
) -> Result<()> {
    debug!("Mux 2.0: Accepted new multiplexed connection");
    
    // In a real implementation, the session key would be derived from the VLESS handshake.
    // For this prototype, we use a static key or randomly generated key exchanged earlier.
    let key = [0u8; 32]; 
    let mut session = Mux2Session::new(key);

    loop {
        match session.read_frame(&mut stream).await {
            Ok(frame) => {
                match frame {
                    MuxFrame::OpenStream { id, host, port } => {
                        debug!("Mux 2.0: OpenStream {} to {}:{}", id, host, port);
                        // Spawn task to handle stream
                    }
                    MuxFrame::Data { id, payload } => {
                        debug!("Mux 2.0: Data {} ({} bytes)", id, payload.len());
                    }
                    MuxFrame::CloseStream { id } => {
                        debug!("Mux 2.0: CloseStream {}", id);
                    }
                }
            }
            Err(e) => {
                error!("Mux 2.0 read loop terminated: {}", e);
                break;
            }
        }
    }

    Ok(())
}

// Stubs for remaining compilation dependencies
#[derive(Clone)]
pub struct MuxPool;

impl MuxPool {
    pub fn new() -> Self {
        Self
    }
}
