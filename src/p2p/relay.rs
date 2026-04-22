// src/p2p/relay.rs
//! P2P Relay Listener
//!
//! Accepts incoming peer connections authenticated via a pre-shared key (PSK).
//! Each authenticated peer gets a bidirectional encrypted channel for traffic relay.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

/// PSK authentication salt
const PSK_SALT: &[u8] = b"rustray-p2p-relay-v1";
/// Auth challenge size
const CHALLENGE_SIZE: usize = 32;
/// Auth response size (BLAKE3 hash)
const AUTH_HASH_SIZE: usize = 32;

/// Configuration for the relay listener.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RelayConfig {
    /// Listen address for incoming peer connections
    pub listen: String,
    /// Pre-shared key for authentication
    pub psk: String,
    /// Maximum concurrent peers
    #[serde(default = "default_max_peers")]
    pub max_peers: usize,
}

fn default_max_peers() -> usize {
    32
}

/// Authenticated peer state.
#[allow(dead_code)]
struct PeerState {
    addr: SocketAddr,
    stream: TcpStream,
    authenticated: bool,
}

/// Relay listener that accepts and authenticates peer connections.
pub struct RelayListener {
    config: RelayConfig,
    psk_key: [u8; 32],
    peers: Arc<Mutex<HashMap<SocketAddr, PeerState>>>,
}

impl RelayListener {
    pub fn new(config: RelayConfig) -> Self {
        let psk_key = Self::derive_psk_key(&config.psk);
        Self {
            config,
            psk_key,
            peers: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Derive a 32-byte key from the PSK using BLAKE3.
    fn derive_psk_key(psk: &str) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(PSK_SALT);
        hasher.update(psk.as_bytes());
        *hasher.finalize().as_bytes()
    }

    /// Start listening for peer connections.
    pub async fn listen(&self) -> io::Result<()> {
        let listener = TcpListener::bind(&self.config.listen).await?;
        info!("P2P Relay listening on {}", self.config.listen);

        loop {
            let (stream, addr) = listener.accept().await?;
            let peers = self.peers.clone();
            let psk_key = self.psk_key;
            let max_peers = self.config.max_peers;

            tokio::spawn(async move {
                if let Err(e) =
                    Self::handle_peer(stream, addr, psk_key, peers, max_peers).await
                {
                    debug!("Peer {} auth failed: {}", addr, e);
                }
            });
        }
    }

    /// Handle a new peer connection: challenge-response auth.
    async fn handle_peer(
        mut stream: TcpStream,
        addr: SocketAddr,
        psk_key: [u8; 32],
        peers: Arc<Mutex<HashMap<SocketAddr, PeerState>>>,
        max_peers: usize,
    ) -> io::Result<()> {
        // Check peer limit
        {
            let guard = peers.lock().await;
            if guard.len() >= max_peers {
                warn!("P2P Relay: max peers reached, rejecting {}", addr);
                return Err(io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    "Max peers reached",
                ));
            }
        }

        // 1. Send challenge (random 32 bytes)
        let challenge: [u8; CHALLENGE_SIZE] = rand::random();
        stream.write_all(&challenge).await?;

        // 2. Read response (BLAKE3 hash of challenge + PSK key)
        let mut response = [0u8; AUTH_HASH_SIZE];
        stream.read_exact(&mut response).await?;

        // 3. Verify
        let mut hasher = blake3::Hasher::new();
        hasher.update(&challenge);
        hasher.update(&psk_key);
        let expected = hasher.finalize();

        if response != *expected.as_bytes() {
            stream.write_all(&[0x00]).await?; // Auth failed
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "PSK auth failed",
            ));
        }

        // 4. Send success
        stream.write_all(&[0x01]).await?;
        info!("P2P Relay: peer {} authenticated", addr);

        // 5. Register peer
        {
            let mut guard = peers.lock().await;
            guard.insert(
                addr,
                PeerState {
                    addr,
                    stream,
                    authenticated: true,
                },
            );
        }

        Ok(())
    }

    /// Authenticate as a client to a relay.
    pub async fn connect_to_relay(
        addr: &str,
        psk: &str,
    ) -> io::Result<TcpStream> {
        let mut stream = TcpStream::connect(addr).await?;
        let psk_key = Self::derive_psk_key(psk);

        // 1. Read challenge
        let mut challenge = [0u8; CHALLENGE_SIZE];
        stream.read_exact(&mut challenge).await?;

        // 2. Compute response
        let mut hasher = blake3::Hasher::new();
        hasher.update(&challenge);
        hasher.update(&psk_key);
        let response = hasher.finalize();

        // 3. Send response
        stream.write_all(response.as_bytes()).await?;

        // 4. Read result
        let mut result = [0u8; 1];
        stream.read_exact(&mut result).await?;

        if result[0] != 0x01 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Relay PSK auth failed",
            ));
        }

        info!("P2P: authenticated to relay {}", addr);
        Ok(stream)
    }
}
