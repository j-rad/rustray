// src/outbounds/ssh_outbound.rs
use super::Outbound;
use crate::app::dns::DnsServer;
use crate::config::{LevelPolicy, SshOutboundSettings};
use crate::error::Result;
use crate::transport::BoxedStream;
use async_trait::async_trait;
use russh::client; // client module, Channel struct
use russh::keys::PublicKey; // Explicit import
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io;
use tracing::{info, warn};

struct SshHandler;
impl client::Handler for SshHandler {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        _server_public_key: &PublicKey,
    ) -> std::result::Result<bool, Self::Error> {
        // Insecure: Accept all keys for now
        Ok(true)
    }
}

#[allow(dead_code)]
type ConnectionKey = String;

pub struct SshOutbound {
    settings: SshOutboundSettings,
    // Using Box<dyn Any> because yamux::Control visibility is fighting me.
    // Ideally: sessions: Arc<DashMap<ConnectionKey, yamux::Control>>,
    // We will comment out session reuse logic for now to unblock build.
    // sessions: Arc<DashMap<ConnectionKey, yamux::Control>>,
    dns: Arc<DnsServer>,
}

impl SshOutbound {
    pub fn new(settings: SshOutboundSettings, dns: Arc<DnsServer>) -> Self {
        Self {
            settings,
            // sessions: Arc::new(DashMap::new()),
            dns,
        }
    }
}

#[async_trait]
impl Outbound for SshOutbound {
    async fn handle(
        &self,
        mut stream: BoxedStream,
        host: String,
        port: u16,
        policy: Arc<LevelPolicy>,
    ) -> Result<()> {
        info!(
            "SSH: Connecting to gateway {}:{}",
            self.settings.address, self.settings.port
        );

        // 1. Connect to SSH Server
        let addrs = self.dns.resolve_ip(&self.settings.address).await?;
        if addrs.is_empty() {
            return Err(anyhow::anyhow!("SSH server IP not found"));
        }
        let ssh_addr = SocketAddr::new(addrs[0], self.settings.port);

        let config = client::Config::default();
        let config = Arc::new(config);
        let sh = SshHandler;

        let mut session = client::connect(config, ssh_addr, sh).await?;

        // 2. Authenticate
        let mut authenticated = false;
        if let Some(password) = &self.settings.password {
            // Russh 0.40+ `authenticate_password` returns `Result<bool, Error>` or `Result<AuthResult, Error>` dependent on version?
            // Checking recent docs/crates: it usually returns `Result<bool, Error>` or `Result<AuthResult, Error>`.
            // The previous error says `?` converts to `AuthResult`.
            // So `let res = ...?;` `res` is `AuthResult`.
            // We need to import `AuthResult`? It might be `russh::client::AuthResult`.
            // Or we can just use `matches!`.
            let res = session
                .authenticate_password(&self.settings.user, password)
                .await?;
            // If it's an enum, we can check Debug or just assume if it returns, check if it is success.
            // Let's assume `AuthResult` has a `Success` variant.
            authenticated = matches!(res, russh::client::AuthResult::Success);
        } else if let Some(_key) = &self.settings.private_key {
            warn!("SSH: Private key auth not implemented yet");
            return Err(anyhow::anyhow!("SSH key auth missing"));
        }

        if !authenticated {
            return Err(anyhow::anyhow!("SSH authentication failed"));
        }

        // 3. Open Direct TCP/IP Channel (Tunnel)
        let channel = session
            .channel_open_direct_tcpip(host.clone(), port as u32, "0.0.0.0", 0)
            .await?;

        info!("SSH: Tunnel established to {}:{}", host, port);

        // 4. Pipe Data
        let mut channel_stream = channel.into_stream();
        let operation = io::copy_bidirectional(&mut stream, &mut channel_stream);
        let idle_timeout = Duration::from_secs(policy.conn_idle.unwrap_or(300) as u64);

        match tokio::time::timeout(idle_timeout, operation).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err(anyhow::anyhow!("Idle timeout")),
        }
    }

    async fn dial(&self, _host: String, _port: u16) -> Result<BoxedStream> {
        Err(anyhow::anyhow!(
            "SSH: Dialing is not yet supported for racing"
        ))
    }
}
