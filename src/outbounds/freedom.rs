// src/outbounds/freedom.rs
use super::Outbound;
use crate::app::dns::DnsServer;
use crate::app::stats::StatsManager;
use crate::config::{FreedomSettings, LevelPolicy, StreamSettings};
use crate::error::Result;
use crate::transport::{self, BoxedStream, Packet, UdpPacket, stats::StatsStream};
use async_trait::async_trait;
use dashmap::DashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

// --- UDP Session Management for Full Cone NAT ---

/// Session key: (Source IP, Source Port) uniquely identifies a client
type UdpSessionKey = SocketAddr;

/// UDP Session holds the proxy socket and response channel
#[allow(dead_code)]
struct UdpSession {
    /// Socket bound to random port for communicating with internet
    socket: Arc<UdpSocket>,
    /// Last activity timestamp for timeout tracking
    last_activity: std::sync::Mutex<Instant>,
    /// Channel to send responses back to inbound handler
    reply_tx: mpsc::Sender<Box<dyn Packet>>,
    /// Target address (for logging/debugging)
    target: SocketAddr,
}

pub struct Freedom {
    _settings: FreedomSettings,
    dns_server: Arc<DnsServer>,
    stats_manager: Arc<StatsManager>,
    tag: String,
    /// Thread-safe UDP session manager using DashMap
    udp_manager: Arc<DashMap<UdpSessionKey, UdpSession>>,
}

impl Freedom {
    pub fn new(
        settings: FreedomSettings,
        dns_server: Arc<DnsServer>,
        stats_manager: Arc<StatsManager>,
        tag: String,
    ) -> Self {
        let manager = Arc::new(DashMap::new());
        let manager_clone = manager.clone();

        // Background cleanup task: Remove inactive sessions every 30 seconds
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                let now = Instant::now();

                // Retain only sessions active within last 60 seconds
                manager_clone.retain(|_src: &std::net::SocketAddr, session: &mut UdpSession| {
                    let last = *session.last_activity.lock().unwrap();
                    let inactive_duration = now.duration_since(last);

                    if inactive_duration >= Duration::from_secs(60) {
                        debug!(
                            "Freedom: Expiring UDP session (inactive for {:?})",
                            inactive_duration
                        );
                        false
                    } else {
                        true
                    }
                });
            }
        });

        Self {
            _settings: settings,
            dns_server,
            stats_manager,
            tag,
            udp_manager: manager,
        }
    }
}

#[async_trait]
impl Outbound for Freedom {
    async fn handle<'a>(
        &'a self,
        mut in_stream: BoxedStream,
        host: String,
        port: u16,
        policy: Arc<LevelPolicy>,
    ) -> Result<()> {
        let mut outbound_stream = self.dial(host.clone(), port).await?;

        info!("Freedom: Connection established to {}:{}", host, port);

        let up_counter = self
            .stats_manager
            .get_counter(&format!("outbound>>{}>>traffic>>uplink", self.tag));
        let down_counter = self
            .stats_manager
            .get_counter(&format!("outbound>>{}>>traffic>>downlink", self.tag));

        let idle_timeout = Duration::from_secs(policy.conn_idle.unwrap_or(300) as u64);

        #[cfg(target_os = "linux")]
        {
            let splice_fut = crate::transport::splice::splice_bidirectional(
                &mut in_stream,
                &mut outbound_stream,
            );
            match tokio::time::timeout(idle_timeout, splice_fut).await {
                Ok(Some(res)) => {
                    let (sent, recv) = res?;
                    up_counter.fetch_add(sent, std::sync::atomic::Ordering::Relaxed);
                    down_counter.fetch_add(recv, std::sync::atomic::Ordering::Relaxed);
                    return Ok(());
                }
                Ok(None) => {
                    // Not TCP or splice failed, fallthrough to standard copy
                }
                Err(_) => {
                    return Err(anyhow::anyhow!("Connection idle timeout"));
                }
            }
        }

        let mut in_stream_stats =
            StatsStream::new(in_stream, up_counter.clone(), down_counter.clone());
        let mut out_stream_stats = StatsStream::new(outbound_stream, down_counter, up_counter);

        let operation = io::copy_bidirectional(&mut in_stream_stats, &mut out_stream_stats);

        match tokio::time::timeout(idle_timeout, operation).await {
            Ok(Ok(_)) => Ok(()),
            Ok(Err(e)) => Err(e.into()),
            Err(_) => Err(anyhow::anyhow!("Connection idle timeout")),
        }
    }

    async fn dial(&self, host: String, port: u16) -> Result<BoxedStream> {
        let config = self.stats_manager.config.load();
        let settings: StreamSettings = if let Some(outbounds) = &config.outbounds {
            outbounds
                .iter()
                .find(|o| o.tag == self.tag)
                .and_then(|o| o.stream_settings.clone())
                .unwrap_or_default()
        } else {
            StreamSettings::default()
        };

        let stream = transport::connect(&settings, self.dns_server.clone(), &host, port).await?;
        Ok(stream)
    }

    async fn handle_packet(
        &self,
        packet: Box<dyn Packet>,
        reply_tx: Option<mpsc::Sender<Box<dyn Packet>>>,
    ) -> Result<()> {
        // Production-grade UDP NAT with Full Cone support
        let src = packet.src();
        let dest = packet.dest();
        let payload = packet.payload();

        // Ensure we have a reply channel
        let reply_tx = reply_tx.ok_or_else(|| {
            anyhow::anyhow!("Freedom UDP: No reply channel provided for packet routing")
        })?;

        // Check if session exists
        if let Some(session_ref) = self.udp_manager.get_mut(&src) {
            // Update activity timestamp
            *session_ref.last_activity.lock().unwrap() = Instant::now();

            // Send packet to destination using existing socket
            let socket = session_ref.socket.clone();
            debug!("Freedom: Reusing UDP session {} -> {}", src, dest);

            socket.send_to(payload, dest).await?;
            return Ok(());
        }

        // Create new session
        debug!("Freedom: Creating new UDP session for {} -> {}", src, dest);

        // Bind to random port for Full Cone NAT behavior
        let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        let local_addr = socket.local_addr()?;
        debug!(
            "Freedom: Bound UDP socket {} for session {}",
            local_addr, src
        );

        let session = UdpSession {
            socket: socket.clone(),
            last_activity: std::sync::Mutex::new(Instant::now()),
            reply_tx: reply_tx.clone(),
            target: dest,
        };

        self.udp_manager.insert(src, session);

        // Spawn response listener task
        let socket_recv = socket.clone();
        let src_clone = src;
        let manager = self.udp_manager.clone();
        let tag = self.tag.clone();

        // Clone reply_tx for the task so we don't need to lock DashMap to send
        let reply_tx_task = reply_tx.clone();

        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535]; // Max UDP packet size

            loop {
                // Read with timeout to detect inactive sessions
                match tokio::time::timeout(Duration::from_secs(65), socket_recv.recv_from(&mut buf))
                    .await
                {
                    Ok(Ok((len, from))) => {
                        debug!(
                            "Freedom[{}]: UDP response from {} -> {} ({} bytes)",
                            tag, from, src_clone, len
                        );

                        // 1. Update session activity (Quick Lock)
                        // We only need to check if session still exists and update timestamp.
                        // If it doesn't exist, we should probably stop?
                        // Yes, because it means expiry task removed it.
                        {
                            if let Some(session) = manager.get_mut(&src_clone) {
                                *session.last_activity.lock().unwrap() = Instant::now();
                            } else {
                                // Session removed
                                debug!(
                                    "Freedom[{}]: Session {} removed, stopping listener",
                                    tag, src_clone
                                );
                                break;
                            }
                        } // Lock released here

                        // 2. Create response packet
                        let response_packet = UdpPacket {
                            src: from,       // Internet server
                            dest: src_clone, // Original client
                            data: buf[..len].to_vec(),
                        };

                        // 3. Send back to inbound handler via channel (Async, no lock held)
                        if let Err(e) = reply_tx_task.send(Box::new(response_packet)).await {
                            warn!(
                                "Freedom[{}]: Failed to send UDP response to inbound: {}",
                                tag, e
                            );
                            break; // Channel closed, stop task
                        }
                    }
                    Ok(Err(e)) => {
                        warn!("Freedom[{}]: UDP recv error for {}: {}", tag, src_clone, e);
                        break;
                    }
                    Err(_) => {
                        // Timeout - check if session still exists
                        if !manager.contains_key(&src_clone) {
                            debug!(
                                "Freedom[{}]: Session {} expired, stopping listener",
                                tag, src_clone
                            );
                            break;
                        }
                        // Session still exists but no traffic, continue listening
                    }
                }
            }

            // Cleanup handled by expiry task, but we can double check?
            // No, expiry task handles map removal. We just exit.
            debug!(
                "Freedom[{}]: UDP listener task ended for {}",
                tag, src_clone
            );
        });

        // Send initial packet to destination
        socket.send_to(payload, dest).await?;

        Ok(())
    }
}
