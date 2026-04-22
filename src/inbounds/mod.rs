// src/inbounds/mod.rs
pub mod dokodemo;
pub mod http;
pub mod reverse_portal;
pub mod socks;
pub mod nginx_decoy;

use crate::app::dns::DnsServer;
use crate::app::reverse::ReverseManager;
use crate::app::stats::{ConfigEvent, StatsManager};
use crate::config::{Inbound, InboundSettings};
use crate::error::Result;
#[cfg(feature = "quic")]
use crate::protocols::{hysteria2, tuic};
use crate::protocols::{trojan, vless};
use crate::router::Router;
#[cfg(feature = "quic")]
use crate::transport::quic;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::task::AbortHandle;
use tracing::{error, info, warn};

/// Manages all configured inbound listeners.
pub struct InboundManager {
    router: Arc<Router>,
    dns_server: Arc<DnsServer>,
    stats_manager: Arc<StatsManager>,
    reverse_manager: Arc<ReverseManager>,
}

impl InboundManager {
    pub fn new(
        router: Arc<Router>,
        dns_server: Arc<DnsServer>,
        stats_manager: Arc<StatsManager>,
        reverse_manager: Arc<ReverseManager>,
    ) -> Self {
        Self {
            router,
            dns_server,
            stats_manager,
            reverse_manager,
        }
    }

    /// Starts inbound listeners and listens for dynamic config changes.
    pub async fn run(&self, stats_manager: Arc<StatsManager>) -> Result<()> {
        // Map of Tag -> AbortHandle to cancel listeners
        let mut running_tasks: HashMap<String, AbortHandle> = HashMap::new();
        let mut rx = stats_manager.config_event_tx.subscribe();

        // 1. Initial Startup
        let initial_inbounds = {
            let config = stats_manager.config.load();
            config.inbounds.clone().unwrap_or_default()
        };

        for inbound in initial_inbounds {
            self.start_inbound(&inbound, &mut running_tasks).await;
        }

        // 2. Dynamic Event Loop
        loop {
            match rx.recv().await {
                Ok(event) => match event {
                    ConfigEvent::InboundAdded(inbound) => {
                        info!("InboundManager: Adding inbound '{}'", inbound.tag);
                        // Stop existing if tag matches (update/restart)
                        if let Some(handle) = running_tasks.remove(&inbound.tag) {
                            handle.abort();
                        }
                        self.start_inbound(&inbound, &mut running_tasks).await;
                    }
                    ConfigEvent::InboundRemoved(tag) => {
                        info!("InboundManager: Removing inbound '{}'", tag);
                        if let Some(handle) = running_tasks.remove(&tag) {
                            handle.abort();
                        }
                    }
                    _ => {} // Ignore outbound events
                },
                Err(e) => {
                    error!("InboundManager: Event bus error: {}", e);
                    // If lag occurs, we might miss events. Real impl handles lag.
                }
            }
        }
    }

    async fn start_inbound(
        &self,
        inbound: &Inbound,
        running_tasks: &mut HashMap<String, AbortHandle>,
    ) {
        // Clone context for the task
        let router = self.router.clone();
        let stats = self.stats_manager.clone();
        let reverse = self.reverse_manager.clone();
        let dns = self.dns_server.clone();
        let inbound_clone = inbound.clone();
        let tag = inbound.tag.clone();

        let tag_clone = tag.clone();
        let task = tokio::spawn(async move {
            let tag = tag_clone; // Use cloned tag inside async move block
            // Simplified listener logic for brevity
            // Real impl would reuse the grouping logic from previous epochs
            let port = inbound_clone.port;
            let listen = inbound_clone
                .listen
                .clone()
                .unwrap_or("0.0.0.0".to_string());
            let settings = inbound_clone.settings;
            let stream_settings = inbound_clone.stream_settings;

            let network = stream_settings
                .as_ref()
                .map(|s| s.network.as_str())
                .unwrap_or("tcp");
            match network {
                "udp" => {
                    if let Some(InboundSettings::Dokodemo(doko_settings)) = &settings {
                        let r = router.clone();
                        let s = stats.clone();
                        let settings_clone = doko_settings.clone();
                        let tproxy = doko_settings.tproxy.unwrap_or(false);
                        let listen_port = port; // Capture port for async move

                        tokio::spawn(async move {
                            if let Err(e) =
                                dokodemo::listen_packet(r, s, settings_clone, listen_port, tproxy)
                                    .await
                            {
                                error!("UDP Dokodemo listener failed: {}", e);
                            }
                        });
                    } else {
                        warn!(
                            "UDP network selected but protocol not supported (only Dokodemo implemented for UDP)"
                        );
                    }
                    // UDP listener is single long-running task usually (or loop inside listen_packet)
                    // We break the loop or sleep forever to keep task alive if needed, but listen_packet has a loop.
                    // Wait, `tokio::spawn` above handles it. This task finishes setup.
                    // But we are inside `task`. This outer task needs to stay alive? No, it spawns the actual listener loop.
                    // Actually `task` IS the listener loop for TCP.
                    // For UDP, we just spawn one handler and wait?
                    // We need a way to keep `task` alive or just let it finish if it only setup UDP.
                    // But `running_tasks` holds the handle to `task`. If `task` finishes, the handle might not be useful for aborting?
                    // `AbortHandle` aborts the future. If future completes, abort does nothing.
                    // We should await the UDP listener here.
                    futures::future::pending::<()>().await;
                }
                "tcp" | "ws" | "http" => {
                    let listener = match TcpListener::bind(format!("{}:{}", listen, port)).await {
                        Ok(l) => l,
                        Err(e) => {
                            error!("Failed to bind {}: {}", inbound_clone.tag, e);
                            return;
                        }
                    };
                    info!("Started listener {}", inbound_clone.tag);
                    loop {
                        if let Ok((stream, addr)) = listener.accept().await {
                            let source = addr.to_string();
                            let r = router.clone();
                            let s = stats.clone();
                            let d = dns.clone();
                            let set = settings.clone();
                            let _rev = reverse.clone();
                            let ss = stream_settings.clone();
                            let tag = tag.clone(); // Clone for this iteration
                            let source = source.clone();

                            tokio::spawn(async move {
                                let default_ss = crate::config::StreamSettings::default();
                                let ss_ref = ss.as_ref().unwrap_or(&default_ss);
                                let stream = match crate::transport::wrap_inbound_stream(
                                    Box::new(stream),
                                    ss_ref,
                                )
                                .await
                                {
                                    Ok(s) => s,
                                    Err(_) => return,
                                };

                                // Dispatch based on settings type
                                let _ = if let Some(s_cfg) = set {
                                    match s_cfg {
                                        InboundSettings::Socks(cfg) => {
                                            socks::listen_stream(r, d, s, stream, cfg, source).await
                                        }
                                        InboundSettings::Vless(cfg) => {
                                            vless::listen_stream(r, s, stream, cfg, source).await
                                        }
                                        InboundSettings::Trojan(cfg) => {
                                            trojan::TrojanInbound::handle_stream(
                                                stream, Arc::new(cfg), s, r, None, source,
                                            )
                                            .await
                                        }
                                        InboundSettings::Flow(_cfg) => {
                                            // flow::FlowInbound::handle_stream(stream, Arc::new(cfg), r).await
                                            Ok(())
                                        }
                                        InboundSettings::Http(cfg) => {
                                            http::listen_stream(r, s, stream, cfg, source).await
                                        }
                                        InboundSettings::ReversePortal(cfg) => {
                                            reverse_portal::listen_stream_tcp(
                                                _rev, stream, cfg, &tag, source,
                                            )
                                            .await
                                        }
                                        // ... add other protocols
                                        _ => Ok(()),
                                    }
                                } else {
                                    Ok(())
                                };
                            });
                        }
                    }
                }
                #[cfg(feature = "quic")]
                "quic" => {
                    let certificate = if let Some(InboundSettings::Tuic(s)) = &settings {
                        s.certificate.clone()
                    } else if let Some(InboundSettings::Hysteria2(_s)) = &settings {
                        // Hysteria2 also needs certs, assuming a similar structure
                        None // Replace with actual cert logic for Hysteria2
                    } else {
                        None
                    };

                    info!("Starting QUIC listener on UDP {}:{}", listen, port);
                    let quic_listener = match quic::listen(&listen, port, &certificate).await {
                        Ok(l) => l,
                        Err(e) => {
                            error!("Failed to bind QUIC listener for {}: {}", tag, e);
                            return;
                        }
                    };

                    loop {
                        if let Ok(mut new_conn) = quic_listener.accept().await {
                            let r = router.clone();
                            let s = stats.clone();
                            let set = settings.clone();

                            tokio::spawn(async move {
                                let alpn = new_conn.application_protocol().await;
                                if let Ok(stream) = new_conn.accept_stream().await {
                                    match (alpn.as_slice(), set) {
                                        (b"tuic-v5", Some(InboundSettings::Tuic(ts))) => {
                                            if let Err(e) = tuic::listen_stream(
                                                r,
                                                s,
                                                stream,
                                                ts,
                                                new_conn.remote_address().await.to_string(),
                                            )
                                            .await
                                            {
                                                warn!("TUIC stream handler error: {}", e);
                                            }
                                        }
                                        (b"hy2", Some(InboundSettings::Hysteria2(hs))) => {
                                            if let Err(e) = hysteria2::handle_inbound_stream(
                                                r,
                                                s,
                                                stream,
                                                Arc::new(hs),
                                                new_conn.remote_address().await.to_string(),
                                            )
                                            .await
                                            {
                                                warn!("Hysteria2 stream handler error: {}", e);
                                            }
                                        }
                                        _ => {
                                            warn!(
                                                "QUIC connection with ALPN {:?} not supported for this inbound",
                                                String::from_utf8_lossy(&alpn)
                                            );
                                        }
                                    }
                                }
                            });
                        }
                    }
                }
                #[cfg(not(feature = "quic"))]
                "quic" => {
                    warn!(
                        "QUIC support is disabled, cannot start listener for {}",
                        tag
                    );
                }
                _ => {
                    warn!("Dynamic start not fully implemented for UDP yet");
                }
            }
        });

        running_tasks.insert(tag.clone(), task.abort_handle());
    }
}
