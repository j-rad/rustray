// src/outbounds/mod.rs
pub mod blackhole;
pub mod freedom;
pub mod reverse_bridge;
pub mod ssh_outbound;
pub mod tailscale_outbound;
pub mod tor_outbound;

use crate::app::reverse::ReverseManager;
use crate::app::stats::StatsManager;
use crate::config::LevelPolicy;
use crate::config::OutboundSettings;
use crate::error::Result;
use crate::protocols::{http_proxy, naive, shadowsocks_2022, trojan, vless, vmess, wireguard};
#[cfg(feature = "quic")]
use crate::protocols::{hysteria2, tuic};
use crate::transport::{BoxedStream, Packet};
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::info;

/// Trait for all outbound handlers.
#[async_trait]
pub trait Outbound: Send + Sync {
    async fn handle(
        &self,
        stream: BoxedStream,
        host: String,
        port: u16,
        policy: Arc<LevelPolicy>,
    ) -> Result<()>;

    async fn dial(&self, host: String, port: u16) -> Result<BoxedStream>;

    async fn handle_packet(
        &self,
        _packet: Box<dyn Packet>,
        _reply_tx: Option<tokio::sync::mpsc::Sender<Box<dyn Packet>>>,
    ) -> Result<()> {
        Err(anyhow::anyhow!(
            "This outbound does not support packet-level routing"
        ))
    }
}

pub struct OutboundManager {
    handlers: HashMap<String, Arc<dyn Outbound>>,
}

impl OutboundManager {
    pub async fn new(
        stats_manager: Arc<StatsManager>,
        reverse_manager: Arc<ReverseManager>,
    ) -> Result<Self> {
        let mut handlers: HashMap<String, Arc<dyn Outbound>> = HashMap::new();
        let config = stats_manager.config.load();
        let dns_server = stats_manager.dns_server.clone();

        if let Some(outbounds) = &config.outbounds {
            for outbound_config in outbounds {
                let tag = outbound_config.tag.clone();
                let handler: Arc<dyn Outbound> = match &outbound_config.settings {
                    Some(OutboundSettings::Freedom(s)) => Arc::new(freedom::Freedom::new(
                        s.clone(),
                        dns_server.clone(),
                        stats_manager.clone(),
                        tag.clone(),
                    )),
                    Some(OutboundSettings::Blackhole(s)) => {
                        Arc::new(blackhole::Blackhole::new(s.clone()))
                    }
                    Some(OutboundSettings::ReverseBridge(s)) => Arc::new(
                        reverse_bridge::ReverseBridge::new(s.clone(), reverse_manager.clone()),
                    ),
                    Some(OutboundSettings::Http(s)) => Arc::new(http_proxy::HttpOutbound::new(
                        s.clone(),
                        dns_server.clone(),
                        stats_manager.clone(),
                        tag.clone(),
                    )),
                    Some(OutboundSettings::Shadowsocks2022(s)) => {
                        Arc::new(shadowsocks_2022::Shadowsocks2022Outbound::new(
                            s.clone(),
                            dns_server.clone(),
                            stats_manager.clone(),
                            tag.clone(),
                        ))
                    }
                    Some(OutboundSettings::WireGuard(s)) => Arc::new(
                        wireguard::WireGuardOutbound::new(s.clone(), stats_manager.clone())?,
                    ),
                    Some(OutboundSettings::Naive(s)) => {
                        Arc::new(naive::NaiveOutbound::new(s.clone(), dns_server.clone()))
                    }
                    Some(OutboundSettings::Ssh(s)) => Arc::new(ssh_outbound::SshOutbound::new(
                        s.clone(),
                        dns_server.clone(),
                    )),
                    Some(OutboundSettings::Tor(s)) => {
                        Arc::new(tor_outbound::TorOutbound::new(s.clone()))
                    }
                    Some(OutboundSettings::Tailscale(s)) => {
                        Arc::new(tailscale_outbound::TailscaleOutbound::new(s.clone()))
                    }
                    Some(OutboundSettings::Vless(s)) => Arc::new(vless::VlessOutbound::new(
                        s.clone(),
                        outbound_config.stream_settings.clone(),
                        outbound_config.mux.clone(),
                        dns_server.clone(),
                    )),
                    Some(OutboundSettings::Vmess(s)) => Arc::new(vmess::VmessOutbound::new(
                        s.clone(),
                        outbound_config.stream_settings.clone(),
                        dns_server.clone(),
                    )),
                    #[cfg(feature = "quic")]
                    Some(OutboundSettings::Hysteria2(s)) => {
                        Arc::new(hysteria2::Hysteria2Outbound::new(s.clone()))
                    }
                    #[cfg(feature = "quic")]
                    Some(OutboundSettings::Tuic(s)) => Arc::new(tuic::TuicOutbound::new(s.clone())),
                    #[cfg(not(feature = "quic"))]
                    Some(OutboundSettings::Hysteria2(_)) | Some(OutboundSettings::Tuic(_)) => {
                        // Fallback or error? Freedom is safest fallback to avoid panic
                        Arc::new(freedom::Freedom::new(
                            Default::default(),
                            dns_server.clone(),
                            stats_manager.clone(),
                            tag.clone(),
                        ))
                    }
                    Some(OutboundSettings::Trojan(s)) => Arc::new(trojan::TrojanOutbound::new(
                        s.address.clone(),
                        s.port,
                        s.password.clone(),
                        dns_server.clone(),
                        None,
                    )),
                    Some(OutboundSettings::Flow(_s)) => {
                        // Flow protocol is primarily for inbound; use Freedom for outbound
                        Arc::new(freedom::Freedom::new(
                            Default::default(),
                            dns_server.clone(),
                            stats_manager.clone(),
                            tag.clone(),
                        ))
                    }
                    _ => {
                        // Default to Freedom for Generic/Dns/None
                        Arc::new(freedom::Freedom::new(
                            Default::default(),
                            dns_server.clone(),
                            stats_manager.clone(),
                            tag.clone(),
                        ))
                    }
                };

                info!("Initialized outbound handler: tag='{}'", tag);
                handlers.insert(tag, handler);
            }
        }
        Ok(Self { handlers })
    }

    pub fn get(&self, tag: &str) -> Option<Arc<dyn Outbound>> {
        self.handlers.get(tag).cloned()
    }

    pub fn get_all_tags(&self) -> Vec<String> {
        self.handlers.keys().cloned().collect()
    }
}
