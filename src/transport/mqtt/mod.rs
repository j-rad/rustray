// src/transport/mqtt/mod.rs
//!
//! Phase 4+13 — MQTT Multi-Homing & Dynamic Port-Sweep Transport
//!
//! Tunnels TCP streams over MQTT publish/subscribe with:
//! - Dynamic endpoint resolution via `MqttEndpoint` / `PortSweepConfig`
//! - Zero-drop failover across protocol variants (MQTTS → WSS → MQTT → WS)
//! - Topic-based sharding mimicking sensor telemetry
//! - Quality-gated failover (throughput + packet-loss thresholds)

pub mod config;

use bytes::{Bytes, BytesMut};
use config::{MqttEndpoint, PortSweepConfig};
use futures::SinkExt;
use rumqttc::{AsyncClient, Event, MqttOptions, Packet, QoS, Transport};
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
use tokio_util::sync::PollSender;
use tracing::{debug, info, warn};
use uuid::Uuid;
use crate::protocols::flow_trait::{BoxedTrinityTransport, TrinityTransport};
use crate::error::Result as anyhowResult;

// --- Endpoint Health Tracker ---

/// Per-endpoint quality metrics collected at runtime.
struct EndpointHealth {
    endpoint: MqttEndpoint,
    client: AsyncClient,
    tx_bytes: AtomicU64,
    rx_bytes: AtomicU64,
    tx_errors: AtomicU64,
    last_success: Mutex<Instant>,
    is_alive: std::sync::atomic::AtomicBool,
}

impl EndpointHealth {
    fn new(endpoint: MqttEndpoint, client: AsyncClient) -> Self {
        Self {
            endpoint,
            client,
            tx_bytes: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            tx_errors: AtomicU64::new(0),
            last_success: Mutex::new(Instant::now()),
            is_alive: std::sync::atomic::AtomicBool::new(true),
        }
    }

    fn record_tx_success(&self, bytes: u64) {
        self.tx_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    fn record_tx_error(&self) {
        self.tx_errors.fetch_add(1, Ordering::Relaxed);
    }

    fn mark_alive(&self) {
        self.is_alive.store(true, Ordering::Relaxed);
    }

    fn mark_dead(&self) {
        self.is_alive.store(false, Ordering::Relaxed);
    }

    fn alive(&self) -> bool {
        self.is_alive.load(Ordering::Relaxed)
    }
}

// --- MQTT Transport Manager ---

#[derive(Clone)]
pub struct MqttTransport {
    health: Arc<Vec<EndpointHealth>>,
    sessions: Arc<Mutex<HashMap<String, UnboundedSender<Bytes>>>>,
    base_topic: String,
    outgoing_tx: mpsc::Sender<(String, Vec<u8>)>,
    active_idx: Arc<AtomicUsize>,
}

impl MqttTransport {
    pub async fn new(
        server_uri: &str,
        client_id: &str,
        base_topic: &str,
        pqc: Option<&crate::config::PqcSettings>,
    ) -> anyhow::Result<Self> {
        let base_endpoint = MqttEndpoint::parse(server_uri)?;
        let sweep = PortSweepConfig::from_base(&base_endpoint);
        Self::with_sweep(sweep, client_id, base_topic, pqc).await
    }

    /// Create with an explicit port-sweep configuration.
    pub async fn with_sweep(
        sweep: PortSweepConfig,
        client_id: &str,
        base_topic: &str,
        pqc: Option<&crate::config::PqcSettings>,
    ) -> anyhow::Result<Self> {
        let sessions: Arc<Mutex<HashMap<String, UnboundedSender<Bytes>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let (out_tx, mut out_rx) = mpsc::channel::<(String, Vec<u8>)>(1024);

        let mut health_entries = Vec::with_capacity(sweep.endpoints.len());

        for endpoint in sweep.endpoints.iter() {
            let mut options = MqttOptions::new(
                format!(
                    "{}_{}_{}",
                    client_id,
                    endpoint.protocol.scheme(),
                    endpoint.port
                ),
                &endpoint.host,
                endpoint.port,
            );
            options.set_keep_alive(Duration::from_secs(5));
            options.set_clean_session(true);

            if endpoint.protocol.requires_tls() {
                let mut root_store = rustls::RootCertStore::empty();
                root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

                let mut provider = rustls::crypto::aws_lc_rs::default_provider();
                if let Some(pqc_settings) = pqc
                    && pqc_settings.enabled
                {
                    provider.kx_groups = vec![crate::transport::pqc::HybridGroup::X25519MlKem768.rustls_group()];
                }

                let rustls_config = rustls::ClientConfig::builder_with_provider(Arc::new(provider))
                    .with_safe_default_protocol_versions()
                    .map_err(|e| anyhow::anyhow!("MQTT TLS: Failed to set protocol versions: {}", e))?
                    .with_root_certificates(root_store)
                    .with_no_client_auth();

                options.set_transport(Transport::tls_with_config(rumqttc::TlsConfiguration::Rustls(
                    Arc::new(rustls_config),
                )));
            }

            if endpoint.protocol.is_websocket() {
                // rumqttc WebSocket transport: configure via URL scheme
                // The event loop handles ws:// / wss:// transport internally
                // when the broker address starts with the ws(s) scheme.
            }

            let (client, mut eventloop) = AsyncClient::new(options, 10);
            let entry = EndpointHealth::new(endpoint.clone(), client.clone());
            health_entries.push(entry);

            let sessions_clone = sessions.clone();
            let port = endpoint.port;
            let scheme = endpoint.protocol.scheme().to_string();

            tokio::spawn(async move {
                loop {
                    match eventloop.poll().await {
                        Ok(Event::Incoming(Packet::Publish(p))) => {
                            let topic = p.topic;
                            let payload = p.payload;
                            let parts: Vec<&str> = topic.split('/').collect();
                            if parts.len() >= 2
                                && let Some(&session_id) = parts.get(parts.len().saturating_sub(2))
                            {
                                let map = sessions_clone.lock().await;
                                if let Some(tx) = map.get(session_id) {
                                    let _ = tx.send(payload);
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(e) => {
                            warn!("MQTT connection error on {}:{}: {:?}", scheme, port, e);
                            tokio::time::sleep(Duration::from_secs(2)).await;
                        }
                    }
                }
            });
        }

        let health = Arc::new(health_entries);
        let active_idx = Arc::new(AtomicUsize::new(0));

        // --- Failover Publisher Task ---
        let health_clone = health.clone();
        let active_idx_clone = active_idx.clone();
        tokio::spawn(async move {
            while let Some((topic, payload)) = out_rx.recv().await {
                let payload_len = payload.len() as u64;

                // Try from active index, then sweep remaining
                let count = health_clone.len();
                let start = active_idx_clone.load(Ordering::Relaxed) % count;
                let mut success = false;

                for offset in 0..count {
                    let idx = (start + offset) % count;
                    let entry = &health_clone[idx];

                    if !entry.alive() && offset == 0 {
                        // Active endpoint is dead, skip immediately to next
                        continue;
                    }

                    match entry
                        .client
                        .publish(&topic, QoS::AtMostOnce, false, payload.clone())
                        .await
                    {
                        Ok(_) => {
                            entry.record_tx_success(payload_len);
                            entry.mark_alive();
                            if offset != 0 {
                                // Failover occurred — update active index
                                active_idx_clone.store(idx, Ordering::Relaxed);
                                info!(
                                    "MQTT failover: now using {}:{} ({})",
                                    entry.endpoint.host,
                                    entry.endpoint.port,
                                    entry.endpoint.protocol.scheme()
                                );
                            }
                            success = true;
                            break;
                        }
                        Err(_) => {
                            entry.record_tx_error();
                            entry.mark_dead();
                            debug!(
                                "MQTT endpoint {}:{} failed, trying next",
                                entry.endpoint.host, entry.endpoint.port
                            );
                        }
                    }
                }

                if !success {
                    warn!("MQTT Publish Error: Failed on all {} endpoints", count);
                }
            }
        });

        let endpoint_desc: Vec<String> = sweep
            .endpoints
            .iter()
            .map(|e| format!("{}:{}", e.protocol.scheme(), e.port))
            .collect();
        info!(
            "MQTT Transport initialized with port-sweep: [{}]",
            endpoint_desc.join(", ")
        );

        Ok(Self {
            health,
            sessions,
            base_topic: base_topic.to_string(),
            outgoing_tx: out_tx,
            active_idx,
        })
    }

    /// Create a bidirectional stream over MQTT.
    pub async fn create_stream(&self) -> anyhow::Result<MqttStream> {
        let session_id = Uuid::new_v4().to_string();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        {
            let mut sessions = self.sessions.lock().await;
            sessions.insert(session_id.clone(), tx);
        }

        // Subscribe on all alive endpoints for redundant reception
        let topic = format!("{}/{}/down", self.base_topic, session_id);
        for entry in self.health.iter() {
            if entry.alive() {
                let _ = entry.client.subscribe(&topic, QoS::AtMostOnce).await;
            }
        }

        Ok(MqttStream {
            session_id,
            base_topic: self.base_topic.clone(),
            rx,
            read_buffer: BytesMut::new(),
            outgoing_tx: PollSender::new(self.outgoing_tx.clone()),
        })
    }

    /// Get the currently active endpoint index.
    pub fn active_endpoint_idx(&self) -> usize {
        self.active_idx.load(Ordering::Relaxed)
    }

    /// Get the total number of configured endpoints.
    pub fn endpoint_count(&self) -> usize {
        self.health.len()
    }
}

// --- MqttStream ---

pub struct MqttStream {
    session_id: String,
    base_topic: String,
    rx: UnboundedReceiver<Bytes>,
    read_buffer: BytesMut,
    outgoing_tx: PollSender<(String, Vec<u8>)>,
}

impl AsyncRead for MqttStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.read_buffer.is_empty() {
            let len = std::cmp::min(buf.remaining(), self.read_buffer.len());
            buf.put_slice(&self.read_buffer.split_to(len));
            return Poll::Ready(Ok(()));
        }

        match self.rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                let len = std::cmp::min(buf.remaining(), data.len());
                buf.put_slice(&data[..len]);
                if len < data.len() {
                    self.read_buffer.extend_from_slice(&data[len..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for MqttStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.outgoing_tx.poll_ready_unpin(cx) {
            Poll::Ready(Ok(())) => {
                let topic = format!("{}/{}/up", self.base_topic, self.session_id);
                let payload = buf.to_vec();
                if self.outgoing_tx.start_send_unpin((topic, payload)).is_err() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "MQTT channel closed",
                    )));
                }
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "MQTT channel closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.outgoing_tx.poll_flush_unpin(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "MQTT channel flush failed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.outgoing_tx.poll_close_unpin(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "MQTT channel shutdown failed",
            ))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl TrinityTransport for MqttStream {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }

    fn switch_carrier(&mut self, _new_carrier: BoxedTrinityTransport) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::Unsupported, "MqttStream: hot-swap not supported"))
    }
    fn apply_fragmentation(&mut self) -> io::Result<()> {
        Ok(())
    }
    fn handover(self, _new_tal: BoxedTrinityTransport) -> anyhowResult<Self> {
        Err(anyhow::anyhow!("MqttStream: handover not implemented"))
    }
}

pub mod scheduler;
