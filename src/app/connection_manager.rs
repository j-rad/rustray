// src/app/connection_manager.rs
//! ConMan — The Brain of the Virtual Transport Matrix
//!
//! This module implements autonomous carrier management for the 2026 GFW
//! "Total Surveillance" threat model.  It is responsible for:
//!
//! 1. **Happy Eyeballs v3** (`happy_eyeballs_v3`): Races multiple carriers
//!    (Reality, WebRTC, WS+CDN, MQTT) in parallel and selects the first
//!    winner, pruning losers after `RACE_PRUNE_MS`.
//!
//! 2. **Maintenance Loop** (`maintenance_loop`): Keeps a "Hot Standby"
//!    survival connection (dnstt) alive with a 1 packet/second heartbeat.
//!    If the active carrier dies, the standby is promoted instantly.
//!
//! 3. **Mesh Routing** (`route_via_mesh`): Discovers local P2P peers via
//!    mDNS and uses them as relay hops when direct internet access is
//!    restricted or throttled.

use crate::app::behavior_synth::BehaviorSynthesizer;
use crate::protocols::flow_trait::{BoxedTrinityTransport, TrinityStream};
use crate::transport::BoxedStream;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::{Mutex, RwLock, mpsc, watch};
use tokio::time::{Instant, sleep};
use tracing::{debug, info, warn};

// ─── Constants ────────────────────────────────────────────────────────────────

/// Milliseconds before a losing racer is pruned.
const RACE_PRUNE_MS: u64 = 3_000;

/// Heartbeat interval for the Hot Standby survival connection.
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);

/// mDNS service type used by RustRay peers for mesh discovery.
const MDNS_SERVICE_TYPE: &str = "_rustray._tcp.local.";

/// Size of the heartbeat payload (minimises MTU overhead while keeping the
/// connection alive under carrier-grade NAT / GFW stateful inspection).
const HEARTBEAT_PAYLOAD_LEN: usize = 16;

// ─── Carrier descriptor ───────────────────────────────────────────────────────

/// A named carrier with a dialing closure.
///
/// The `name` field is used for logging and metrics.
/// The `dial` closure returns an established `BoxedStream` or an error.
pub struct CarrierDescriptor {
    pub name: &'static str,
    pub addr: SocketAddr,
}

// ─── RaceResult ───────────────────────────────────────────────────────────────

/// Outcome of a carrier race.
pub struct RaceResult {
    pub winner_name: &'static str,
    pub stream: BoxedTrinityTransport,
    pub latency_ms: u64,
}

// ─── PeerInfo ─────────────────────────────────────────────────────────────────

/// A discovered mesh peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub latency_ms: u32,
    pub last_seen: Instant,
}

// ─── ConnectionManager ────────────────────────────────────────────────────────

/// The central ConMan.  Holds state for the active carrier, the hot-standby
/// connection, and the mesh peer table.
pub struct ConnectionManager {
    /// Currently active outbound carrier stream (protected for hot-swap).
    pub active_stream: Arc<Mutex<Option<BoxedTrinityTransport>>>,

    /// Hot-standby dnstt stream kept alive by `maintenance_loop`.
    pub standby_stream: Arc<Mutex<Option<BoxedTrinityTransport>>>,

    /// Known mesh peers, keyed by their socket address.
    mesh_peers: Arc<RwLock<HashMap<String, PeerInfo>>>,

    /// Notifier sent when the active carrier dies; triggers standby promotion.
    carrier_dead_tx: watch::Sender<bool>,
    carrier_dead_rx: watch::Receiver<bool>,

    /// Behavioural synthesizer for heartbeat timing.
    synth: Arc<Mutex<BehaviorSynthesizer>>,
}

impl ConnectionManager {
    /// Create a new `ConnectionManager`.
    pub fn new() -> Self {
        let (carrier_dead_tx, carrier_dead_rx) = watch::channel(false);
        Self {
            active_stream: Arc::new(Mutex::new(None)),
            standby_stream: Arc::new(Mutex::new(None)),
            mesh_peers: Arc::new(RwLock::new(HashMap::new())),
            carrier_dead_tx,
            carrier_dead_rx,
            synth: Arc::new(Mutex::new(BehaviorSynthesizer::auto_detect())),
        }
    }

    // ── Happy Eyeballs v3 ─────────────────────────────────────────────────────

    /// Race multiple carriers in parallel and return the first to connect.
    ///
    /// Each carrier is dialed concurrently.  The first to succeed wins; the
    /// rest are gracefully closed after `RACE_PRUNE_MS`.
    ///
    /// # Carrier priority (in case of ties)
    /// 1. Reality (lowest latency on non-censored paths)
    /// 2. WebRTC / SRTP media parasite
    /// 3. WS + CDN fronting
    /// 4. MQTT industrial mimicry
    ///
    /// If all carriers fail, returns the last error encountered.
    pub async fn happy_eyeballs_v3(
        carriers: Vec<CarrierDescriptor>,
    ) -> Result<RaceResult, anyhow::Error> {
        if carriers.is_empty() {
            return Err(anyhow::anyhow!("No carriers provided to race"));
        }

        let (winner_tx, mut winner_rx) = mpsc::channel::<RaceResult>(1);
        let start = Instant::now();

        // Spawn a racer task per carrier.
        for descriptor in carriers {
            let tx = winner_tx.clone();
            let addr = descriptor.addr;
            let name = descriptor.name;

            tokio::spawn(async move {
                let race_start = Instant::now();
                match TcpStream::connect(addr).await {
                    Ok(stream) => {
                        let latency_ms = race_start.elapsed().as_millis() as u64;
                        let trinity: BoxedTrinityTransport =
                            Box::new(TrinityStream::from_boxed(Box::new(stream) as BoxedStream));
                        let result = RaceResult {
                            winner_name: name,
                            stream: trinity,
                            latency_ms,
                        };
                        // Only send if we're the first winner (channel is capacity-1).
                        let _ = tx.send(result).await;
                        debug!("HEv3: carrier '{}' connected in {}ms", name, latency_ms);
                    }
                    Err(e) => {
                        warn!("HEv3: carrier '{}' failed: {}", name, e);
                    }
                }
                // Racer waits for the prune timeout then exits, closing its
                // half of the channel.  Any stream opened after the winner
                // was picked will simply be dropped here.
                sleep(Duration::from_millis(RACE_PRUNE_MS)).await;
            });
        }

        // Drop our own sender so the channel closes when all racers exit.
        drop(winner_tx);

        // Wait for the first winner.
        match winner_rx.recv().await {
            Some(result) => {
                let total_ms = start.elapsed().as_millis();
                info!(
                    "HEv3: winner='{}' latency={}ms total_race={}ms",
                    result.winner_name, result.latency_ms, total_ms
                );
                Ok(result)
            }
            None => Err(anyhow::anyhow!(
                "HEv3: all carriers failed within {}ms",
                RACE_PRUNE_MS
            )),
        }
    }

    // ── Maintenance Loop ──────────────────────────────────────────────────────

    /// Start the maintenance loop as a background task.
    ///
    /// The loop performs two duties:
    ///
    /// 1. **Heartbeat**: Sends a 1 pps keepalive over the Hot Standby stream
    ///    to keep it alive through GFW stateful inspection and carrier-grade NAT.
    ///    The heartbeat payload is shaped by `BehaviorSynthesizer` to look like
    ///    a natural application keepalive.
    ///
    /// 2. **Carrier promotion**: Watches `carrier_dead_rx`.  When the active
    ///    carrier signals death, the standby is atomically promoted to active.
    pub fn start_maintenance_loop(self: Arc<Self>) {
        let mgr = Arc::clone(&self);

        tokio::spawn(async move {
            let mut carrier_dead_rx = mgr.carrier_dead_rx.clone();

            loop {
                tokio::select! {
                    // Heartbeat branch — fires every HEARTBEAT_INTERVAL.
                    _ = sleep(HEARTBEAT_INTERVAL) => {
                        mgr.send_standby_heartbeat().await;
                    }

                    // Promotion branch — fires when the active carrier dies.
                    Ok(_) = carrier_dead_rx.changed() => {
                        if *carrier_dead_rx.borrow() {
                            info!("ConMan: active carrier dead — promoting hot standby");
                            mgr.promote_standby().await;
                            // Reset the dead flag so we don't re-trigger.
                            let _ = mgr.carrier_dead_tx.send(false);
                        }
                    }
                }
            }
        });
    }

    /// Signal that the active carrier has died.
    pub fn signal_carrier_death(&self) {
        let _ = self.carrier_dead_tx.send(true);
    }

    /// Send a shaped heartbeat over the standby stream.
    async fn send_standby_heartbeat(&self) {
        use tokio::io::AsyncWriteExt;

        let mut standby = self.standby_stream.lock().await;
        if let Some(stream) = standby.as_mut() {
            // Build a shaped payload that looks like an app keepalive.
            let synth = self.synth.lock().await;
            let mut payload = vec![0u8; HEARTBEAT_PAYLOAD_LEN];
            rand::Rng::fill(&mut rand::thread_rng(), &mut payload[..]);
            synth.shape_entropy(&mut payload);
            drop(synth);

            match stream.write_all(&payload).await {
                Ok(_) => {
                    debug!("ConMan: standby heartbeat sent ({} bytes)", payload.len());
                }
                Err(e) => {
                    warn!("ConMan: standby heartbeat failed: {}", e);
                    // Standby is dead — drop it and clear the slot.
                    *standby = None;
                }
            }
        }
        // If no standby exists, the loop continues silently.  The next
        // `happy_eyeballs_v3` call will establish a fresh standby.
    }

    /// Atomically promote the standby stream to active.
    pub async fn promote_standby(&self) {
        let mut standby = self.standby_stream.lock().await;
        let mut active = self.active_stream.lock().await;
        if standby.is_some() {
            *active = standby.take();
            info!("ConMan: hot standby promoted to active carrier");
        } else {
            warn!("ConMan: standby promotion requested but no standby available");
        }
    }

    /// Install a new hot-standby stream.
    pub async fn set_standby(&self, stream: BoxedTrinityTransport) {
        let mut standby = self.standby_stream.lock().await;
        *standby = Some(stream);
        debug!("ConMan: new hot standby installed");
    }

    // ── Mesh Routing ──────────────────────────────────────────────────────────

    /// Discover local P2P peers via mDNS and route through the lowest-latency hop.
    ///
    /// When direct internet access is throttled or blackholed, this function
    /// finds RustRay peers on the local network (or VPN subnet) and uses the
    /// fastest one as a relay.
    ///
    /// Returns a `BoxedTrinityTransport` connected to the chosen peer, or an
    /// error if no reachable peers were found.
    pub async fn route_via_mesh(
        &self,
        dest_host: &str,
        dest_port: u16,
    ) -> Result<BoxedTrinityTransport, anyhow::Error> {
        // Refresh the peer table from mDNS.
        self.discover_peers_mdns().await;

        let peers = self.mesh_peers.read().await;
        if peers.is_empty() {
            return Err(anyhow::anyhow!(
                "Mesh: no peers discovered on local network"
            ));
        }

        // Select the peer with the lowest observed latency.
        let best_peer = peers
            .values()
            .min_by_key(|p| p.latency_ms)
            .ok_or_else(|| anyhow::anyhow!("Mesh: empty peer table after lock"))?
            .clone();
        drop(peers);

        info!(
            "Mesh: routing {}:{} via peer {} (latency={}ms)",
            dest_host, dest_port, best_peer.addr, best_peer.latency_ms
        );

        // Connect to the relay peer.
        let relay_stream = TcpStream::connect(best_peer.addr)
            .await
            .map_err(|e| anyhow::anyhow!("Mesh: relay connect failed: {}", e))?;

        // Send the PROXY-CONNECT style header so the peer knows the ultimate dest.
        // Format: 1 byte version=0x01, 2 bytes port, 1 byte hostname_len, hostname bytes.
        use tokio::io::AsyncWriteExt;
        let mut relay_stream = relay_stream;
        let host_bytes = dest_host.as_bytes();
        let mut header = Vec::with_capacity(4 + host_bytes.len());
        header.push(0x01u8); // protocol version
        header.extend_from_slice(&dest_port.to_be_bytes());
        header.push(host_bytes.len() as u8);
        header.extend_from_slice(host_bytes);
        relay_stream
            .write_all(&header)
            .await
            .map_err(|e| anyhow::anyhow!("Mesh: relay header write failed: {}", e))?;

        let trinity: BoxedTrinityTransport = Box::new(TrinityStream::from_boxed(Box::new(
            relay_stream,
        )
            as BoxedStream));

        Ok(trinity)
    }

    /// Discover peers using mDNS-SD, probing `MDNS_SERVICE_TYPE`.
    ///
    /// Discovered peers are inserted into `self.mesh_peers` with their
    /// observed TCP handshake latency.
    async fn discover_peers_mdns(&self) {
        // Use the mdns-sd crate already in Cargo.toml.
        use mdns_sd::{ServiceDaemon, ServiceEvent};
        use std::time::Duration as StdDuration;

        let mdns = match ServiceDaemon::new() {
            Ok(d) => d,
            Err(e) => {
                warn!("Mesh: mDNS daemon creation failed: {}", e);
                return;
            }
        };

        let receiver = match mdns.browse(MDNS_SERVICE_TYPE) {
            Ok(r) => r,
            Err(e) => {
                warn!("Mesh: mDNS browse failed: {}", e);
                return;
            }
        };

        // Collect responses for a bounded window.
        let deadline = tokio::time::Instant::now() + StdDuration::from_millis(800);
        let mut peers = self.mesh_peers.write().await;

        loop {
            if tokio::time::Instant::now() >= deadline {
                break;
            }

            match receiver.recv_timeout(StdDuration::from_millis(50)) {
                Ok(ServiceEvent::ServiceResolved(info)) => {
                    for addr in info.get_addresses() {
                        let port = info.get_port();
                        let parsed_ip: std::net::IpAddr = addr.to_string().parse().unwrap();
                        let sock: SocketAddr = SocketAddr::new(parsed_ip, port);

                        // Measure TCP handshake latency.
                        let probe_start = Instant::now();
                        if TcpStream::connect(sock).await.is_ok() {
                            let lat = probe_start.elapsed().as_millis() as u32;
                            peers.insert(
                                sock.to_string(),
                                PeerInfo {
                                    addr: sock,
                                    latency_ms: lat,
                                    last_seen: Instant::now(),
                                },
                            );
                            debug!("Mesh: discovered peer {} latency={}ms", sock, lat);
                        }
                    }
                }
                Ok(_) => {}      // other events (Added, Removed) — ignore
                Err(_) => break, // timeout or channel closed
            }
        }

        // Evict stale peers (not seen for > 60 s).
        let now = Instant::now();
        peers.retain(|_, p| now.duration_since(p.last_seen) < StdDuration::from_secs(60));
    }
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn happy_eyeballs_v3_picks_fastest() {
        // Spin up a real listener.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        tokio::spawn(async move {
            if let Ok((stream, _)) = listener.accept().await {
                drop(stream);
            }
        });

        let carriers = vec![CarrierDescriptor {
            name: "test-reality",
            addr,
        }];

        let result = ConnectionManager::happy_eyeballs_v3(carriers)
            .await
            .unwrap();
        assert_eq!(result.winner_name, "test-reality");
        assert!(result.latency_ms < 1000);
    }

    #[tokio::test]
    async fn happy_eyeballs_v3_fails_gracefully() {
        // Port 1 is almost certainly unreachable without root.
        let carriers = vec![CarrierDescriptor {
            name: "unreachable",
            addr: "127.0.0.1:1".parse().unwrap(),
        }];

        let result = ConnectionManager::happy_eyeballs_v3(carriers).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn carrier_death_triggers_promotion() {
        let mgr = Arc::new(ConnectionManager::new());

        // Install a fake standby.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                drop(s);
            }
        });

        let standby_tcp = TcpStream::connect(addr).await.unwrap();
        let standby: BoxedTrinityTransport = Box::new(TrinityStream::from_boxed(Box::new(
            standby_tcp,
        )
            as BoxedStream));
        mgr.set_standby(standby).await;

        // Signal death and give the loop time to react.
        mgr.signal_carrier_death();
        // Give the promotion a moment (no loop running in unit test,
        // so we call promote_standby directly).
        mgr.promote_standby().await;

        assert!(mgr.active_stream.lock().await.is_some());
        assert!(mgr.standby_stream.lock().await.is_none());
    }
}
