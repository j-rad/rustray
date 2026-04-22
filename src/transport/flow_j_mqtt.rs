// src/transport/flow_j_mqtt.rs
//! Flow-J MQTT Transport Implementation
//!
//! Mode C: IoT Camouflage using MQTT v5 tunneling.
//! Traffic is encapsulated inside MQTT Publish packets disguised as sensor data.
//!
//! Topics:
//! - Upload: sensors/temperature/... (client -> server)
//! - Download: sensors/firmware/... (server -> client)

use crate::error::Result;
use crate::protocols::flow_j::MqttSettings;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use bytes::{Buf, BytesMut};
use hkdf::Hkdf;
use rand::{Rng, RngCore as _};
use rumqttc::{AsyncClient, Event, MqttOptions, Publish, QoS};
use sha2::Sha256;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

// ============================================================================
// CONSTANTS
// ============================================================================

#[allow(dead_code)]
const DEFAULT_UPLOAD_TOPIC: &str = "sensors/temperature";
#[allow(dead_code)]
const DEFAULT_DOWNLOAD_TOPIC: &str = "sensors/firmware";
const DEFAULT_BROKER_PORT: u16 = 8883;

// Maximum payload size for MQTT messages
const MAX_MQTT_PAYLOAD: usize = 65536;

// ============================================================================
// MQTT TUNNEL
// ============================================================================

/// MQTT tunnel for Flow-J traffic
pub struct MqttTunnel {
    /// MQTT client
    client: AsyncClient,
    /// Session ID for topic routing
    session_id: String,
    /// Upload topic
    upload_topic: String,
    /// Download topic
    #[allow(dead_code)]
    download_topic: String,
    /// Receive channel for incoming data
    rx: mpsc::Receiver<Vec<u8>>,
}

impl MqttTunnel {
    /// Create new MQTT tunnel
    pub async fn connect(settings: &MqttSettings) -> Result<Self> {
        // Parse broker address
        let (host, port) = parse_broker_address(&settings.broker)?;

        // Generate session ID
        let session_id = generate_session_id();

        // Create MQTT options
        let client_id = settings.client_id.as_deref().unwrap_or("flow-j-client");

        let mut mqtt_options =
            MqttOptions::new(format!("{}-{}", client_id, &session_id[..8]), host, port);

        mqtt_options.set_keep_alive(Duration::from_secs(30));
        mqtt_options.set_clean_session(true);

        // Set credentials if provided
        if let (Some(username), Some(password)) = (&settings.username, &settings.password) {
            mqtt_options.set_credentials(username, password);
        }

        // Create topics with session ID
        let upload_topic = format!("{}/{}/data", settings.upload_topic.as_str(), session_id);
        let download_topic = format!("{}/{}/data", settings.download_topic.as_str(), session_id);

        // Create channel for incoming data
        let (tx, rx) = mpsc::channel(128);

        // Create MQTT client
        let (client, mut eventloop) = AsyncClient::new(mqtt_options, 128);

        // Subscribe to download topic
        let qos = match settings.qos {
            0 => QoS::AtMostOnce,
            1 => QoS::AtLeastOnce,
            _ => QoS::ExactlyOnce,
        };

        client.subscribe(&download_topic, qos).await?;

        debug!("Flow-J MQTT: Connected, subscribed to {}", download_topic);

        // Spawn event loop handler
        let download_topic_clone = download_topic.clone();
        tokio::spawn(async move {
            loop {
                match eventloop.poll().await {
                    Ok(Event::Incoming(rumqttc::Packet::Publish(publish))) => {
                        if publish.topic == download_topic_clone {
                            // Extract payload and send to channel
                            let data = publish.payload.to_vec();
                            if tx.send(data).await.is_err() {
                                debug!("Flow-J MQTT: Receive channel closed");
                                break;
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        warn!("Flow-J MQTT: Event loop error: {}", e);
                        // Reconnect logic could be added here
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        });

        // Spawn shadow telemetry task (Phase 3)
        let shadow_client = client.clone();
        let shadow_topic = upload_topic.clone();
        tokio::spawn(async move {
            loop {
                use rand::Rng;
                let delay = rand::thread_rng().gen_range(45..=120);
                tokio::time::sleep(Duration::from_secs(delay)).await;

                let sensor_type = match rand::thread_rng().gen_range(0..4) {
                    0 => "temperature",
                    1 => "humidity",
                    2 => "heartbeat",
                    _ => "status",
                };

                let val = rand::thread_rng().gen_range(20..80);
                let fake_data = format!("{{\"val\":{},\"state\":\"ok\"}}", val);
                let payload = create_iot_payload(fake_data.as_bytes(), sensor_type);

                if let Err(e) = shadow_client
                    .publish(&shadow_topic, QoS::AtMostOnce, false, payload)
                    .await
                {
                    debug!("Flow-J MQTT: Shadow telemetry failed: {}", e);
                } else {
                    debug!("Flow-J MQTT: Published shadow telemetry");
                }
            }
        });

        Ok(Self {
            client,
            session_id,
            upload_topic,
            download_topic,
            rx,
        })
    }

    /// Send data through MQTT tunnel
    pub async fn send(&self, data: &[u8]) -> Result<()> {
        // Encode data with framing
        let framed = frame_data(data);

        // Split into chunks if necessary
        for chunk in framed.chunks(MAX_MQTT_PAYLOAD) {
            self.client
                .publish(&self.upload_topic, QoS::AtLeastOnce, false, chunk)
                .await?;
        }

        Ok(())
    }

    /// Receive data from MQTT tunnel
    pub async fn receive(&mut self) -> Result<Vec<u8>> {
        match self.rx.recv().await {
            Some(data) => {
                // Decode framed data
                let decoded = unframe_data(&data)?;
                Ok(decoded)
            }
            None => Err(anyhow::anyhow!("MQTT receive channel closed")),
        }
    }

    /// Get session ID
    pub fn session_id(&self) -> &str {
        &self.session_id
    }
}

// ============================================================================
// MQTT STREAM
// ============================================================================

use futures::SinkExt;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::sync::PollSender;

// ...

/// Async stream wrapper for MQTT tunnel
pub struct MqttStream {
    _tunnel: Arc<Mutex<MqttTunnel>>,
    read_buffer: BytesMut,
    _write_buffer: BytesMut,
    read_rx: mpsc::Receiver<Vec<u8>>,
    write_tx: PollSender<Vec<u8>>,
}

impl MqttStream {
    /// Create new MQTT stream from tunnel
    pub fn new(tunnel: MqttTunnel) -> Self {
        let tunnel = Arc::new(Mutex::new(tunnel));

        let (read_tx, read_rx) = mpsc::channel::<Vec<u8>>(128);
        let (write_tx_inner, mut write_rx) = mpsc::channel::<Vec<u8>>(128);

        // Spawn write task
        let write_tunnel = tunnel.clone();
        tokio::spawn(async move {
            while let Some(data) = write_rx.recv().await {
                // If tunnel mutex is locked for long, this might block?
                // MqttTunnel::send is async.
                let tunnel = write_tunnel.lock().await;
                if let Err(e) = tunnel.send(&data).await {
                    warn!("Flow-J MQTT: Write error: {}", e);
                    break;
                }
            }
        });

        // Spawn read task
        let read_tunnel = tunnel.clone();
        tokio::spawn(async move {
            loop {
                let data_result = {
                    let mut tunnel = read_tunnel.lock().await;
                    tunnel.receive().await
                };

                match data_result {
                    Ok(data) if !data.is_empty() => {
                        if read_tx.send(data).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(e) => {
                        debug!("Flow-J MQTT: Read channel closed: {}", e);
                        break;
                    }
                }
            }
        });

        Self {
            _tunnel: tunnel,
            read_buffer: BytesMut::with_capacity(65536),
            _write_buffer: BytesMut::with_capacity(65536),
            read_rx,
            write_tx: PollSender::new(write_tx_inner),
        }
    }
}

impl AsyncRead for MqttStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // 1. Drain read_buffer first
        if !self.read_buffer.is_empty() {
            let len = std::cmp::min(self.read_buffer.len(), buf.remaining());
            buf.put_slice(&self.read_buffer[..len]);
            self.read_buffer.advance(len);
            return Poll::Ready(Ok(()));
        }

        // 2. Poll receiver
        match self.read_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                if data.len() <= buf.remaining() {
                    buf.put_slice(&data);
                } else {
                    let len = buf.remaining();
                    buf.put_slice(&data[..len]);
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
        // Try to push to sink
        // Since we use a PollSender over mpsc, start_send should be enough if checked with poll_ready
        // But we want to buffer small writes?
        // Let's assume MqttTunnel handles fragmentation (MAX_MQTT_PAYLOAD).
        // Sending Vec over mpsc is cheap move.

        if let Err(e) = std::task::ready!(self.write_tx.poll_ready_unpin(cx)) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e)));
        }

        let data = buf.to_vec();
        if let Err(e) = self.write_tx.start_send_unpin(data) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e)));
        }

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match std::task::ready!(self.write_tx.poll_flush_unpin(cx)) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e))),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match std::task::ready!(self.write_tx.poll_close_unpin(cx)) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e))),
        }
    }
}

// ============================================================================
// STEALTH MQTT STREAM
// ============================================================================

/// Async stream wrapper for Stealth MQTT tunnel
pub struct StealthMqttStream {
    _tunnel: Arc<Mutex<StealthMqttTunnel>>,
    read_buffer: BytesMut,
    _write_buffer: BytesMut,
    read_rx: mpsc::Receiver<Vec<u8>>,
    write_tx: PollSender<Vec<u8>>,
}

impl StealthMqttStream {
    /// Create new Stealth MQTT stream from tunnel
    pub fn new(tunnel: StealthMqttTunnel) -> Self {
        let tunnel = Arc::new(Mutex::new(tunnel));

        let (read_tx, read_rx) = mpsc::channel::<Vec<u8>>(128);
        let (write_tx_inner, mut write_rx) = mpsc::channel::<Vec<u8>>(128);

        // Spawn write task
        let write_tunnel = tunnel.clone();
        tokio::spawn(async move {
            while let Some(data) = write_rx.recv().await {
                let mut tunnel = write_tunnel.lock().await;
                if let Err(e) = tunnel.send(&data).await {
                    warn!("Flow-J Stealth MQTT: Write error: {}", e);
                    break;
                }
            }
        });

        // Spawn read task
        let read_tunnel = tunnel.clone();
        tokio::spawn(async move {
            loop {
                let data_result = {
                    let mut tunnel = read_tunnel.lock().await;
                    tunnel.receive().await
                };

                match data_result {
                    Ok(data) if !data.is_empty() => {
                        if read_tx.send(data).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    Err(e) => {
                        debug!("Flow-J Stealth MQTT: Read channel closed: {}", e);
                        break;
                    }
                }
            }
        });

        Self {
            _tunnel: tunnel,
            read_buffer: BytesMut::with_capacity(65536),
            _write_buffer: BytesMut::with_capacity(65536),
            read_rx,
            write_tx: PollSender::new(write_tx_inner),
        }
    }
}

impl AsyncRead for StealthMqttStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.read_buffer.is_empty() {
            let len = std::cmp::min(self.read_buffer.len(), buf.remaining());
            buf.put_slice(&self.read_buffer[..len]);
            self.read_buffer.advance(len);
            return Poll::Ready(Ok(()));
        }

        match self.read_rx.poll_recv(cx) {
            Poll::Ready(Some(data)) => {
                if data.len() <= buf.remaining() {
                    buf.put_slice(&data);
                } else {
                    let len = buf.remaining();
                    buf.put_slice(&data[..len]);
                    self.read_buffer.extend_from_slice(&data[len..]);
                }
                Poll::Ready(Ok(()))
            }
            Poll::Ready(None) => Poll::Ready(Ok(())), // EOF
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for StealthMqttStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(e) = std::task::ready!(self.write_tx.poll_ready_unpin(cx)) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e)));
        }

        let data = buf.to_vec();
        if let Err(e) = self.write_tx.start_send_unpin(data) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e)));
        }

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match std::task::ready!(self.write_tx.poll_flush_unpin(cx)) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e))),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match std::task::ready!(self.write_tx.poll_close_unpin(cx)) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(io::Error::new(io::ErrorKind::BrokenPipe, e))),
        }
    }
}

// ============================================================================
// MQTT SERVER
// ============================================================================

/// MQTT server for handling Flow-J connections
pub struct MqttServer {
    settings: MqttSettings,
    sessions: Arc<Mutex<HashMap<String, mpsc::Sender<Vec<u8>>>>>,
}

impl MqttServer {
    /// Create new MQTT server
    pub fn new(settings: MqttSettings) -> Self {
        Self {
            settings,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Start MQTT server
    pub async fn run(&self) -> Result<()> {
        let (host, port) = parse_broker_address(&self.settings.broker)?;

        let mut mqtt_options = MqttOptions::new("flow-j-server", host, port);
        mqtt_options.set_keep_alive(Duration::from_secs(60));

        if let (Some(username), Some(password)) = (&self.settings.username, &self.settings.password)
        {
            mqtt_options.set_credentials(username, password);
        }

        let (client, mut eventloop) = AsyncClient::new(mqtt_options, 128);

        // Subscribe to upload topics with wildcard
        let upload_pattern = format!("{}/#", self.settings.upload_topic);
        client.subscribe(&upload_pattern, QoS::AtLeastOnce).await?;

        info!(
            "Flow-J MQTT Server: Listening on pattern {}",
            upload_pattern
        );

        let _sessions = self.sessions.clone();
        let download_topic_base = self.settings.download_topic.clone();

        loop {
            match eventloop.poll().await {
                Ok(Event::Incoming(rumqttc::Packet::Publish(publish))) => {
                    self.handle_publish(&client, publish, &download_topic_base)
                        .await;
                }
                Ok(_) => {}
                Err(e) => {
                    warn!("Flow-J MQTT Server: Event loop error: {}", e);
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }

    /// Handle incoming MQTT publish
    /// Routes payload to destination and sends response back
    async fn handle_publish(
        &self,
        client: &AsyncClient,
        publish: Publish,
        download_topic_base: &str,
    ) {
        // Extract session ID from topic
        let parts: Vec<&str> = publish.topic.split('/').collect();
        if parts.len() < 3 {
            return;
        }

        let session_id = parts[parts.len() - 2];
        let payload = publish.payload.to_vec();

        debug!(
            "Flow-J MQTT Server: Received {} bytes for session {}",
            payload.len(),
            session_id
        );

        // Parse Flow-J header if present
        if payload.len() >= 4 && &payload[0..4] == b"FJ01" {
            // This is a Flow-J framed message
            // Parse header to extract destination
            if let Ok((header, _consumed)) = crate::protocols::flow_j::FlowJHeader::decode(&payload)
            {
                debug!("Flow-J MQTT: Routing to {}:{}", header.address, header.port);

                // In production, we would:
                // 1. Connect to the target destination
                // 2. Forward the payload (after header)
                // 3. Read response from target
                // 4. Send response back via MQTT

                let response_topic = format!("{}/{}/data", download_topic_base, session_id);

                // For now, send acknowledgment
                let ack = format!("ACK:{}:{}", header.address, header.port);
                if let Err(e) = client
                    .publish(&response_topic, QoS::AtLeastOnce, false, ack.as_bytes())
                    .await
                {
                    warn!("Flow-J MQTT Server: Failed to send ack: {}", e);
                }

                return;
            }
        }

        // For non-Flow-J payloads, extract from IoT wrapper if present
        let data = if let Ok(extracted) = extract_iot_payload(&payload) {
            extracted
        } else {
            payload.clone()
        };

        // Echo back with IoT-style wrapper for camouflage
        let response_topic = format!("{}/{}/data", download_topic_base, session_id);
        let response = create_iot_payload(&data, "firmware");

        if let Err(e) = client
            .publish(&response_topic, QoS::AtLeastOnce, false, response)
            .await
        {
            warn!("Flow-J MQTT Server: Failed to send response: {}", e);
        }
    }
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Parse broker address into host and port
fn parse_broker_address(addr: &str) -> Result<(String, u16)> {
    // Handle formats like "broker:8883" or just "broker"
    if let Some((host, port_str)) = addr.rsplit_once(':') {
        let port = port_str.parse().unwrap_or(DEFAULT_BROKER_PORT);
        Ok((host.to_string(), port))
    } else {
        Ok((addr.to_string(), DEFAULT_BROKER_PORT))
    }
}

/// Generate random session ID
fn generate_session_id() -> String {
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Frame data for MQTT transport
/// Format: [length: u32 BE][data]
fn frame_data(data: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(4 + data.len());
    framed.extend_from_slice(&(data.len() as u32).to_be_bytes());
    framed.extend_from_slice(data);
    framed
}

/// Unframe data from MQTT transport
fn unframe_data(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 4 {
        return Err(anyhow::anyhow!("Frame too short"));
    }

    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;

    if data.len() < 4 + len {
        return Err(anyhow::anyhow!("Incomplete frame"));
    }

    Ok(data[4..4 + len].to_vec())
}

/// Create IoT-style payload wrapper
/// Makes traffic look like sensor data
fn create_iot_payload(data: &[u8], sensor_type: &str) -> Vec<u8> {
    // JSON wrapper to disguise as sensor data
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let data_b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data);

    let json = format!(
        r#"{{"sensor":"{}","timestamp":{},"data":"{}"}}"#,
        sensor_type, timestamp, data_b64
    );

    json.into_bytes()
}

/// Extract data from IoT-style payload
fn extract_iot_payload(payload: &[u8]) -> Result<Vec<u8>> {
    let json_str = std::str::from_utf8(payload)?;

    // Simple JSON parsing for "data" field
    if let Some(start) = json_str.find(r#""data":""#) {
        let start = start + 8;
        if let Some(end) = json_str[start..].find('"') {
            let data_b64 = &json_str[start..start + end];
            let decoded =
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, data_b64)?;
            return Ok(decoded);
        }
    }

    // If not IoT format, return as-is
    Ok(payload.to_vec())
}

// ============================================================================
// STEALTH TOPIC ROTATOR
// ============================================================================

/// Iranian SCADA / smart-home topic corpus (48 entries).
///
/// All entries are plausible paths that appear on public MQTT brokers observed
/// inside Iran (IRANCELL IoT pilots, industrial SCADA deployments).
const TOPIC_CORPUS: &[&str] = &[
    "home/living_room/co2",
    "home/kitchen/temperature",
    "home/bedroom/humidity",
    "home/entrance/motion",
    "home/balcony/light_level",
    "home/garage/door_state",
    "factory/conveyor_1/speed_rpm",
    "factory/press_line_4/vibration",
    "factory/boiler_3/pressure_bar",
    "factory/hvac_zone2/setpoint",
    "factory/tank_level/litre",
    "factory/compressor/temp_c",
    "building/floor_2/energy_kwh",
    "building/elevator/door_cycles",
    "building/parking/occupancy",
    "building/access/badge_events",
    "agri/field_7/soil_moisture",
    "agri/greenhouse_1/co2_ppm",
    "agri/pump_station/flow_lpm",
    "agri/weather/wind_speed",
    "agri/silo_a/grain_temp",
    "agri/irrigation/valve_state",
    "city/traffic/junction_12_count",
    "city/air/pm25_ug_m3",
    "city/water/pipe_pressure",
    "city/bin/fill_pct",
    "city/lamp/status",
    "city/solar/output_w",
    "vehicle/bus_47/gps_lat",
    "vehicle/bus_47/gps_lon",
    "vehicle/truck_21/engine_temp",
    "vehicle/truck_21/fuel_pct",
    "energy/solar_roof/generation_w",
    "energy/battery/soc_pct",
    "energy/grid/import_w",
    "energy/heat_pump/cop",
    "hospital/ward_3/bed_occupancy",
    "hospital/pharmacy/fridge_temp",
    "hospital/generator/fuel_pct",
    "retail/freezer_aisle/temp_c",
    "retail/pos/tx_count",
    "retail/hvac/return_air_temp",
    "telecom/tower_19/vswr",
    "telecom/tower_19/power_dbm",
    "telecom/ups_room/load_pct",
    "telecom/battery_bank/voltage",
    "telecom/ac_unit/inlet_temp",
];

/// Rotation period in seconds.
const ROTATION_PERIOD_SECS: u64 = 90;

/// Deterministic MQTT topic rotator.
///
/// Both client and server call `current_pair()` independently and always
/// obtain the same `(upload, download)` topic names for the same epoch,
/// because they share the session key and wall-clock epoch bucket.
pub struct StealthTopicRotator {
    session_key: [u8; 32],
}

impl StealthTopicRotator {
    /// Create a rotator from a 32-byte session key.
    pub fn new(session_key: [u8; 32]) -> Self {
        Self { session_key }
    }

    /// Derive a corpus index for the given epoch and directional label.
    fn index_for_epoch(&self, epoch: u64, label: &[u8]) -> usize {
        let hk = Hkdf::<Sha256>::new(Some(&epoch.to_be_bytes()), &self.session_key);
        let mut okm = [0u8; 8];
        hk.expand(label, &mut okm)
            .expect("valid HKDF output length");
        (u64::from_be_bytes(okm) as usize) % TOPIC_CORPUS.len()
    }

    /// Current epoch (wall-clock seconds ÷ rotation period).
    pub fn current_epoch() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            / ROTATION_PERIOD_SECS
    }

    /// Return `(upload_topic, download_topic)` for the current epoch.
    ///
    /// Upload and download use different HKDF labels so they never collide.
    pub fn current_pair(&self) -> (String, String) {
        self.pair_for_epoch(Self::current_epoch())
    }

    /// Return topic pair for an explicit epoch (useful for testing).
    pub fn pair_for_epoch(&self, epoch: u64) -> (String, String) {
        let up_idx = self.index_for_epoch(epoch, b"upload");
        // Offset by half the corpus so upload != download.
        let dn_idx = (up_idx + TOPIC_CORPUS.len() / 2) % TOPIC_CORPUS.len();

        // Add dynamic randomization using HKDF
        let mut prk = [0u8; 8];
        let hk = Hkdf::<Sha256>::new(Some(&epoch.to_be_bytes()), &self.session_key);
        hk.expand(b"random-suffix", &mut prk).unwrap();
        let up_suffix_hex = hex::encode(&prk[..4]);
        let dn_suffix_hex = hex::encode(&prk[4..8]);

        let upload = format!("{}/{}", TOPIC_CORPUS[up_idx], up_suffix_hex);
        let download = format!("{}/{}", TOPIC_CORPUS[dn_idx], dn_suffix_hex);

        (upload, download)
    }

    /// 4-byte hex suffix derived from the session key for sub-topic namespacing.
    pub fn session_suffix(&self) -> String {
        hex::encode(&self.session_key[..4])
    }
}

// ============================================================================
// MQTT PAYLOAD CIPHER
// ============================================================================

/// Sensor type labels cycled through to vary the JSON wrapper.
const SENSOR_LABELS: &[&str] = &[
    "temperature",
    "humidity",
    "pressure",
    "co2",
    "vibration",
    "flow",
    "level",
    "energy",
];

/// Per-session AES-256-GCM cipher that wraps ciphertext in IoT JSON.
///
/// Wire format inside the `"v"` field (before base64):
/// ```text
/// [nonce 12 B][ciphertext + GCM-tag 16 B]
/// ```
pub struct MqttPayloadCipher {
    cipher: Aes256Gcm,
    counter: u64,
}

impl MqttPayloadCipher {
    /// Construct from a 32-byte AES-256 key.
    pub fn new(key: &[u8; 32]) -> Self {
        Self {
            cipher: Aes256Gcm::new_from_slice(key).expect("32-byte key is always valid"),
            counter: 0,
        }
    }

    fn next_sensor_label(&mut self) -> &'static str {
        let label = SENSOR_LABELS[self.counter as usize % SENSOR_LABELS.len()];
        self.counter = self.counter.wrapping_add(1);
        label
    }

    /// Encrypt `data` and return IoT-JSON-wrapped bytes ready to publish.
    pub fn encrypt_wrap(&mut self, data: &[u8]) -> Vec<u8> {
        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = self
            .cipher
            .encrypt(nonce, data)
            .expect("AES-256-GCM encryption is infallible for valid key/nonce");

        // wire = nonce || ciphertext (ciphertext already includes 16-byte GCM tag)
        let mut wire = Vec::with_capacity(12 + ciphertext.len());
        wire.extend_from_slice(&nonce_bytes);
        wire.extend_from_slice(&ciphertext);

        let b64 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &wire);

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let sensor = self.next_sensor_label();

        format!("{{\"sensor\":\"{sensor}\",\"ts\":{ts},\"v\":\"{b64}\"}}").into_bytes()
    }

    /// Unwrap IoT JSON and decrypt.
    ///
    /// Returns `Err` if the JSON is malformed, base64 is invalid, or the
    /// GCM authentication tag does not match (indicating tampering).
    pub fn decrypt_unwrap(&self, payload: &[u8]) -> Result<Vec<u8>> {
        let json = std::str::from_utf8(payload)
            .map_err(|e| anyhow::anyhow!("non-UTF8 MQTT payload: {e}"))?;

        // Locate the "v":"..." field.
        let key_marker = "\"v\":\"";
        let v_start = json
            .find(key_marker)
            .map(|i| i + key_marker.len())
            .ok_or_else(|| anyhow::anyhow!("missing 'v' field in MQTT JSON"))?;
        let v_end = json[v_start..]
            .find('"')
            .ok_or_else(|| anyhow::anyhow!("unterminated 'v' field in MQTT JSON"))?;
        let b64 = &json[v_start..v_start + v_end];

        let wire = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64)
            .map_err(|e| anyhow::anyhow!("base64 decode failed: {e}"))?;

        if wire.len() < 12 {
            return Err(anyhow::anyhow!(
                "MQTT payload too short for nonce (got {} B)",
                wire.len()
            ));
        }

        let (nonce_bytes, ct) = wire.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = self.cipher.decrypt(nonce, ct).map_err(|_| {
            anyhow::anyhow!("AES-256-GCM authentication failed — possible tampering")
        })?;

        Ok(plaintext)
    }
}

// ============================================================================
// STEALTH MQTT TUNNEL
// ============================================================================

/// Drop-in replacement for `MqttTunnel` with topic rotation and AES-256-GCM.
///
/// Obtain a session key from the `HybridAuthPacket` shared secret (Phase 1)
/// and pass it here.  The `send` / `receive` interface is unchanged.
pub struct StealthMqttTunnel {
    inner: MqttTunnel,
    rotator: StealthTopicRotator,
    cipher: MqttPayloadCipher,
    shaper: crate::protocols::stealth::ProbabilisticShaper,
    pacer: crate::protocols::stealth::MarkovJitter,
}

impl StealthMqttTunnel {
    /// Wrap an existing connected `MqttTunnel`.
    pub fn new(inner: MqttTunnel, session_key: [u8; 32], noise_intensity: f64) -> Self {
        Self {
            inner,
            rotator: StealthTopicRotator::new(session_key),
            cipher: MqttPayloadCipher::new(&session_key),
            shaper: crate::protocols::stealth::ProbabilisticShaper::with_intensity(noise_intensity),
            pacer: crate::protocols::stealth::MarkovJitter::new(),
        }
    }

    /// Shorthand: connect and return a stealth tunnel.
    pub async fn connect(settings: &MqttSettings, session_key: [u8; 32]) -> Result<Self> {
        let inner = MqttTunnel::connect(settings).await?;
        let rotator = StealthTopicRotator::new(session_key);

        // Spawn Shadow Telemetry Task
        let client_clone = inner.client.clone();
        let rotator_clone = StealthTopicRotator::new(session_key);
        let mut shadow_shaper = crate::protocols::stealth::ProbabilisticShaper::with_intensity(
            settings.noise_intensity,
        );
        let mut shadow_cipher = MqttPayloadCipher::new(&session_key);

        tokio::spawn(async move {
            loop {
                // Sleep for a random interval 1-10s
                let sleep_ms = rand::thread_rng().gen_range(1000..=10000);
                tokio::time::sleep(std::time::Duration::from_millis(sleep_ms)).await;

                let (upload_topic, _) = rotator_clone.current_pair();
                let suffix = rotator_clone.session_suffix();
                // Use a separate subtopic for shadow pings
                let topic = format!("{upload_topic}/{suffix}/s");

                // Fake JSON payload simulating sensor data heartbeat
                let fake_data = b"{\"hb\":1,\"status\":\"ok\"}";
                let shaped = shadow_shaper.shape_packet(fake_data);
                let payload = shadow_cipher.encrypt_wrap(&shaped);

                if client_clone
                    .publish(&topic, rumqttc::QoS::AtMostOnce, false, payload)
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });

        Ok(Self {
            inner,
            rotator,
            cipher: MqttPayloadCipher::new(&session_key),
            shaper: crate::protocols::stealth::ProbabilisticShaper::with_intensity(
                settings.noise_intensity,
            ),
            pacer: crate::protocols::stealth::MarkovJitter::new(),
        })
    }

    /// Encrypt `data`, apply probabilistic shaping, and publish to the current rotation topic.
    pub async fn send(&mut self, data: &[u8]) -> Result<()> {
        let (upload_topic, _) = self.rotator.current_pair();
        let suffix = self.rotator.session_suffix();
        let topic = format!("{upload_topic}/{suffix}/d");

        // Apply Gaussian noise padding
        let shaped = self.shaper.shape_packet(data);

        let payload = self.cipher.encrypt_wrap(&shaped);
        for chunk in payload.chunks(MAX_MQTT_PAYLOAD) {
            // Apply Pacing Engine delay before sending
            self.pacer.apply_jitter().await;

            self.inner
                .client
                .publish(&topic, rumqttc::QoS::AtLeastOnce, false, chunk)
                .await?;
        }
        Ok(())
    }

    /// Receive data, unwrap, decrypt, and strip shaping padding.
    pub async fn receive(&mut self) -> Result<Vec<u8>> {
        let raw = self.inner.receive().await?;
        let decrypted = self.cipher.decrypt_unwrap(&raw)?;

        // Strip Gaussian noise padding
        let unshaped = crate::protocols::stealth::ProbabilisticShaper::unshape_packet(&decrypted)
            .ok_or_else(|| anyhow::anyhow!("Failed to unshape MQTT payload"))?;

        Ok(unshaped.to_vec())
    }

    /// Session ID (for logging/metrics).
    pub fn session_id(&self) -> &str {
        self.inner.session_id()
    }
}

// ============================================================================
// MANUAL MQTT v3.1.1 PACKET CONSTRUCTION
// ============================================================================

/// Raw MQTT v3.1.1 `PUBLISH` control packet constructor.
///
/// Builds packets at the byte level (no external MQTT library required)
/// for maximum control over the wire format. This is used for the
/// Shadow Telemetry injector to produce protocol-compliant packets
/// that pass deep packet inspection without any library fingerprinting.
pub struct ManualMqttPacket;

impl ManualMqttPacket {
    /// Encode a variable-length field (MQTT Remaining Length encoding).
    ///
    /// MQTT uses a variable-length encoding where each byte encodes 7 bits
    /// of value and bit 7 indicates continuation.
    fn encode_remaining_length(len: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(4);
        let mut x = len;
        loop {
            let mut encoded_byte = (x % 128) as u8;
            x /= 128;
            if x > 0 {
                encoded_byte |= 0x80;
            }
            result.push(encoded_byte);
            if x == 0 {
                break;
            }
        }
        result
    }

    /// Construct a raw MQTT v3.1.1 PUBLISH packet.
    ///
    /// Fixed header format:
    /// ```text
    /// Byte 1: 0x30 | (DUP << 3) | (QoS << 1) | Retain
    /// Bytes 2-5: Remaining Length (variable)
    /// ```
    ///
    /// Variable header:
    /// ```text
    /// [Topic Length MSB][Topic Length LSB][Topic UTF-8 string]
    /// [Packet Identifier MSB][Packet Identifier LSB] (only if QoS > 0)
    /// ```
    ///
    /// Payload:
    /// ```text
    /// [Application message bytes]
    /// ```
    pub fn build_publish(topic: &str, payload: &[u8], qos: u8, retain: bool) -> Vec<u8> {
        let topic_bytes = topic.as_bytes();
        let topic_len = topic_bytes.len();

        // Calculate remaining length
        let mut remaining = 2 + topic_len + payload.len(); // 2 for topic length prefix
        if qos > 0 {
            remaining += 2; // packet identifier
        }

        let remaining_encoded = Self::encode_remaining_length(remaining);

        let mut packet = Vec::with_capacity(1 + remaining_encoded.len() + remaining);

        // Fixed header byte: PUBLISH = 0x30
        let mut fixed_byte: u8 = 0x30;
        fixed_byte |= (qos & 0x03) << 1;
        if retain {
            fixed_byte |= 0x01;
        }
        packet.push(fixed_byte);

        // Remaining length
        packet.extend_from_slice(&remaining_encoded);

        // Topic length (MSB, LSB)
        packet.push((topic_len >> 8) as u8);
        packet.push((topic_len & 0xFF) as u8);

        // Topic string
        packet.extend_from_slice(topic_bytes);

        // Packet identifier (only for QoS 1 or 2)
        if qos > 0 {
            let pkt_id: u16 = rand::thread_rng().gen_range(1..=65535);
            packet.push((pkt_id >> 8) as u8);
            packet.push((pkt_id & 0xFF) as u8);
        }

        // Payload
        packet.extend_from_slice(payload);

        packet
    }

    /// Build a MQTT v3.1.1 CONNECT packet for handshake.
    ///
    /// ```text
    /// Fixed header: 0x10 | Remaining Length
    /// Variable header: Protocol Name + Level + Connect Flags + Keep Alive
    /// Payload: Client Identifier
    /// ```
    pub fn build_connect(client_id: &str, keep_alive_secs: u16) -> Vec<u8> {
        let client_id_bytes = client_id.as_bytes();

        // Variable header: "MQTT" protocol name (7 bytes) + level(1) + flags(1) + keepalive(2) = 10 bytes
        // Payload: client ID length(2) + client ID bytes
        let remaining = 10 + 2 + client_id_bytes.len();
        let remaining_encoded = Self::encode_remaining_length(remaining);

        let mut packet = Vec::with_capacity(1 + remaining_encoded.len() + remaining);

        // Fixed header: CONNECT = 0x10
        packet.push(0x10);
        packet.extend_from_slice(&remaining_encoded);

        // Protocol Name: "MQTT" (length-prefixed UTF-8)
        packet.push(0x00); // Length MSB
        packet.push(0x04); // Length LSB
        packet.extend_from_slice(b"MQTT");

        // Protocol Level: 4 (MQTT 3.1.1)
        packet.push(0x04);

        // Connect Flags: Clean Session = 1
        packet.push(0x02);

        // Keep Alive (seconds)
        packet.push((keep_alive_secs >> 8) as u8);
        packet.push((keep_alive_secs & 0xFF) as u8);

        // Client Identifier (length-prefixed)
        packet.push((client_id_bytes.len() >> 8) as u8);
        packet.push((client_id_bytes.len() & 0xFF) as u8);
        packet.extend_from_slice(client_id_bytes);

        packet
    }
}

// ============================================================================
// GAUSSIAN SHADOW TELEMETRY
// ============================================================================

/// Gaussian-distributed shadow telemetry injector.
///
/// Generates fake IoT sensor data at intervals drawn from a Gaussian
/// distribution (mean=82.5s, σ=18.75s) to produce realistic-looking
/// traffic patterns that blend in with genuine IoT device behavior.
pub struct GaussianShadowTelemetry {
    /// Mean interval between shadow packets (seconds).
    mean_interval_secs: f64,
    /// Standard deviation of the interval (seconds).
    stddev_secs: f64,
    /// Monotonically increasing sequence number for realism.
    sequence: u64,
    /// Simulated battery level that slowly drains.
    battery_level: f64,
}

impl GaussianShadowTelemetry {
    /// Create with default IoT-realistic parameters.
    pub fn new() -> Self {
        Self {
            mean_interval_secs: 82.5,
            stddev_secs: 18.75,
            sequence: 0,
            battery_level: 100.0,
        }
    }

    /// Create with custom timing parameters.
    pub fn with_timing(mean_secs: f64, stddev_secs: f64) -> Self {
        Self {
            mean_interval_secs: mean_secs,
            stddev_secs,
            sequence: 0,
            battery_level: 100.0,
        }
    }

    /// Sample the next inter-packet delay from the Gaussian distribution.
    pub fn next_delay(&self) -> Duration {
        use rand_distr::{Distribution, Normal};
        let normal = Normal::new(self.mean_interval_secs, self.stddev_secs)
            .unwrap_or_else(|_| Normal::new(82.5, 18.75).unwrap());
        let raw: f64 = normal.sample(&mut rand::thread_rng());
        // Clamp to [10s, 300s] to avoid suspiciously short or long intervals
        let clamped = raw.clamp(10.0, 300.0);
        Duration::from_secs_f64(clamped)
    }

    /// Generate a realistic IoT telemetry JSON payload.
    pub fn generate_payload(&mut self) -> Vec<u8> {
        self.sequence += 1;

        // Slowly drain battery (realistic IoT behavior)
        self.battery_level = (self.battery_level - 0.001).max(10.0);
        let battery = self.battery_level as u32;

        let uptime_secs = self.sequence * 82; // ~82s per reading

        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Vary the sensor type for realism
        let sensor_types = [
            "temperature",
            "humidity",
            "pressure",
            "vibration",
            "co2",
            "flow",
        ];
        let sensor = sensor_types[self.sequence as usize % sensor_types.len()];

        // Generate realistic sensor values
        let value: f64 = match sensor {
            "temperature" => 20.0 + rand::thread_rng().gen_range(-2.0..2.0_f64),
            "humidity" => 45.0 + rand::thread_rng().gen_range(-5.0..5.0_f64),
            "pressure" => 1013.25 + rand::thread_rng().gen_range(-3.0..3.0_f64),
            "vibration" => 0.02 + rand::thread_rng().gen_range(0.0..0.05_f64),
            "co2" => 400.0 + rand::thread_rng().gen_range(-20.0..50.0_f64),
            _ => 12.5 + rand::thread_rng().gen_range(-1.0..1.0_f64),
        };

        format!(
            "{{\"sensor\":\"{}\",\"v\":{:.2},\"ts\":{},\"seq\":{},\"battery\":{},\"uptime\":{},\"status\":\"ok\"}}",
            sensor, value, ts, self.sequence, battery, uptime_secs
        )
        .into_bytes()
    }
}

impl Default for GaussianShadowTelemetry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// IOT PAYLOAD FRAGMENTER
// ============================================================================

/// Fragments proxy payload into IoT-sized windows (128–1024 bytes)
/// to match typical IoT sensor data transmission patterns.
pub struct IoTPayloadFragmenter {
    /// Minimum fragment size (bytes).
    min_fragment: usize,
    /// Maximum fragment size (bytes).
    max_fragment: usize,
}

impl IoTPayloadFragmenter {
    /// Create with default IoT-size windows.
    pub fn new() -> Self {
        Self {
            min_fragment: 128,
            max_fragment: 1024,
        }
    }

    /// Create with custom fragment size range.
    pub fn with_range(min: usize, max: usize) -> Self {
        Self {
            min_fragment: min.max(32),
            max_fragment: max.max(min),
        }
    }

    /// Fragment `data` into IoT-sized chunks.
    pub fn fragment(&self, data: &[u8]) -> Vec<Vec<u8>> {
        if data.is_empty() {
            return vec![];
        }

        let mut fragments = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            let remaining = data.len() - offset;
            let chunk_size = if remaining <= self.max_fragment {
                remaining
            } else {
                rand::thread_rng().gen_range(self.min_fragment..=self.max_fragment)
            };

            fragments.push(data[offset..offset + chunk_size].to_vec());
            offset += chunk_size;
        }

        fragments
    }
}

impl Default for IoTPayloadFragmenter {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_broker_address() {
        let (host, port) = parse_broker_address("mqtt.example.com:1883").unwrap();
        assert_eq!(host, "mqtt.example.com");
        assert_eq!(port, 1883);

        let (host, port) = parse_broker_address("localhost").unwrap();
        assert_eq!(host, "localhost");
        assert_eq!(port, DEFAULT_BROKER_PORT);
    }

    #[test]
    fn test_session_id_generation() {
        let id1 = generate_session_id();
        let id2 = generate_session_id();

        assert_eq!(id1.len(), 32); // 16 bytes = 32 hex chars
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_frame_unframe() {
        let data = b"Hello, MQTT world!";
        let framed = frame_data(data);

        assert_eq!(framed.len(), 4 + data.len());

        let unframed = unframe_data(&framed).unwrap();
        assert_eq!(unframed, data);
    }

    #[test]
    fn test_iot_payload() {
        let data = b"encrypted proxy data";
        let payload = create_iot_payload(data, "temperature");

        // Should be valid JSON
        let json_str = String::from_utf8(payload.clone()).unwrap();
        assert!(json_str.contains("sensor"));
        assert!(json_str.contains("temperature"));
        assert!(json_str.contains("timestamp"));
        assert!(json_str.contains("data"));

        // Should be extractable
        let extracted = extract_iot_payload(&payload).unwrap();
        assert_eq!(extracted, data);
    }

    // ------------------------------------------------------------------
    // Stealth topic rotator tests
    // ------------------------------------------------------------------

    #[test]
    fn test_topic_rotation_deterministic() {
        let key = [0x42u8; 32];
        let a = StealthTopicRotator::new(key);
        let b = StealthTopicRotator::new(key);

        // Same key + same epoch → identical pair.
        let epoch = 12345u64;
        assert_eq!(a.pair_for_epoch(epoch), b.pair_for_epoch(epoch));
    }

    #[test]
    fn test_topic_rotation_upload_ne_download() {
        let key = [0xABu8; 32];
        let rotator = StealthTopicRotator::new(key);

        // For every epoch in a 24-hour window, upload ≠ download.
        let base = StealthTopicRotator::current_epoch();
        let epochs_per_day = 86400 / ROTATION_PERIOD_SECS;
        for offset in 0..epochs_per_day {
            let (up, dn) = rotator.pair_for_epoch(base + offset);
            assert_ne!(up, dn, "epoch {} has upload == download", base + offset);
        }
    }

    #[test]
    fn test_topic_rotation_uses_corpus() {
        let key = [0x11u8; 32];
        let rotator = StealthTopicRotator::new(key);
        let epoch = 99999u64;
        let (up, dn) = rotator.pair_for_epoch(epoch);
        // up and dn match corpus prefix
        assert!(
            TOPIC_CORPUS.iter().any(|c| up.starts_with(c)),
            "upload topic not in corpus"
        );
        assert!(
            TOPIC_CORPUS.iter().any(|c| dn.starts_with(c)),
            "download topic not in corpus"
        );
    }

    // ------------------------------------------------------------------
    // MqttPayloadCipher tests
    // ------------------------------------------------------------------

    #[test]
    fn test_stealth_payload_round_trip() {
        let key = [0x5Cu8; 32];
        let mut enc = MqttPayloadCipher::new(&key);
        let dec = MqttPayloadCipher::new(&key);

        let plaintext = b"this is secret proxy traffic";
        let wrapped = enc.encrypt_wrap(plaintext);

        // The wrapped form should look like IoT JSON.
        let json = String::from_utf8(wrapped.clone()).unwrap();
        assert!(json.starts_with('{'), "expected JSON object");
        assert!(json.contains("\"sensor\""), "missing sensor field");
        assert!(json.contains("\"v\""), "missing v field");

        // Decryption must recover the original.
        let recovered = dec.decrypt_unwrap(&wrapped).expect("decrypt failed");
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn test_stealth_payload_tamper_detected() {
        let key = [0x7Fu8; 32];
        let mut enc = MqttPayloadCipher::new(&key);
        let dec = MqttPayloadCipher::new(&key);

        let mut wrapped = enc.encrypt_wrap(b"secret");

        // Flip a byte in the middle of the JSON value to simulate tampering.
        let mid = wrapped.len() / 2;
        wrapped[mid] ^= 0xFF;

        assert!(
            dec.decrypt_unwrap(&wrapped).is_err(),
            "tampered payload should fail decryption"
        );
    }
}
