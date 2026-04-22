// src/transport/mqtt_parasite.rs
use crate::error::Result;
use crate::protocols::flow_j::MqttSettings;

use bytes::BytesMut;
use futures::SinkExt;
use rand::Rng;
use rumqttc::{AsyncClient, Event, MqttOptions, QoS};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Mutex};
use tokio_util::sync::PollSender;
use tracing::{debug, warn};
use uuid::Uuid;

// Maximum payload size for an MQTT packet encapsulating Flow-J data
const MAX_MQTT_PAYLOAD: usize = 65536; // 64KB

pub struct MqttParasiteTunnel {
    client: AsyncClient,
    session_id: String,
    upload_topic: String,
    download_topic: String,
    rx: mpsc::Receiver<Vec<u8>>,
    settings: Arc<MqttSettings>,
}

impl MqttParasiteTunnel {
    pub async fn connect(settings: MqttSettings) -> Result<Self> {
        let (host, port_str) = if let Some((h, p)) = settings.broker.split_once(':') {
            (h.to_string(), p.to_string())
        } else {
            (settings.broker.clone(), "8883".to_string()) // Defaults to secure port
        };
        let port: u16 = port_str.parse().unwrap_or(8883);

        let session_id = Uuid::new_v4().to_string().replace("-", "");
        let client_id = settings.client_id.as_deref().unwrap_or("industrial_plc_01");
        
        let mut mqtt_options = MqttOptions::new(format!("{}_{}", client_id, &session_id[..8]), host, port);
        mqtt_options.set_keep_alive(Duration::from_secs(60));
        mqtt_options.set_clean_session(true);

        if let (Some(username), Some(password)) = (&settings.username, &settings.password) {
            mqtt_options.set_credentials(username, password);
        }

        // e.g. factory/mri/telemetry/up/session_id
        let upload_topic = format!("{}/up/{}", settings.upload_topic, session_id);
        let download_topic = format!("{}/down/{}", settings.download_topic, session_id);
        
        let (tx, rx) = mpsc::channel(128);
        
        let (client, mut eventloop) = AsyncClient::new(mqtt_options, 128);

        let qos = match settings.qos {
            0 => QoS::AtMostOnce,
            1 => QoS::AtLeastOnce,
            _ => QoS::ExactlyOnce,
        };

        client.subscribe(&download_topic, qos).await?;
        
        debug!("Flow-J MQTT Parasite: Connected. Subscribed to {}", download_topic);

        let download_topic_clone = download_topic.clone();
        
        tokio::spawn(async move {
            loop {
                match eventloop.poll().await {
                    Ok(Event::Incoming(rumqttc::Packet::Publish(publish))) => {
                        if publish.topic == download_topic_clone {
                            // Extract actual payload from outer industrial format
                            let data = Self::extract_payload(&publish.payload);
                            if tx.send(data).await.is_err() {
                                debug!("Flow-J MQTT Parasite: Receive channel closed.");
                                break;
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        warn!("Flow-J MQTT Parasite Event loop error: {}", e);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        });
        
        Ok(Self {
            client,
            session_id,
            upload_topic,
            download_topic,
            rx,
            settings: Arc::new(settings),
        })
    }

    pub async fn send(&self, data: &[u8]) -> Result<()> {
        let framed = Self::frame_data(data);
        
        for chunk in framed.chunks(MAX_MQTT_PAYLOAD) {
            let wrapped_payload = self.create_industrial_payload(chunk);
            self.client.publish(&self.upload_topic, QoS::AtLeastOnce, false, wrapped_payload).await?;
            
            // Match industrial hardware heartbeat (50ms - 100ms interval) to blend in
            let heartbeat_delay = rand::thread_rng().gen_range(50..=100);
            tokio::time::sleep(Duration::from_millis(heartbeat_delay)).await;
        }
        Ok(())
    }

    pub async fn receive(&mut self) -> Result<Vec<u8>> {
        match self.rx.recv().await {
            Some(data) => Self::unframe_data(&data),
            None => Err(anyhow::anyhow!("MQTT parasite receive channel closed")),
        }
    }
    
    // Formatting & Obfuscation
    
    fn create_industrial_payload(&self, data: &[u8]) -> Vec<u8> {
        let b64_data = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, data);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
            
        // Disguise as factory telemetry JSON
        let json = format!(
            r#"{{"sensor_id":"{}","ts_ms":{},"volt_mv":{},"stat":"ok","payload":"{}"}}"#,
            self.session_id,
            timestamp,
            rand::thread_rng().gen_range(23000..24500), // ~24V industrial supply
            b64_data
        );
        json.into_bytes()
    }
    
    fn extract_payload(wrapped: &[u8]) -> Vec<u8> {
        if let Ok(json_str) = std::str::from_utf8(wrapped) {
            if let Some(start) = json_str.find(r#""payload":""#) {
                let start = start + 11;
                if let Some(end) = json_str[start..].find('"') {
                    let b64 = &json_str[start..start + end];
                    if let Ok(decoded) = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64) {
                        return decoded;
                    }
                }
            }
        }
        wrapped.to_vec() // Fallback to raw if unparseable
    }

    fn frame_data(data: &[u8]) -> Vec<u8> {
        let mut framed = Vec::with_capacity(4 + data.len());
        framed.extend_from_slice(&(data.len() as u32).to_be_bytes());
        framed.extend_from_slice(data);
        framed
    }

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
}

pub struct MqttParasiteStream {
    tunnel: Arc<Mutex<MqttParasiteTunnel>>,
    read_buffer: BytesMut,
    write_buffer: BytesMut,
    read_rx: mpsc::Receiver<Vec<u8>>,
    write_tx: PollSender<Vec<u8>>,
}

impl MqttParasiteStream {
    pub fn new(tunnel: MqttParasiteTunnel) -> Self {
        let tunnel = Arc::new(Mutex::new(tunnel));
        
        let (read_tx, read_rx) = mpsc::channel::<Vec<u8>>(128);
        let (write_tx_inner, mut write_rx) = mpsc::channel::<Vec<u8>>(128);

        let write_tunnel = tunnel.clone();
        tokio::spawn(async move {
            while let Some(data) = write_rx.recv().await {
                let t = write_tunnel.lock().await;
                if let Err(e) = t.send(&data).await {
                    warn!("Flow-J MQTT Parasite: Write error: {}", e);
                    break;
                }
            }
        });

        let read_tunnel = tunnel.clone();
        tokio::spawn(async move {
            loop {
                let data_result = {
                    let mut t = read_tunnel.lock().await;
                    t.receive().await
                };
                match data_result {
                    Ok(data) if !data.is_empty() => {
                        if read_tx.send(data).await.is_err() { break; }
                    }
                    Ok(_) => tokio::time::sleep(Duration::from_millis(10)).await,
                    Err(e) => {
                        debug!("Flow-J MQTT Parasite: Read channel closed: {}", e);
                        break;
                    }
                }
            }
        });

        Self {
            tunnel,
            read_buffer: BytesMut::with_capacity(65536),
            write_buffer: BytesMut::new(),
            read_rx,
            write_tx: PollSender::new(write_tx_inner),
        }
    }
}

impl AsyncRead for MqttParasiteStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.read_buffer.is_empty() {
            let len = std::cmp::min(self.read_buffer.len(), buf.remaining());
            buf.put_slice(&self.read_buffer[..len]);
            let remaining = self.read_buffer.split_off(len);
            self.read_buffer = remaining;
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

impl AsyncWrite for MqttParasiteStream {
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
