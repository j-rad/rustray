// src/transport/mqtt.rs
//!
//! MQTT Transport Implementation
//!
//! Tunneling TCP streams over MQTT publish/subscribe.
//!
//! Structure:
//! - Upstream (Client -> Server): Encapsulate data in MQTT PUBLISH messages to topic `base/session_id/up`.
//! - Downstream (Server -> Client): Server PUBLISHes to `base/session_id/down`, Client subscribes.
//!
//! This requires a persistent MQTT client that multiplexes multiple "streams" (sessions).

use bytes::{Bytes, BytesMut};
use futures::SinkExt;
use rumqttc::{AsyncClient, Event, MqttOptions, Packet, QoS};
use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;
use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};
// use tokio_stream::StreamExt;
use tokio_util::sync::PollSender;
use tracing::warn;
use uuid::Uuid;

// --- MQTT Transport Manager ---

pub struct MqttTransport {
    client: AsyncClient,
    // Map SessionID -> Data Channel
    sessions: Arc<Mutex<HashMap<String, UnboundedSender<Bytes>>>>,
    base_topic: String,
    outgoing_tx: mpsc::Sender<(String, Vec<u8>)>,
}

impl MqttTransport {
    pub async fn new(server_uri: &str, client_id: &str, base_topic: &str) -> anyhow::Result<Self> {
        let mut options = MqttOptions::new(client_id, server_uri, 1883); // Port logic needed
        // Parsing logic for URI should be here
        options.set_keep_alive(Duration::from_secs(5));

        let (client, mut eventloop) = AsyncClient::new(options, 10);
        let sessions: Arc<Mutex<HashMap<String, UnboundedSender<Bytes>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let sessions_clone = sessions.clone();

        // Outgoing Channel (Bounded for Backpressure)
        let (out_tx, mut out_rx) = mpsc::channel::<(String, Vec<u8>)>(1024);
        let client_clone = client.clone();

        // Background Loop
        // Task 1: Event Loop (Incoming)
        tokio::spawn(async move {
            loop {
                match eventloop.poll().await {
                    Ok(Event::Incoming(Packet::Publish(p))) => {
                        let topic = p.topic;
                        let payload = p.payload;
                        let parts: Vec<&str> = topic.split('/').collect();
                        if parts.len() >= 2 {
                            // Extract session_id from topic
                            // Format: base/session_id/down
                            if let Some(&session_id) = parts.get(parts.len().saturating_sub(2)) {
                                let map = sessions_clone.lock().await;
                                if let Some(tx) = map.get(session_id) {
                                    if let Err(_) = tx.send(payload) {
                                        // Channel closed owner receiver dropped
                                    }
                                }
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(e) => {
                        warn!("MQTT connection error: {:?}", e);
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        });

        // Task 2: Outgoing Loop (Publish)
        tokio::spawn(async move {
            while let Some((topic, payload)) = out_rx.recv().await {
                if let Err(e) = client_clone
                    .publish(topic, QoS::AtMostOnce, false, payload)
                    .await
                {
                    warn!("MQTT Publish Error: {}", e);
                }
            }
        });

        Ok(Self {
            client,
            sessions,
            base_topic: base_topic.to_string(),
            outgoing_tx: out_tx,
        })
    }

    pub async fn create_stream(&self) -> anyhow::Result<MqttStream> {
        let session_id = Uuid::new_v4().to_string();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();

        {
            let mut sessions = self.sessions.lock().await;
            sessions.insert(session_id.clone(), tx);
        }

        // Subscribe to downlink
        let topic = format!("{}/{}/down", self.base_topic, session_id);
        self.client.subscribe(&topic, QoS::AtMostOnce).await?;

        Ok(MqttStream {
            session_id,
            base_topic: self.base_topic.clone(),
            rx,
            read_buffer: BytesMut::new(),
            outgoing_tx: PollSender::new(self.outgoing_tx.clone()),
        })
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
                if let Err(_) = self.outgoing_tx.start_send_unpin((topic, payload)) {
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
