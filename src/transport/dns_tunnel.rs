// src/transport/dns_tunnel.rs
//! DNS Transport Tunnel
//!
//! Bidirectional AsyncRead/AsyncWrite stream over DNS queries (TXT records).
//! Encapsulates data in DNS query names (outbound) and TXT record payloads (inbound).

use crate::transport::dns_codec;
use bytes::Bytes;
use std::collections::VecDeque;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::debug;

/// Configuration for the DNS tunnel.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DnsTunnelConfig {
    /// DNS resolver address (e.g. "8.8.8.8:53")
    pub resolver: String,
    /// Base domain for tunneling (e.g. "t.example.com")
    pub domain: String,
    /// Maximum payload bytes per DNS query (before encoding). Default: 110
    #[serde(default = "default_max_payload")]
    pub max_payload_per_query: usize,
    /// Polling interval in milliseconds for checking responses
    #[serde(default = "default_poll_interval_ms")]
    pub poll_interval_ms: u64,
}

fn default_max_payload() -> usize {
    110
}

fn default_poll_interval_ms() -> u64 {
    100
}

/// Shared state between the proxy task and the stream interface.
struct TunnelState {
    /// Received data waiting to be read by the consumer
    recv_buf: VecDeque<u8>,
    /// Send queue: data waiting to be encoded and sent as DNS queries
    send_queue: VecDeque<Bytes>,
    /// Transaction ID counter
    next_tx_id: u16,
}

/// DNS Transport: wraps DNS queries/responses as a bidirectional stream.
pub struct DnsTransport {
    state: Arc<Mutex<TunnelState>>,
    _proxy_task: tokio::task::JoinHandle<()>,
}

impl DnsTransport {
    pub async fn connect(config: &DnsTunnelConfig) -> io::Result<Self> {
        let resolver: SocketAddr = config
            .resolver
            .parse()
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let domain = config.domain.clone();
        let max_payload = config.max_payload_per_query;
        let poll_interval = config.poll_interval_ms;

        let state = Arc::new(Mutex::new(TunnelState {
            recv_buf: VecDeque::with_capacity(4096),
            send_queue: VecDeque::new(),
            next_tx_id: rand::random(),
        }));

        let task_state = state.clone();
        let proxy_task = tokio::spawn(async move {
            Self::proxy_loop(task_state, socket, resolver, domain, max_payload, poll_interval)
                .await;
        });

        Ok(Self {
            state,
            _proxy_task: proxy_task,
        })
    }

    async fn proxy_loop(
        state: Arc<Mutex<TunnelState>>,
        socket: UdpSocket,
        resolver: SocketAddr,
        domain: String,
        max_payload: usize,
        poll_interval: u64,
    ) {
        let mut recv_buf = [0u8; 2048];

        loop {
            // 1. Check if there's data to send
            let outgoing = {
                let mut s = state.lock().await;
                s.send_queue.pop_front().map(|data| {
                    let tx_id = s.next_tx_id;
                    s.next_tx_id = s.next_tx_id.wrapping_add(1);
                    (data, tx_id)
                })
            };

            if let Some((data, tx_id)) = outgoing {
                // Split into DNS-sized chunks and send
                for chunk in data.chunks(max_payload) {
                    match dns_codec::build_dns_query(chunk, &domain, tx_id) {
                        Ok(query_packet) => {
                            if let Err(e) = socket.send_to(&query_packet, resolver).await {
                                debug!("DNS tunnel send error: {}", e);
                            }
                        }
                        Err(e) => {
                            debug!("DNS codec encode error: {}", e);
                        }
                    }
                }
            }

            // 2. Try to receive DNS response
            match tokio::time::timeout(
                std::time::Duration::from_millis(poll_interval),
                socket.recv_from(&mut recv_buf),
            )
            .await
            {
                Ok(Ok((len, src))) => {
                    if src != resolver {
                        continue;
                    }
                    let packet = &recv_buf[..len];
                    // Parse TXT response and extract payload
                    if let Some(payload) = Self::extract_txt_payload(packet) {
                        let mut s = state.lock().await;
                        s.recv_buf.extend(payload.iter());
                    }
                }
                Ok(Err(e)) => {
                    debug!("DNS tunnel recv error: {}", e);
                }
                Err(_) => {
                    // Timeout — send a keepalive/poll query if no data
                }
            }
        }
    }

    /// Extract TXT record payload from a DNS response packet.
    fn extract_txt_payload(packet: &[u8]) -> Option<Vec<u8>> {
        if packet.len() < 12 {
            return None;
        }

        let an_count = u16::from_be_bytes([packet[6], packet[7]]);
        if an_count == 0 {
            return None;
        }

        // Skip header (12 bytes), then skip question section
        let mut offset = 12;

        // Skip QNAME
        while offset < packet.len() {
            let len = packet[offset] as usize;
            if len == 0 {
                offset += 1;
                break;
            }
            if (len & 0xC0) == 0xC0 {
                offset += 2;
                break;
            }
            offset += len + 1;
        }
        offset += 4; // QTYPE + QCLASS

        if offset >= packet.len() {
            return None;
        }

        // Parse answer RR
        // Skip NAME (could be pointer)
        let name_byte = packet.get(offset)?;
        if (name_byte & 0xC0) == 0xC0 {
            offset += 2;
        } else {
            while offset < packet.len() {
                let len = packet[offset] as usize;
                if len == 0 {
                    offset += 1;
                    break;
                }
                offset += len + 1;
            }
        }

        if offset + 10 > packet.len() {
            return None;
        }

        let rr_type = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        offset += 8; // TYPE(2) + CLASS(2) + TTL(4)
        let rd_length = u16::from_be_bytes([packet[offset], packet[offset + 1]]) as usize;
        offset += 2;

        if rr_type != 16 || offset + rd_length > packet.len() {
            return None;
        }

        // Parse TXT RDATA segments
        let mut data = Vec::new();
        let end = offset + rd_length;
        while offset < end {
            let seg_len = packet[offset] as usize;
            offset += 1;
            if offset + seg_len > end {
                break;
            }
            data.extend_from_slice(&packet[offset..offset + seg_len]);
            offset += seg_len;
        }

        Some(data)
    }
}

impl AsyncRead for DnsTransport {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let state = self.state.clone();
        let mut guard = match state.try_lock() {
            Ok(g) => g,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        if guard.recv_buf.is_empty() {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }

        let to_read = buf.remaining().min(guard.recv_buf.len());
        let drained: Vec<u8> = guard.recv_buf.drain(..to_read).collect();
        buf.put_slice(&drained);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for DnsTransport {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let state = self.state.clone();
        let mut guard = match state.try_lock() {
            Ok(g) => g,
            Err(_) => {
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
        };

        guard.send_queue.push_back(Bytes::copy_from_slice(buf));
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
