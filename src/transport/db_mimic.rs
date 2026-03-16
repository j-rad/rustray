// src/transport/db_mimic.rs
//! Database Mimicry Transport
//!
//! Wraps arbitrary data streams in database wire protocols (PostgreSQL, Redis)
//! to evade DPI filters that block unknown protocols or look for specific signatures.

use crate::config::DbMimicConfig;
use crate::error::Result;
use crate::transport::AsyncStream;
use bytes::{Buf, BufMut, BytesMut};
use md5::{Digest, Md5};
use rand_distr::{Distribution, Normal};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

// --- PostgreSQL Constants ---
const PG_STARTUP_MSG_CODE: i32 = 196608; // Protocol 3.0
const PG_TYPE_DATA_ROW: u8 = b'D';
const PG_TYPE_AUTH_REQUEST: u8 = b'R';
const PG_TYPE_READY_FOR_QUERY: u8 = b'Z';
const PG_TYPE_PASSWORD_MESSAGE: u8 = b'p';

// --- Redis Constants ---
const REDIS_BULK_STRING: u8 = b'$';

pub struct DbMimicStream {
    inner: TcpStream,
    protocol: DbProtocol,
    rx_buf: BytesMut,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum DbProtocol {
    Postgres,
    Redis,
}

impl DbMimicStream {
    pub async fn connect(host: &str, port: u16, config: &DbMimicConfig) -> Result<Self> {
        let stream = TcpStream::connect((host, port)).await?;
        let protocol = match config.protocol.to_lowercase().as_str() {
            "redis" => DbProtocol::Redis,
            "postgresql" | "postgres" | "pg" => DbProtocol::Postgres,
            _ => {
                return Err(anyhow::anyhow!(
                    "Unsupported DB protocol: {}",
                    config.protocol
                ));
            }
        };

        let mut mimic = Self {
            inner: stream,
            protocol,
            rx_buf: BytesMut::with_capacity(8192),
        };

        // Perform Initial Handshake
        mimic.handshake(config).await?;

        Ok(mimic)
    }

    async fn handshake(&mut self, config: &DbMimicConfig) -> Result<()> {
        match self.protocol {
            DbProtocol::Postgres => self.handshake_postgres(config).await,
            DbProtocol::Redis => self.handshake_redis(config).await,
        }
    }

    async fn handshake_postgres(&mut self, config: &DbMimicConfig) -> Result<()> {
        // 1. Send StartupMessage
        let user = config.user.as_deref().unwrap_or("postgres");
        let database = config.database.as_deref().unwrap_or("postgres");

        let mut buf = BytesMut::new();
        buf.put_i32(0); // Placeholder length
        buf.put_i32(PG_STARTUP_MSG_CODE);

        buf.put_slice(b"user\0");
        buf.put_slice(user.as_bytes());
        buf.put_u8(0);
        buf.put_slice(b"database\0");
        buf.put_slice(database.as_bytes());
        buf.put_u8(0);
        buf.put_u8(0); // Terminator

        let len = buf.len() as i32;
        buf[0..4].copy_from_slice(&len.to_be_bytes());

        self.inner.write_all(&buf).await?;

        // 2. Loop until ReadyForQuery
        loop {
            let mut type_buf = [0u8; 1];
            self.inner.read_exact(&mut type_buf).await?;
            let msg_type = type_buf[0];

            let mut len_buf = [0u8; 4];
            self.inner.read_exact(&mut len_buf).await?;
            let msg_len = i32::from_be_bytes(len_buf) as usize;

            if msg_len < 4 {
                return Err(anyhow::anyhow!("Invalid PG message length: {}", msg_len));
            }

            let mut body = vec![0u8; msg_len - 4];
            if !body.is_empty() {
                self.inner.read_exact(&mut body).await?;
            }

            match msg_type {
                PG_TYPE_AUTH_REQUEST => {
                    let auth_type = i32::from_be_bytes([body[0], body[1], body[2], body[3]]);
                    match auth_type {
                        0 => {
                            // AuthOK
                            continue;
                        }
                        5 => {
                            // MD5 Password
                            let salt = &body[4..8];
                            let password = config.password_hash.as_deref().ok_or_else(|| {
                                anyhow::anyhow!(
                                    "Postgres MD5 auth requested but no password provided"
                                )
                            })?;

                            // concat("md5", md5(concat(md5(concat(password, username)), salt)))
                            let mut hasher = Md5::new();
                            hasher.update(password.as_bytes());
                            hasher.update(user.as_bytes());
                            let h1 = format!("{:x}", hasher.finalize_reset());

                            hasher.update(h1.as_bytes());
                            hasher.update(salt);
                            let h2 = format!("md5{:x}", hasher.finalize());

                            let mut pass_msg = BytesMut::with_capacity(h2.len() + 6);
                            pass_msg.put_u8(PG_TYPE_PASSWORD_MESSAGE);
                            pass_msg.put_i32((h2.len() + 5) as i32);
                            pass_msg.put_slice(h2.as_bytes());
                            pass_msg.put_u8(0);

                            self.inner.write_all(&pass_msg).await?;
                        }
                        _ => {
                            return Err(anyhow::anyhow!("Unsupported PG auth type: {}", auth_type));
                        }
                    }
                }
                PG_TYPE_READY_FOR_QUERY => {
                    break;
                }
                _ => {
                    // Ignore other messages during handshake (ParameterStatus, etc.)
                    continue;
                }
            }
        }

        Ok(())
    }

    async fn handshake_redis(&mut self, config: &DbMimicConfig) -> Result<()> {
        if let Some(user) = &config.user {
            let cmd = format!(
                "AUTH {} {}\r\n",
                user,
                config.password_hash.as_deref().unwrap_or("")
            );
            self.inner.write_all(cmd.as_bytes()).await?;
            let mut junk = [0u8; 128];
            let _ = self.inner.read(&mut junk).await?;
        }
        Ok(())
    }
}

// --- AsyncRead / AsyncWrite Implementation ---

impl AsyncRead for DbMimicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.rx_buf.is_empty() {
                let len = std::cmp::min(buf.remaining(), self.rx_buf.len());
                buf.put_slice(&self.rx_buf[..len]);
                self.rx_buf.advance(len);
                return Poll::Ready(Ok(()));
            }

            let mut temp_buf = [0u8; 8192];
            let mut read_buf = tokio::io::ReadBuf::new(&mut temp_buf);

            match Pin::new(&mut self.inner).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n > 0 {
                        let mut raw = &temp_buf[..n];
                        match self.protocol {
                            DbProtocol::Postgres => {
                                while raw.remaining() >= 5 {
                                    let msg_type = raw[0];
                                    // Postgres length includes self (4 bytes)
                                    let msg_len =
                                        i32::from_be_bytes([raw[1], raw[2], raw[3], raw[4]])
                                            as usize;

                                    if raw.len() < 1 + msg_len {
                                        break; // Incomplete frame
                                    }

                                    if msg_type == PG_TYPE_DATA_ROW {
                                        // 'D' + Len(4) + ColCount(2) + [ColLen(4)+Bytes]
                                        // Header is 1 + 4 = 5 bytes. Body is msg_len - 4.
                                        // Body starts at raw[5].
                                        let mut body = &raw[5..1 + msg_len]; // Limit to this frame
                                        if body.remaining() >= 2 {
                                            let _col_count = body.get_i16();
                                            if body.remaining() >= 4 {
                                                let col_len = body.get_i32();
                                                if col_len >= 0 {
                                                    let ulen = col_len as usize;
                                                    if body.remaining() >= ulen {
                                                        self.rx_buf.put_slice(&body[..ulen]);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    raw.advance(1 + msg_len);
                                }
                            }
                            DbProtocol::Redis => {
                                // Stream-based parsing for RESP
                                // We are looking for BulkStrings: $<len>\r\n<data>\r\n
                                while raw.has_remaining() {
                                    // Check for Bulk String marker
                                    if raw[0] == REDIS_BULK_STRING {
                                        // Find first \r\n
                                        if let Some(idx) =
                                            raw.chunk().windows(2).position(|w| w == b"\r\n")
                                        {
                                            // Parse length
                                            if let Ok(len_str) =
                                                std::str::from_utf8(&raw.chunk()[1..idx])
                                            {
                                                if let Ok(len) = len_str.parse::<i32>() {
                                                    let data_start = idx + 2;
                                                    if len >= 0 {
                                                        let ulen = len as usize;
                                                        // Check if we have the full payload + trailing \r\n
                                                        if raw.remaining() >= data_start + ulen + 2
                                                        {
                                                            self.rx_buf.put_slice(
                                                                &raw.chunk()
                                                                    [data_start..data_start + ulen],
                                                            );
                                                            raw.advance(data_start + ulen + 2);
                                                            continue;
                                                        }
                                                    } else if len == -1 {
                                                        // Null Bulk String, just skip
                                                        raw.advance(data_start);
                                                        continue;
                                                    }
                                                }
                                            }
                                        }
                                        // Incomplete or invalid
                                        break;
                                    } else {
                                        // Skip unknown/protocol bytes (e.g. +OK, -Err)
                                        // Simply advance one byte to try to find sync
                                        // Real implementation might want to be smarter
                                        raw.advance(1);
                                    }
                                }
                            }
                        }
                    } else {
                        return Poll::Ready(Ok(())); // EOF
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for DbMimicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let encoded = match self.protocol {
            DbProtocol::Postgres => {
                // Wrap in DataRow 'D'
                // Format: 'D' + Length(i32) + ColCount(i16) + ColLen(i32) + Data
                let mut frame = BytesMut::with_capacity(buf.len() + 11);
                frame.put_u8(PG_TYPE_DATA_ROW);
                frame.put_i32((buf.len() + 10) as i32); // Length
                frame.put_i16(1); // One column
                frame.put_i32(buf.len() as i32); // Column length
                frame.put_slice(buf);
                frame
            }
            DbProtocol::Redis => {
                let header = format!("${}\r\n", buf.len());
                let mut frame = BytesMut::with_capacity(header.len() + buf.len() + 2);
                frame.put_slice(header.as_bytes());
                frame.put_slice(buf);
                frame.put_slice(b"\r\n");
                frame
            }
        };

        match Pin::new(&mut self.inner).poll_write(cx, &encoded) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// --- Fake Server Decoy ---

pub struct DbMimicServer;

impl DbMimicServer {
    /// Serve a decoy rejection to an active probe.
    /// This acts as a honeypot, proxying the connection to a domestic whitelisted site
    /// (e.g., bank.ir) over standard TCP with Gaussian jitter applied to the TTFB.
    pub async fn serve_decoy(stream: &mut tokio::net::TcpStream, _protocol: &str) -> Result<()> {
        let mut target_stream = match tokio::net::TcpStream::connect("bank.ir:443").await {
            Ok(s) => s,
            Err(_) => {
                let _ = stream.shutdown().await;
                return Ok(()); // Silently close on connect failure
            }
        };

        // Gaussian jitter for TTFB (Mean = 15.0ms, StdDev = 5.0ms)
        let normal = Normal::new(15.0, 5.0).unwrap();
        let delay_ms: f64 = normal.sample(&mut rand::thread_rng());
        let delay_ms = delay_ms.max(0.0);
        tokio::time::sleep(std::time::Duration::from_millis(delay_ms as u64)).await;

        let _ = tokio::io::copy_bidirectional(stream, &mut target_stream).await;
        Ok(())
    }
}
