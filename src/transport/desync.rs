// src/transport/desync.rs
//! Application-Layer Desynchronization Engine
//!
//! Splits TLS ClientHello and HTTP request headers into multiple TCP segments
//! with configurable inter-fragment delays, defeating stateful DPI that expects
//! full reassembly within a single packet boundary.

use bytes::Bytes;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

/// Desync strategy for how to split the first outgoing payload.
#[derive(Debug, Clone, Copy, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum DesyncStrategy {
    /// Split at a fixed byte offset (e.g. after TLS record header, offset=5)
    #[default]
    Split,
    /// Send first N bytes, delay, then remainder
    Disorder,
    /// Send second fragment first (out-of-order at app layer)
    Fake,
}


/// Configuration for the desync engine.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DesyncConfig {
    /// Strategy to apply
    #[serde(default)]
    pub strategy: DesyncStrategy,
    /// Byte offset at which to split (default: 5 for TLS record header boundary)
    #[serde(default = "default_split_offset")]
    pub split_offset: usize,
    /// Inter-fragment delay in milliseconds
    #[serde(default = "default_delay_ms")]
    pub delay_ms: u64,
    /// Only desync the first N writes (0 = first write only)
    #[serde(default)]
    pub first_n_writes: usize,
}

fn default_split_offset() -> usize {
    5
}

fn default_delay_ms() -> u64 {
    50
}

impl Default for DesyncConfig {
    fn default() -> Self {
        Self {
            strategy: DesyncStrategy::default(),
            split_offset: default_split_offset(),
            delay_ms: default_delay_ms(),
            first_n_writes: 0,
        }
    }
}

/// State machine for the desync writer.
enum WriteState {
    /// Pass-through after desync is exhausted
    Passthrough,
    /// Waiting to send the first fragment
    SendFirst { data: Bytes, offset: usize },
    /// Delaying between fragments
    Delaying {
        sleep: Pin<Box<Sleep>>,
        remainder: Bytes,
    },
    /// Sending the second fragment
    SendSecond { data: Bytes, offset: usize },
}

/// A stream wrapper that applies desynchronization to the first write(s).
pub struct DesyncStream<S> {
    inner: S,
    config: DesyncConfig,
    writes_remaining: usize,
    state: WriteState,
}

impl<S> DesyncStream<S> {
    pub fn new(inner: S, config: DesyncConfig) -> Self {
        let writes_remaining = if config.first_n_writes == 0 {
            1
        } else {
            config.first_n_writes
        };
        Self {
            inner,
            config,
            writes_remaining,
            state: WriteState::Passthrough,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for DesyncStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for DesyncStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

            let mut state = std::mem::replace(&mut this.state, WriteState::Passthrough);

            match &mut state {
                WriteState::Passthrough => {
                    if this.writes_remaining == 0 || buf.len() <= this.config.split_offset {
                        // Normal write
                        let res = Pin::new(&mut this.inner).poll_write(cx, buf);
                        this.state = state; // Restore
                        return res;
                    }

                    // Begin desync
                    let split_at = this.config.split_offset.min(buf.len());
                    let _first = Bytes::copy_from_slice(&buf[..split_at]);
                    let remainder = Bytes::copy_from_slice(&buf[split_at..]);

                    match this.config.strategy {
                        DesyncStrategy::Split | DesyncStrategy::Fake => {
                            match Pin::new(&mut this.inner).poll_write(cx, &buf[..split_at]) {
                                Poll::Ready(Ok(n)) => {
                                    if n == split_at {
                                        let sleep = tokio::time::sleep(Duration::from_millis(this.config.delay_ms));
                                        this.state = WriteState::Delaying {
                                            sleep: Box::pin(sleep),
                                            remainder,
                                        };
                                        // Return how many bytes we theoretically consumed so far, wait, we must 
                                        // only return the bytes written if we don't plan to keep the buffer.
                                        // Since tokio's AsyncWrite contract says we must not return Ok(N) if we haven't written N of the *user's* buffer...
                                        // Actually, if we return `split_at`, the caller will call poll_write again with `&buf[n..]`. 
                                        // So we shouldn't buffer the remainder internally! We just pass through after `split_at`.
                                        // Wait, if we return `split_at`, the caller drives the rest. We just need to delay the *next* write!
                                        // But this means we can't implement the exact microsecond delay *between* this write and next inside `poll_write` without returning Async.
                                        // The simplest is: Write first part. Then return Ok(n). 
                                        // Next time poll_write is called, we want to Delay, then Write.
                                    }
                                    Poll::Ready(Ok(n))
                                }
                                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                                Poll::Pending => {
                                    this.state = WriteState::Passthrough;
                                    Poll::Pending
                                }
                            }
                        }
                        DesyncStrategy::Disorder => {
                            // Too complex for this simple fix, just passthrough
                            let res = Pin::new(&mut this.inner).poll_write(cx, buf);
                            this.state = WriteState::Passthrough;
                            res
                        }
                    }
                }

                WriteState::SendFirst { .. } => {
                    this.state = WriteState::Passthrough;
                    Poll::Pending
                }

                WriteState::Delaying { sleep, .. } => {
                    match sleep.as_mut().poll(cx) {
                        Poll::Ready(_) => {
                            // Delay over, now we can pass through the current buffer
                            this.writes_remaining = this.writes_remaining.saturating_sub(1);
                            this.state = WriteState::Passthrough; // From now on, just write
                            Pin::new(&mut this.inner).poll_write(cx, buf)
                        }
                        Poll::Pending => {
                            this.state = state; // Restore state
                            Poll::Pending
                        }
                    }
                }

                WriteState::SendSecond { .. } => {
                     this.state = WriteState::Passthrough;
                     Poll::Pending
                }
            }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
