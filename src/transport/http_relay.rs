// src/transport/http_relay.rs
//! HTTP Relay with Traffic Mimicry
//!
//! Wraps a TrinityTransport and applies Markov-chain based jitter and
//! chunking to make the traffic pattern look like industrial protocols.

use crate::error::Result;
use crate::protocols::flow_trait::{BoxedTrinityTransport, TrinityTransport};
use crate::transport::behavior_synth::{BehaviorSynthesizer, MimicProfile};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct HttpRelayStream {
    inner: BoxedTrinityTransport,
    synth: BehaviorSynthesizer,
    write_state: WriteState,
}

enum WriteState {
    Idle,
    Delaying(Pin<Box<tokio::time::Sleep>>),
}

impl HttpRelayStream {
    pub fn new(inner: BoxedTrinityTransport, profile: MimicProfile) -> Self {
        Self {
            inner,
            synth: BehaviorSynthesizer::new(profile),
            write_state: WriteState::Idle,
        }
    }
}

impl AsyncRead for HttpRelayStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for HttpRelayStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        loop {
            match &mut self.write_state {
                WriteState::Idle => {
                    let (size_hint, delay) = self.synth.next_step();
                    
                    if delay > Duration::from_micros(10) {
                        self.write_state = WriteState::Delaying(Box::pin(tokio::time::sleep(delay)));
                        continue;
                    }

                    // Apply size hint: chunk the write if it's too large for the current state
                    let actual_size = if size_hint > 0 {
                        buf.len().min(size_hint)
                    } else {
                        buf.len()
                    };

                    return Pin::new(&mut self.inner).poll_write(cx, &buf[..actual_size]);
                }
                WriteState::Delaying(sleep) => {
                    match sleep.as_mut().poll(cx) {
                        Poll::Ready(()) => {
                            self.write_state = WriteState::Idle;
                            continue;
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
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

impl TrinityTransport for HttpRelayStream {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }

    fn switch_carrier(&mut self, new_carrier: BoxedTrinityTransport) -> io::Result<()> {
        self.inner.switch_carrier(new_carrier)
    }

    fn apply_fragmentation(&mut self) -> io::Result<()> {
        self.inner.apply_fragmentation()
    }

    fn handover(self, new_tal: BoxedTrinityTransport) -> Result<Self> {
        Ok(Self {
            inner: new_tal,
            synth: self.synth,
            write_state: WriteState::Idle,
        })
    }
}
