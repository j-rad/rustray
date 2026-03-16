//! Yamux-based connection multiplexing for RustRay.
//! Stubbed to bypass compilation errors during VLESS Vision development.

use crate::error::Result;
use crate::transport::BoxedStream;
use dashmap::DashMap;
use std::sync::Arc;
use yamux::{Config, Connection};

#[derive(Clone, Debug)]
pub struct Control;
impl Control {
    pub async fn open_stream(&mut self) -> Result<yamux::Stream> {
        Err(anyhow::anyhow!("Mux stubbed"))
    }
    pub async fn close(&mut self) -> Result<()> {
        Ok(())
    }
}

pub struct MuxStreamWrapper(pub BoxedStream);
// Stub for struct usage in Connection<T>
impl Unpin for MuxStreamWrapper {}
unsafe impl Send for MuxStreamWrapper {}
impl futures::io::AsyncRead for MuxStreamWrapper {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &mut [u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Pending
    }
}
impl futures::io::AsyncWrite for MuxStreamWrapper {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        _buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::task::Poll::Pending
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Pending
    }
    fn poll_close(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::task::Poll::Pending
    }
}

type ConnectionKey = String;

#[derive(Clone)]
pub struct MuxPool {
    sessions: Arc<DashMap<ConnectionKey, Control>>,
}

impl MuxPool {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(DashMap::new()),
        }
    }

    pub async fn get_stream<F, Fut>(&self, _dest: &str, _dialer: F) -> Result<BoxedStream>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<BoxedStream>>,
    {
        Err(anyhow::anyhow!("Mux is currently disabled/stubbed"))
    }
}

pub struct RefMuxListener {
    control: Control,
}

impl RefMuxListener {
    pub fn new(_connection: Connection<MuxStreamWrapper>) -> Self {
        Self { control: Control }
    }

    pub async fn accept(&mut self) -> Result<BoxedStream> {
        std::future::pending().await
    }

    pub fn control(&self) -> Control {
        self.control.clone()
    }
}

pub struct MuxListener {
    // connection: Connection<MuxStreamWrapper>,
}

impl MuxListener {
    pub fn new(_stream: BoxedStream, _config: Config) -> Self {
        Self {}
    }

    pub async fn accept(&mut self) -> Option<Result<BoxedStream>> {
        None
    }
}

pub async fn accept_mux_connection(
    _stream: BoxedStream,
    _router: Arc<crate::router::Router>,
    _policy: Arc<crate::config::LevelPolicy>,
) -> Result<()> {
    Ok(())
}
