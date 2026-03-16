#![no_main]
use libfuzzer_sys::fuzz_target;
use rustray::app::stats::StatsManager;
use rustray::config::{Config, VlessSettings};
use rustray::protocols::vless;
use rustray::router::Router;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::runtime::Runtime;

struct MockStream {
    data: std::io::Cursor<Vec<u8>>,
}

impl MockStream {
    fn new(data: &[u8]) -> Self {
        Self {
            data: std::io::Cursor::new(data.to_vec()),
        }
    }
}

impl AsyncRead for MockStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        use std::io::Read;
        let p = buf.initialize_unfilled();
        let n = self.data.read(p)?;
        buf.advance(n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for MockStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fuzz_target!(|data: &[u8]| {
    let rt = Runtime::new().unwrap();
    rt.block_on(async {
        // Minimal config
        let config = Config::default();
        // Router might fail if DNS or internal components fail?
        // Assuming Router::new handles default config gracefully.
        if let Ok(router) = Router::new(&config).await {
            let router = Arc::new(router);
            let stats = Arc::new(StatsManager::new());
            let stream = Box::new(MockStream::new(data));

            let settings = VlessSettings {
                clients: vec![],
                decryption: Some("none".to_string()),
                fallbacks: None,
            };

            // We just want to ensure it doesn't panic
            let _ = vless::handle_inbound(router, stats, stream, &settings).await;
        }
    });
});
