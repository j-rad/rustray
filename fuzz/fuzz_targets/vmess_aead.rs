#![no_main]
use libfuzzer_sys::fuzz_target;
use rustray::app::stats::StatsManager;
use rustray::config::{Config, VmessDefault, VmessSettings, VmessUser};
use rustray::protocols::vmess;
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
        let config = Config::default();
        if let Ok(router) = Router::new(&config).await {
            let router = Arc::new(router);
            let stats = Arc::new(StatsManager::new());
            let stream = Box::new(MockStream::new(data));

            // Should provide at least one user to reach authentication logic
            let settings = VmessSettings {
                clients: vec![VmessUser {
                    id: "509c3132-7232-4235-9626-267926132174".to_string(),
                    alter_id: Some(0),
                    level: Some(0),
                    email: None,
                }],
                default: Some(VmessDefault {
                    level: 0,
                    alter_id: 0,
                }),
                detour: None,
                disable_insecure_encryption: Some(false),
            };

            let _ = vmess::handle_inbound(router, stats, stream, &settings).await;
        }
    });
});
