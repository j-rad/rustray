// src/transport/stats.rs
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct StatsStream<T> {
    inner: T,
    read_counter: Arc<AtomicU64>,
    write_counter: Arc<AtomicU64>,
}

impl<T> StatsStream<T> {
    pub fn new(inner: T, read_counter: Arc<AtomicU64>, write_counter: Arc<AtomicU64>) -> Self {
        Self {
            inner,
            read_counter,
            write_counter,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for StatsStream<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let after = buf.filled().len();
                let params = after - before;
                self.read_counter
                    .fetch_add(params as u64, Ordering::Relaxed);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for StatsStream<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                self.write_counter.fetch_add(n as u64, Ordering::Relaxed);
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
