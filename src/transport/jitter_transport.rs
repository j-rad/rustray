use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use crate::transport::flow_trait::{BoxedTrinityTransport, TrinityTransport, TransportStats};
use crate::app::behavior_synth::{MarkovChain, FlowState};

pub struct JitterTransport {
    inner: BoxedTrinityTransport,
    markov_chain: MarkovChain,
    sleep: Option<Pin<Box<dyn Future<Output = ()> + Send + Sync>>>,
}

impl JitterTransport {
    pub fn new(inner: BoxedTrinityTransport) -> Self {
        Self {
            inner,
            markov_chain: MarkovChain::new(),
            sleep: None,
        }
    }
}

impl AsyncRead for JitterTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for JitterTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(mut fut) = self.sleep.take() {
            match fut.as_mut().poll(cx) {
                Poll::Pending => {
                    self.sleep = Some(fut);
                    return Poll::Pending;
                }
                Poll::Ready(()) => {
                    // Delay complete
                }
            }
        }

        let state = self.markov_chain.update_state();
        let delay = self.markov_chain.get_delay(state);
        
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                // Apply jitter for next write
                self.sleep = Some(Box::pin(tokio::time::sleep(delay)));
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

impl TrinityTransport for JitterTransport {
    fn as_any(&self) -> &dyn std::any::Any { self }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }

    fn switch_carrier(&mut self, new_carrier: BoxedTrinityTransport) -> io::Result<()> {
        self.inner.switch_carrier(new_carrier)
    }

    fn apply_fragmentation(&mut self) -> io::Result<()> {
        self.inner.apply_fragmentation()
    }

    fn get_transport_info(&self) -> TransportStats {
        self.inner.get_transport_info()
    }

    fn handover(self, new_carrier: BoxedTrinityTransport) -> crate::error::Result<Self> {
        Ok(Self {
            inner: new_carrier,
            markov_chain: self.markov_chain,
            sleep: self.sleep,
        })
    }
}
