use crate::transport::BoxedStream;
use std::io;
use std::os::unix::io::AsRawFd;
use tokio::io::Interest;
use tokio::net::TcpStream;
use tracing::debug;

#[cfg(target_os = "linux")]
pub async fn splice_bidirectional(
    inbound: &mut BoxedStream,
    outbound: &mut BoxedStream,
) -> Option<io::Result<(u64, u64)>> {
    // Attempt downcast to TcpStream
    // Note: BoxedStream is Box<dyn AsyncStream>.
    // AsyncStream implements as_any() returning &dny Any.
    // If the underlying stream is TcpStream, we can splice.

    // We need to verify both are TcpStreams.
    // Since we only have mutable references to the BoxedStreams,
    // we can get references to the inner TcpStreams.

    // Safety: We must ensure we don't violate guarantees.
    // Splice works on FDs.

    if let (Some(in_tcp), Some(out_tcp)) = (
        inbound.as_any().downcast_ref::<TcpStream>(),
        outbound.as_any().downcast_ref::<TcpStream>(),
    ) {
        debug!("Splice: Enabled for bidirectional TCP stream");
        let result = splice_tcp(in_tcp, out_tcp).await;
        return Some(result);
    }

    None
}

#[cfg(target_os = "linux")]
async fn splice_tcp(src: &TcpStream, dst: &TcpStream) -> io::Result<(u64, u64)> {
    let (src_fd, dst_fd) = (src.as_raw_fd(), dst.as_raw_fd());

    let pipe_in = create_pipe()?;
    let pipe_out = create_pipe()?;

    let t1 = splice_loop(src, src_fd, dst, dst_fd, pipe_in);
    let t2 = splice_loop(dst, dst_fd, src, src_fd, pipe_out);

    tokio::try_join!(t1, t2)
}

#[cfg(target_os = "linux")]
fn create_pipe() -> io::Result<(i32, i32)> {
    let mut fds = [0i32; 2];
    unsafe {
        if libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok((fds[0], fds[1]))
}

#[cfg(target_os = "linux")]
async fn splice_loop(
    r_stream: &TcpStream,
    r_fd: i32,
    w_stream: &TcpStream,
    w_fd: i32,
    pipe: (i32, i32),
) -> io::Result<u64> {
    let (pipe_r, pipe_w) = pipe;
    let mut total_bytes = 0;

    // Use a guard to close the pipe FDs when the loop finishes
    struct PipeGuard(i32, i32);
    impl Drop for PipeGuard {
        fn drop(&mut self) {
            unsafe {
                libc::close(self.0);
                libc::close(self.1);
            }
        }
    }
    let _guard = PipeGuard(pipe_r, pipe_w);

    loop {
        // Step 1: Read from Socket into Pipe
        let spliced_to_pipe;
        loop {
            // Check for read readiness if we blocked previously, OR just try first?
            // "EAGAIN" means "not ready".
            // It is efficient to try once, then wait.

            let res = unsafe {
                libc::splice(
                    r_fd,
                    std::ptr::null_mut(),
                    pipe_w,
                    std::ptr::null_mut(),
                    65536,
                    libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
                )
            };

            match res {
                r if r >= 0 => {
                    let n = r as usize;
                    if n == 0 {
                        // EOF from reader.
                        // Shutdown writer and return.
                        unsafe {
                            libc::shutdown(w_fd, libc::SHUT_WR);
                        }
                        return Ok(total_bytes);
                    }
                    spliced_to_pipe = n;
                    break;
                }
                -1 => {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::WouldBlock {
                        r_stream.ready(Interest::READABLE).await?;
                        continue;
                    }
                    return Err(err);
                }
                _ => return Err(io::Error::last_os_error()),
            }
        }

        // Step 2: Write from Pipe to Socket
        let mut written_from_pipe = 0;
        while written_from_pipe < spliced_to_pipe {
            let res = unsafe {
                libc::splice(
                    pipe_r,
                    std::ptr::null_mut(),
                    w_fd,
                    std::ptr::null_mut(),
                    (spliced_to_pipe - written_from_pipe) as usize,
                    libc::SPLICE_F_MOVE | libc::SPLICE_F_NONBLOCK,
                )
            };

            match res {
                r if r >= 0 => {
                    let n = r as usize;
                    if n == 0 {
                        return Err(io::Error::new(io::ErrorKind::WriteZero, "write zero"));
                    }
                    written_from_pipe += n;
                    total_bytes += n as u64;
                }
                -1 => {
                    let err = io::Error::last_os_error();
                    if err.kind() == io::ErrorKind::WouldBlock {
                        w_stream.ready(Interest::WRITABLE).await?;
                        continue;
                    }
                    return Err(err);
                }
                _ => return Err(io::Error::last_os_error()),
            }
        }
    }
}

/// A stream that reads a prefix buffer before delegating to the inner stream.
pub struct PrefixStream<S> {
    inner: S,
    prefix: bytes::Bytes,
}

impl<S> PrefixStream<S> {
    pub fn new(inner: S, prefix: bytes::Bytes) -> Self {
        Self { inner, prefix }
    }
}

use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

impl<S: AsyncRead + Unpin> AsyncRead for PrefixStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.prefix.is_empty() {
            let len = std::cmp::min(buf.remaining(), self.prefix.len());
            buf.put_slice(&self.prefix[..len]);
            // Advance prefix (requires splitting or keeping index)
            // Bytes::split_to is cheap
            let _ = self.prefix.split_to(len);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
