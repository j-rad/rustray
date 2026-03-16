// src/protocols/shadowsocks_stream.rs
// Production-grade Shadowsocks-2022 AEAD streaming wrapper

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes128Gcm, Nonce};
use bytes::{Buf, BytesMut};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

const MAX_CHUNK_SIZE: usize = 0x3FFF; // 16383 bytes
const TAG_LEN: usize = 16;

/// Shadowsocks-2022 AEAD encrypted stream wrapper
/// Handles chunked framing: [Encrypted Length (2 bytes + Tag)] [Encrypted Payload (Len bytes + Tag)]
pub struct ShadowsocksStream<S> {
    inner: S,
    cipher: Aes128Gcm,
    read_nonce: [u8; 12],
    write_nonce: [u8; 12],
    #[allow(dead_code)]
    read_buffer: BytesMut,
    write_buffer: BytesMut,
    pending_plaintext: BytesMut,
}

impl<S> ShadowsocksStream<S> {
    pub fn new(stream: S, session_key: &[u8; 16]) -> io::Result<Self> {
        let cipher = Aes128Gcm::new_from_slice(session_key)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid key size"))?;

        Ok(Self {
            inner: stream,
            cipher,
            read_nonce: [0u8; 12],
            write_nonce: [0u8; 12],
            read_buffer: BytesMut::with_capacity(MAX_CHUNK_SIZE + TAG_LEN + 2 + TAG_LEN),
            write_buffer: BytesMut::with_capacity(MAX_CHUNK_SIZE + TAG_LEN + 2 + TAG_LEN),
            pending_plaintext: BytesMut::new(),
        })
    }

    /// Create a new stream with a specific starting nonce
    /// Used when continuing encryption after header parsing
    pub fn new_with_nonce(stream: S, session_key: &[u8; 16], nonce: [u8; 12]) -> io::Result<Self> {
        let cipher = Aes128Gcm::new_from_slice(session_key)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "Invalid key size"))?;

        Ok(Self {
            inner: stream,
            cipher,
            read_nonce: nonce,
            write_nonce: nonce,
            read_buffer: BytesMut::with_capacity(MAX_CHUNK_SIZE + TAG_LEN + 2 + TAG_LEN),
            write_buffer: BytesMut::with_capacity(MAX_CHUNK_SIZE + TAG_LEN + 2 + TAG_LEN),
            pending_plaintext: BytesMut::new(),
        })
    }

    fn increment_nonce(nonce: &mut [u8; 12]) {
        for i in 0..12 {
            if nonce[i] < 255 {
                nonce[i] += 1;
                return;
            }
            nonce[i] = 0;
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ShadowsocksStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // If we have pending plaintext, return it first
        if !self.pending_plaintext.is_empty() {
            let to_copy = buf.remaining().min(self.pending_plaintext.len());
            buf.put_slice(&self.pending_plaintext[..to_copy]);
            self.pending_plaintext.advance(to_copy);
            return Poll::Ready(Ok(()));
        }

        // Read encrypted length (2 bytes + 16 byte tag)
        let this = &mut *self;
        let mut len_buf = [0u8; 2 + TAG_LEN];

        // Try to read length chunk
        let mut read_buf = ReadBuf::new(&mut len_buf);
        match Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => {
                if read_buf.filled().len() < len_buf.len() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Incomplete length chunk",
                    )));
                }
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        // Decrypt length
        let nonce = Nonce::from_slice(&this.read_nonce);
        let len_plain = this
            .cipher
            .decrypt(nonce, len_buf.as_ref())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Length decrypt failed"))?;

        Self::increment_nonce(&mut this.read_nonce);

        let payload_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
        if payload_len > MAX_CHUNK_SIZE {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Chunk too large",
            )));
        }

        // Read encrypted payload
        let mut payload_buf = vec![0u8; payload_len + TAG_LEN];
        let mut payload_read_buf = ReadBuf::new(&mut payload_buf);
        match Pin::new(&mut this.inner).poll_read(cx, &mut payload_read_buf) {
            Poll::Ready(Ok(())) => {
                if payload_read_buf.filled().len() < payload_buf.len() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "Incomplete payload chunk",
                    )));
                }
            }
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            Poll::Pending => return Poll::Pending,
        }

        // Decrypt payload
        let nonce = Nonce::from_slice(&this.read_nonce);
        let plaintext = this
            .cipher
            .decrypt(nonce, payload_buf.as_ref())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Payload decrypt failed"))?;

        Self::increment_nonce(&mut this.read_nonce);

        // Store plaintext and return what fits
        this.pending_plaintext.extend_from_slice(&plaintext);
        let to_copy = buf.remaining().min(this.pending_plaintext.len());
        buf.put_slice(&this.pending_plaintext[..to_copy]);
        this.pending_plaintext.advance(to_copy);

        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ShadowsocksStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;

        // Chunk the data if necessary
        let chunk_size = buf.len().min(MAX_CHUNK_SIZE);
        let chunk = &buf[..chunk_size];

        // Encrypt length
        let len_bytes = (chunk.len() as u16).to_be_bytes();
        let nonce = Nonce::from_slice(&this.write_nonce);
        let len_enc = this
            .cipher
            .encrypt(nonce, len_bytes.as_ref())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Length encrypt failed"))?;

        Self::increment_nonce(&mut this.write_nonce);

        // Encrypt payload
        let nonce = Nonce::from_slice(&this.write_nonce);
        let payload_enc = this
            .cipher
            .encrypt(nonce, chunk)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Payload encrypt failed"))?;

        Self::increment_nonce(&mut this.write_nonce);

        // Write to inner stream
        this.write_buffer.clear();
        this.write_buffer.extend_from_slice(&len_enc);
        this.write_buffer.extend_from_slice(&payload_enc);

        let mut written = 0;
        while written < this.write_buffer.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buffer[written..]) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "Write zero bytes",
                        )));
                    }
                    written += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Poll::Ready(Ok(chunk_size))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
