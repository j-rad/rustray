use crate::app::stats::StatsManager;
use crate::config::HttpProxySettings;
use crate::error::Result;
use crate::router::Router;
use crate::transport::BoxedStream;
use bytes::BytesMut;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::info;

pub async fn listen_stream(
    router: Arc<Router>,
    state: Arc<StatsManager>,
    mut stream: BoxedStream,
    _settings: HttpProxySettings,
    source: String,
) -> Result<()> {
    let mut buf = BytesMut::with_capacity(4096);

    // Read initial request
    // We expect standard HTTP request.
    // Read until \r\n\r\n
    loop {
        if stream.read_buf(&mut buf).await? == 0 {
            return Err(anyhow::anyhow!("HTTP Inbound: Connection closed"));
        }

        // Window scan for double CRLF
        if find_double_crlf(&buf).is_some() {
            // Found header
            break;
        }

        if buf.len() > 16384 {
            return Err(anyhow::anyhow!("HTTP Inbound: Header too large"));
        }
    }

    // Parse Headers
    // We rely on `httparse` if available, or manual.
    // Simple manual parsing for Proxy-Server:
    // Request Line: METHOD SPACE URI SPACE VERSION
    let mut headers = [httparse::Header {
        name: "",
        value: &[],
    }; 32];
    let mut req = httparse::Request::new(&mut headers);

    let status = req.parse(&buf)?;
    if !status.is_complete() {
        // Should be complete due to double crlf check
    }

    let method = req.method.unwrap_or("");
    let path = req.path.unwrap_or("");

    info!("HTTP Inbound Request: {} {}", method, path);

    // Logic:
    // 1. CONNECT -> dest is path.
    // 2. GET/POST -> dest is Host header or parsed from absolute URL.

    let (target_host, target_port) = if method == "CONNECT" {
        // Parse host:port
        if let Some((h, p)) = path.rsplit_once(':') {
            (h.to_string(), p.parse::<u16>().unwrap_or(443))
        } else {
            (path.to_string(), 443)
        }
    } else {
        // Parse absolute URL "http://example.com/foo"
        if path.starts_with("http://") || path.starts_with("https://") {
            if let Ok(url) = url::Url::parse(path) {
                let host = url.host_str().unwrap_or("").to_string();
                let port = url.port_or_known_default().unwrap_or(80);
                (host, port)
            } else {
                return Err(anyhow::anyhow!("Invalid HTTP URL"));
            }
        } else {
            // Relative URL? Must check Host header.
            // httparse headers
            let host_header = req
                .headers
                .iter()
                .find(|h| h.name.eq_ignore_ascii_case("Host"));
            if let Some(h) = host_header {
                let host_str = std::str::from_utf8(h.value)?;
                if let Some((ho, po)) = host_str.rsplit_once(':') {
                    (ho.to_string(), po.parse::<u16>().unwrap_or(80))
                } else {
                    (host_str.to_string(), 80)
                }
            } else {
                return Err(anyhow::anyhow!("HTTP Inbound: No Host Header"));
            }
        }
    };

    // Determine Policy
    // HTTP Inbound doesn't have "User" unless valid auth.
    // Assuming unauthenticated level 0.
    let policy = state.policy_manager.get_policy(0);

    if method == "CONNECT" {
        // Respond 200 OK
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        // Now route as stream
        // CONSUME the buffer? No, CONNECT payload starts after the header.
        // If we consumed more than header?
        let header_len = req.parse(&buf)?.unwrap(); // Get offset
        let body_start = header_len;

        if body_start < buf.len() {
            // We have body? CONNECT usually doesn't have body.
            // But if client sent data early?
            // Route stream and prepend extra data?
            // Need "Splice" or construct new stream with prepend.
            // BoxedStream doesn't support prepend easily unless we wrap it.
            // We can use `tokio::io::chain`?
            // `Box::new(Cursor::new(remaining).chain(stream))`
            let remaining = buf.split_off(body_start);
            // Verify if chain works with BoxedStream (needs AsyncRead/Write).
            // Chain only implements AsyncRead.
            // We need Read+Write.
            // So we need a struct `PrefixStream`
            // For now assume CONNECT has no body in first packet usually.
            if !remaining.is_empty() {
                // Wrap the stream to include the early body
                stream = Box::new(crate::transport::splice::PrefixStream::new(
                    stream,
                    remaining.freeze(),
                ));
            }
        }

        router
            .route_stream(stream, target_host, target_port, source.clone(), policy)
            .await
    } else {
        // Standard HTTP Proxy
        // We need to send the request to the target.
        // We have consumed the header. We need to forward it?
        // Xray router receives a Stream.
        // If we call `router.route_stream`, we give it the stream.
        // But the first packet (Header) is already consumed by us!
        // We must PREPEND header back?
        // OR:
        // We change the request to be relative?
        // "GET http://google.com/" -> "GET /" sent to google.com?
        // Yes, proxies stripe the absolute URI.
        // But `router.route_stream` connects to target.
        // We write the headers.

        // Complex: Editing HTTP requires robust parsing.
        // For simple production readiness:
        // Just forward the buffer we read + the rest of stream.
        // But target server expects "GET /", not "GET http://..."?
        // Most servers handle absolute, but standard practice is to convert.
        // Also we might need to remove Proxy-Connection headers.

        // For simplicity: Just Forward.
        // But we need to use a PrefixStream.

        // Let's implement PrefixStream here.
        let stream = crate::transport::splice::PrefixStream::new(stream, buf.freeze());
        router
            .route_stream(Box::new(stream), target_host, target_port, source, policy)
            .await
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}
