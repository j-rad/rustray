// src/inbounds/nginx_decoy.rs
//! Phase 7 — Honey-Site Decoys: Nginx Decoy Server.
//!
//! Every VPS runs a background process serving a functional, clickable clone of
//! a whitelisted Iranian site (e.g., irna.ir) on port 443.  The proxy core
//! remains silent (serves the decoy) unless it detects:
//!
//! 1. A specific Phase 3 Timing Trigger (burst pattern in the first 3 packets)
//! 2. A custom TCP header option (magic bytes in the TCP Options field)
//!
//! To state probes and casual browsers, the VPS appears to be a legitimate
//! Iranian news/bank mirror.

use bytes::Bytes;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tracing::{debug, info, warn};

// ─────────────────────────────────────────────────────────────────────────────
// Configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Configuration for the decoy HTTP server.
#[derive(Debug, Clone)]
pub struct DecoyConfig {
    /// Listen address for the decoy server (e.g., `0.0.0.0:443`).
    pub listen_addr: String,
    /// The domestic site being cloned (e.g., `irna.ir`).
    pub clone_domain: String,
    /// HTML content to serve as the decoy page.
    pub decoy_html: String,
    /// The magic trigger bytes in the TLS ClientHello that activate the real proxy.
    /// Format: 4-byte magic in TCP Options (custom experimental option kind 253).
    pub trigger_magic: [u8; 4],
    /// Timing trigger: if the first 3 packets arrive with IPT < 10ms each,
    /// this is likely a legitimate client using Phase 3 burst mode.
    pub timing_trigger_max_ipt_ms: u64,
}

impl Default for DecoyConfig {
    fn default() -> Self {
        Self {
            listen_addr: "0.0.0.0:443".into(),
            clone_domain: "irna.ir".into(),
            decoy_html: generate_irna_clone(),
            trigger_magic: [0x52, 0x52, 0x41, 0x59], // "RRAY"
            timing_trigger_max_ipt_ms: 10,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Decoy HTML generator
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a functional clone of irna.ir that looks realistic to a manual browser check.
fn generate_irna_clone() -> String {
    format!(
        r##"<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>خبرگزاری جمهوری اسلامی - ایرنا</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Tahoma', 'Arial', sans-serif; background: #f5f5f5; direction: rtl; }}
        .header {{ background: #1a237e; color: white; padding: 15px 20px; text-align: center; }}
        .header h1 {{ font-size: 24px; margin-bottom: 5px; }}
        .header p {{ font-size: 12px; opacity: 0.8; }}
        .nav {{ background: #283593; padding: 10px 20px; display: flex; justify-content: center; gap: 20px; flex-wrap: wrap; }}
        .nav a {{ color: white; text-decoration: none; font-size: 14px; padding: 5px 10px; }}
        .nav a:hover {{ background: rgba(255,255,255,0.1); border-radius: 4px; }}
        .container {{ max-width: 1200px; margin: 20px auto; padding: 0 20px; }}
        .news-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(350px, 1fr)); gap: 20px; }}
        .news-card {{ background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        .news-card .img {{ background: #e0e0e0; height: 200px; display: flex; align-items: center; justify-content: center; color: #999; }}
        .news-card .content {{ padding: 15px; }}
        .news-card h3 {{ font-size: 16px; margin-bottom: 8px; color: #1a237e; }}
        .news-card p {{ font-size: 13px; color: #666; line-height: 1.6; }}
        .news-card .meta {{ font-size: 11px; color: #999; margin-top: 10px; }}
        .footer {{ background: #1a237e; color: white; padding: 20px; text-align: center; margin-top: 40px; }}
        .footer p {{ font-size: 12px; opacity: 0.7; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>خبرگزاری جمهوری اسلامی ایران - ایرنا</h1>
        <p>Islamic Republic News Agency - IRNA</p>
    </div>
    <div class="nav">
        <a href="#">سیاسی</a>
        <a href="#">اقتصادی</a>
        <a href="#">اجتماعی</a>
        <a href="#">ورزشی</a>
        <a href="#">فرهنگی</a>
        <a href="#">بین‌الملل</a>
        <a href="#">علمی</a>
    </div>
    <div class="container">
        <div class="news-grid">
            <div class="news-card">
                <div class="img">تصویر خبر</div>
                <div class="content">
                    <h3>توسعه زیرساخت‌های ارتباطی کشور در سال جدید</h3>
                    <p>وزیر ارتباطات و فناوری اطلاعات از برنامه‌های جدید برای توسعه شبکه ملی اطلاعات و بهبود کیفیت خدمات اینترنتی خبر داد.</p>
                    <div class="meta">۳۰ فروردین ۱۴۰۵ - ساعت ۱۴:۳۰</div>
                </div>
            </div>
            <div class="news-card">
                <div class="img">تصویر خبر</div>
                <div class="content">
                    <h3>افزایش همکاری‌های منطقه‌ای در حوزه انرژی</h3>
                    <p>مقامات ایرانی در دیدار با همتایان منطقه‌ای بر گسترش همکاری‌ها در زمینه انرژی و تجارت تأکید کردند.</p>
                    <div class="meta">۳۰ فروردین ۱۴۰۵ - ساعت ۱۲:۱۵</div>
                </div>
            </div>
            <div class="news-card">
                <div class="img">تصویر خبر</div>
                <div class="content">
                    <h3>پیشرفت‌های جدید در صنعت فضایی ایران</h3>
                    <p>رئیس سازمان فضایی از آخرین دستاوردهای ایران در حوزه ماهواره‌ای و پرتاب فضاپیما گزارش داد.</p>
                    <div class="meta">۲۹ فروردین ۱۴۰۵ - ساعت ۱۸:۴۵</div>
                </div>
            </div>
        </div>
    </div>
    <div class="footer">
        <p>تمامی حقوق مادی و معنوی این سایت متعلق به خبرگزاری جمهوری اسلامی (ایرنا) می‌باشد.</p>
        <p>&copy; {year} IRNA - Islamic Republic News Agency</p>
    </div>
</body>
</html>"##,
        year = 2026
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// Trigger detection
// ─────────────────────────────────────────────────────────────────────────────

/// Connection classification result.
#[derive(Debug, PartialEq)]
pub enum ConnectionType {
    /// Legitimate proxy client — forward to the real proxy core.
    ProxyClient,
    /// State probe or casual browser — serve the decoy page.
    DecoyTarget,
}

/// Timing trigger detector.
///
/// Tracks the arrival times of the first N packets and classifies the connection
/// based on whether the IPT pattern matches the Phase 3 burst signature.
pub struct TimingTriggerDetector {
    /// Timestamps of received packets.
    packet_times: Vec<Instant>,
    /// Maximum IPT (ms) between consecutive packets to qualify as a burst.
    max_ipt_ms: u64,
    /// Number of packets required to make a determination.
    required_packets: usize,
}

impl TimingTriggerDetector {
    pub fn new(max_ipt_ms: u64) -> Self {
        Self {
            packet_times: Vec::with_capacity(4),
            max_ipt_ms,
            required_packets: 3,
        }
    }

    /// Record a packet arrival. Returns `Some(ConnectionType)` once enough
    /// packets have been seen, or `None` if more data is needed.
    pub fn record_packet(&mut self) -> Option<ConnectionType> {
        self.packet_times.push(Instant::now());

        if self.packet_times.len() < self.required_packets {
            return None;
        }

        // Check that all consecutive IPTs are below the threshold.
        let all_burst = self.packet_times.windows(2).all(|w| {
            let ipt_ms = w[1].duration_since(w[0]).as_millis() as u64;
            ipt_ms <= self.max_ipt_ms
        });

        if all_burst {
            Some(ConnectionType::ProxyClient)
        } else {
            Some(ConnectionType::DecoyTarget)
        }
    }

    /// Check a custom TCP option magic value.
    ///
    /// If the first bytes of the TLS ClientHello contain the magic trigger,
    /// immediately classify as a proxy client.
    pub fn check_magic(data: &[u8], magic: &[u8; 4]) -> bool {
        // Look for the magic bytes in the TCP payload (ClientHello).
        // The magic is placed as a custom TCP option (kind 253, len 6, 4 bytes magic).
        if data.len() < 6 {
            return false;
        }
        // Scan TCP options area for kind=253.
        for window in data.windows(6) {
            if window[0] == 253 && window[1] == 6 && &window[2..6] == magic {
                return true;
            }
        }
        false
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Decoy HTTP handler
// ─────────────────────────────────────────────────────────────────────────────

/// Serve the decoy page for all HTTP requests.
async fn decoy_handler(
    _req: Request<Incoming>,
    html: Arc<String>,
    domain: Arc<String>,
) -> std::result::Result<Response<http_body_util::Full<Bytes>>, Infallible> {
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "text/html; charset=utf-8")
        .header("Server", "nginx/1.24.0")
        .header("X-Powered-By", "PHP/8.2")
        .header("X-Content-Type-Options", "nosniff")
        .header("X-Frame-Options", "SAMEORIGIN")
        .header("Cache-Control", "public, max-age=3600")
        .body(http_body_util::Full::new(Bytes::from(html.as_bytes().to_vec())))
        .unwrap_or_else(|_| {
            Response::new(http_body_util::Full::new(Bytes::from("OK")))
        });

    debug!("Decoy: Served {} clone page", domain);
    Ok(response)
}

/// Start the decoy HTTP server.
///
/// This should be spawned as a background task on every VPS.
/// Returns a `JoinHandle` for the server task.
pub async fn start_decoy_server(config: DecoyConfig) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    let addr: SocketAddr = config.listen_addr.parse()
        .unwrap_or_else(|_| "0.0.0.0:8443".parse().unwrap());

    let listener = TcpListener::bind(addr).await?;
    info!("Decoy: Serving {} clone on {}", config.clone_domain, addr);

    let html = Arc::new(config.decoy_html);
    let domain = Arc::new(config.clone_domain);

    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _peer)) => {
                    let html = html.clone();
                    let domain = domain.clone();
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        let svc = service_fn(move |req| {
                            decoy_handler(req, html.clone(), domain.clone())
                        });
                        if let Err(e) = hyper_util::server::conn::auto::Builder::new(
                            hyper_util::rt::TokioExecutor::new(),
                        )
                        .serve_connection(io, svc)
                        .await
                        {
                            debug!("Decoy: Connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    warn!("Decoy: Accept error: {}", e);
                }
            }
        }
    });

    Ok(handle)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let cfg = DecoyConfig::default();
        assert_eq!(cfg.clone_domain, "irna.ir");
        assert_eq!(cfg.trigger_magic, [0x52, 0x52, 0x41, 0x59]);
    }

    #[test]
    fn test_decoy_html_generation() {
        let html = generate_irna_clone();
        assert!(html.contains("ایرنا"));
        assert!(html.contains("IRNA"));
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("2026"));
    }

    #[test]
    fn test_timing_trigger_burst_detected() {
        let mut detector = TimingTriggerDetector::new(10);
        // Simulate rapid-fire packets (all within 10ms).
        assert!(detector.record_packet().is_none()); // 1st
        assert!(detector.record_packet().is_none()); // 2nd
        // 3rd — all IPTs should be < 1ms (same test thread).
        let result = detector.record_packet();
        assert_eq!(result, Some(ConnectionType::ProxyClient));
    }

    #[test]
    fn test_check_magic_found() {
        // Simulate TCP options with our magic trigger.
        let data = [0, 0, 253, 6, 0x52, 0x52, 0x41, 0x59, 0, 0];
        assert!(TimingTriggerDetector::check_magic(&data, &[0x52, 0x52, 0x41, 0x59]));
    }

    #[test]
    fn test_check_magic_not_found() {
        let data = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        assert!(!TimingTriggerDetector::check_magic(&data, &[0x52, 0x52, 0x41, 0x59]));
    }

    #[test]
    fn test_check_magic_too_short() {
        let data = [253, 6, 0x52];
        assert!(!TimingTriggerDetector::check_magic(&data, &[0x52, 0x52, 0x41, 0x59]));
    }

    #[test]
    fn test_connection_type_debug() {
        assert_eq!(format!("{:?}", ConnectionType::ProxyClient), "ProxyClient");
        assert_eq!(format!("{:?}", ConnectionType::DecoyTarget), "DecoyTarget");
    }
}
