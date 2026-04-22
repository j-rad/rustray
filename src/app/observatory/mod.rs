// src/app/observatory/mod.rs
use crate::app::stats::StatsManager;
use crate::config::ObservatoryConfig;
use crate::outbounds::OutboundManager;
use std::sync::Arc;

pub struct Observatory {
    #[allow(dead_code)]
    config: ObservatoryConfig,
    #[allow(dead_code)]
    outbounds: Arc<OutboundManager>,
    #[allow(dead_code)]
    stats: Arc<StatsManager>,
}

use std::time::Instant;
use tracing::info;

impl Observatory {
    pub fn new(
        config: ObservatoryConfig,
        outbounds: Arc<OutboundManager>,
        stats: Arc<StatsManager>,
    ) -> Self {
        Self {
            config,
            outbounds,
            stats,
        }
    }

    pub fn run(self: Arc<Self>) {
        let this = self.clone();
        tokio::spawn(async move {
            let interval = match parse_duration(&this.config.probe_interval) {
                Some(d) => d,
                None => std::time::Duration::from_secs(10),
            };
            let mut ticker = tokio::time::interval(interval);

            let probe_url = this
                .config
                .probe_url
                .clone()
                .unwrap_or_else(|| "1.1.1.1:80".to_string());
            let (host, port) = if let Some(pos) = probe_url.find(':') {
                let (h, p_str) = probe_url.split_at(pos);
                let p = p_str[1..].parse().unwrap_or(80);
                (h.to_string(), p)
            } else {
                (probe_url, 80)
            };

            loop {
                ticker.tick().await;

                let tags = if let Some(ref selector) = this.config.subject_selector {
                    selector.clone()
                } else {
                    this.outbounds.get_all_tags()
                };

                for tag in tags {
                    let handler = match this.outbounds.get(&tag) {
                        Some(h) => h,
                        None => continue,
                    };

                    let stats = this.stats.clone();
                    let tag_clone = tag.clone();
                    let host_clone = host.clone();
                    let port_clone = port;

                    tokio::spawn(async move {
                        let start = Instant::now();
                        let res = handler.dial(host_clone, port_clone).await;
                        let latency = start.elapsed().as_millis() as u64;

                        stats.update_outbound_monitor(&tag_clone, res.is_ok(), latency);
                        if let Err(e) = res {
                            info!(
                                "Observatory: Probe failed for outbound '{}': {:?}",
                                tag_clone, e
                            );
                        }
                    });
                }
            }
        });
    }
}

fn parse_duration(s: &str) -> Option<std::time::Duration> {
    let mut num = String::new();
    let mut unit = String::new();
    for c in s.chars() {
        if c.is_ascii_digit() {
            num.push(c);
        } else {
            unit.push(c);
        }
    }
    let n: u64 = num.parse().ok()?;
    match unit.as_str() {
        "s" => Some(std::time::Duration::from_secs(n)),
        "ms" => Some(std::time::Duration::from_millis(n)),
        "m" => Some(std::time::Duration::from_secs(n * 60)),
        "h" => Some(std::time::Duration::from_secs(n * 3600)),
        _ => Some(std::time::Duration::from_secs(n)),
    }
}
