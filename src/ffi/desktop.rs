use crate::ffi::ConnectConfig;
use crate::tun::{MtuProfile, StreamEvent, Tun2SocksConfig, Tun2SocksEngine, TunConfig};
use std::net::IpAddr;
use tokio::net::TcpStream;
use tokio::runtime::Runtime;
use tracing::{error, info};

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub fn run_desktop_tun(runtime: &Runtime, connect_config: &ConnectConfig) {
    let routing_mode = connect_config.routing_mode.as_str();

    if routing_mode == "tun" || routing_mode == "global" {
        let tun_name = "rustray0".to_string();
        info!("Starting Desktop Tun2Socks on {}", tun_name);

        let mut tun_conf = Tun2SocksConfig::default();
        tun_conf.tun = TunConfig {
            name: tun_name,
            mtu_profile: MtuProfile::Standard,
            ..Default::default()
        };

        let mut engine = Tun2SocksEngine::new(tun_conf);
        let event_rx = match engine.take_event_receiver() {
            Some(rx) => rx,
            None => {
                error!("Failed to get event receiver");
                return;
            }
        };

        runtime.spawn(async move {
            if let Err(e) = engine.run().await {
                error!("Tun2Socks engine failed: {}", e);
            }
        });

        // Handle SOCKS tunneling loop
        let socks_addr = format!(
            "{}:{}",
            connect_config.local_address, connect_config.local_port
        );

        handle_desktop_events(runtime, event_rx, socks_addr);
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn handle_desktop_events(
    runtime: &Runtime,
    mut event_rx: tokio::sync::mpsc::Receiver<StreamEvent>,
    socks_addr: String,
) {
    runtime.spawn(async move {
        while let Some(event) = event_rx.recv().await {
            if let StreamEvent::TcpConnect {
                    key,
                    stream_tx,
                    mut stream_rx,
                } = event {
                let target_addr = key.dst_addr;
                let target_port = key.dst_port;
                let socks_target = socks_addr.clone();

                tokio::spawn(async move {
                    match TcpStream::connect(&socks_target).await {
                        Ok(mut socks_stream) => {
                            use tokio::io::{AsyncReadExt, AsyncWriteExt};
                            // 1. Auth neg
                            if socks_stream.write_all(&[0x05, 0x01, 0x00]).await.is_err() {
                                return;
                            }
                            let mut buf = [0u8; 2];
                            if socks_stream.read_exact(&mut buf).await.is_err()
                                || buf[0] != 0x05
                                || buf[1] != 0x00
                            {
                                return;
                            }

                            // 2. Request
                            let mut req = vec![0x05, 0x01, 0x00];
                            match target_addr {
                                IpAddr::V4(v4) => {
                                    req.push(0x01);
                                    req.extend_from_slice(&v4.octets());
                                }
                                IpAddr::V6(v6) => {
                                    req.push(0x04);
                                    req.extend_from_slice(&v6.octets());
                                }
                            }
                            req.extend_from_slice(&target_port.to_be_bytes());
                            if socks_stream.write_all(&req).await.is_err() {
                                return;
                            }

                            // 3. Response
                            let mut resp_head = [0u8; 4];
                            if socks_stream.read_exact(&mut resp_head).await.is_err()
                                || resp_head[1] != 0x00
                            {
                                return;
                            }
                            let addr_len = match resp_head[3] {
                                1 => 4,
                                4 => 16,
                                3 => {
                                    let mut len = [0u8];
                                    if socks_stream.read_exact(&mut len).await.is_err() {
                                        return;
                                    }
                                    len[0] as usize
                                }
                                _ => 0,
                            };
                            let mut _addr = vec![0u8; addr_len + 2];
                            let _ = socks_stream.read_exact(&mut _addr).await;

                            // 4. Pipe
                            let (mut ro, mut wo) = socks_stream.into_split();
                            let t2s = tokio::spawn(async move {
                                let mut buf = vec![0u8; 65536];
                                loop {
                                    match ro.read(&mut buf).await {
                                        Ok(0) => break,
                                        Ok(n) => {
                                            if stream_tx.send(buf[..n].to_vec()).await.is_err()
                                            {
                                                break;
                                            }
                                        }
                                        Err(_) => break,
                                    }
                                }
                            });
                            let s2t = tokio::spawn(async move {
                                while let Some(data) = stream_rx.recv().await {
                                    if wo.write_all(&data).await.is_err() {
                                        break;
                                    }
                                }
                            });
                            let _ = tokio::join!(t2s, s2t);
                        }
                        Err(e) => error!("SOCKS connect error: {}", e),
                    }
                });
            }
        }
    });
}
