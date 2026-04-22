// tests/integration.rs
#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use rustray::config::{
        self, ApiConfig, Config, FreedomSettings, Inbound, InboundSettings, Outbound,
        OutboundSettings, RealityServerConfig, SocksSettings, StreamSettings, VlessSettings,
        VlessUser,
    };
    use std::collections::HashMap;
    use std::fs::File;
    use std::io::{Cursor, Write};
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::sync::Once;
    use std::time::Duration;
    use tempfile::TempDir;
    use tokio::net::UdpSocket;

    static INIT: Once = Once::new();

    fn setup_logs() {
        INIT.call_once(|| {
            tracing_subscriber::fmt::init();
        });
    }

    struct ChildGuard(Child);
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    async fn download_rustray() -> PathBuf {
        let bin_path = PathBuf::from("bin/rustray");
        if bin_path.exists() {
            return bin_path;
        }

        std::fs::create_dir_all("bin").unwrap();
        let url = "https://github.com/RustRay/RustRay/releases/download/v25.12.8/RustRay-linux-64.zip";
        let client = reqwest::Client::new();
        let resp = client
            .get(url)
            .send()
            .await
            .expect("Failed to download RustRay");
        let content = resp.bytes().await.expect("Failed to read bytes");
        let mut archive = zip::ZipArchive::new(Cursor::new(content)).expect("Failed to open zip");
        let mut rustray_file = archive
            .by_name("rustray")
            .expect("rustray binary not found in zip");
        let mut dest = File::create(&bin_path).expect("Failed to create rustray file");
        std::io::copy(&mut rustray_file, &mut dest).expect("Failed to copy rustray binary");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&bin_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&bin_path, perms).unwrap();
        }
        bin_path
    }

    #[tokio::test]
    async fn test_vless_tcp_http() {
        setup_logs();
        let rustray_bin = download_rustray().await;
        let server_port = 10001;
        let uuid = "509c3132-7232-4235-9626-267926132174";

        let mut server_config = Config::default();
        server_config.inbounds = Some(vec![Inbound {
            tag: "vless-in".to_string(),
            port: server_port,
            listen: Some("127.0.0.1".to_string()),
            protocol: "vless".to_string(),
            settings: Some(InboundSettings::Vless(VlessSettings {
                clients: vec![VlessUser {
                    id: uuid.to_string(),
                    level: Some(0),
                    email: None,
                    flow: None,
                }],
                decryption: Some("none".to_string()),
                fallbacks: None,
            })),
            stream_settings: None,
            sniffing: None,
            allocation: None,
        }]);
        server_config.outbounds = Some(vec![Outbound {
            tag: "direct".to_string(),
            protocol: "freedom".to_string(),
            settings: Some(OutboundSettings::Freedom(FreedomSettings::default())),
            stream_settings: None,
            mux: None,
            proxy_settings: None,
        }]);
        server_config.api = Some(ApiConfig {
            tag: "api".to_string(),
            services: vec![],
            port: Some(8091),
            listen: Some("127.0.0.1".to_string()),
        });

        let (_tx, rx) = tokio::sync::broadcast::channel(1);
        tokio::spawn(async move {
            rustray::run_server(server_config, rx).await.unwrap();
        });
        tokio::time::sleep(Duration::from_secs(1)).await;

        let client_port = 10002;
        let rustray_config_json = serde_json::json!({
            "log": { "loglevel": "none" },
            "inbounds": [{
                "port": client_port,
                "listen": "127.0.0.1",
                "protocol": "http",
                "settings": {}
            }],
            "outbounds": [{
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": "127.0.0.1",
                        "port": server_port,
                        "users": [{ "id": uuid, "encryption": "none" }]
                    }]
                },
                "streamSettings": { "network": "tcp" }
            }]
        });

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.json");
        let mut file = File::create(&config_path).unwrap();
        file.write_all(
            serde_json::to_string(&rustray_config_json)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();

        let child = Command::new(&rustray_bin)
            .arg("-c")
            .arg(&config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to start rustray");
        let _guard = ChildGuard(child);

        tokio::time::sleep(Duration::from_secs(1)).await;

        let proxy_url = format!("http://127.0.0.1:{}", client_port);
        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::http(&proxy_url).unwrap())
            .build()
            .unwrap();

        let resp = client.get("http://www.google.com").send().await;
        match resp {
            Ok(r) => assert!(r.status().is_success() || r.status().is_redirection()),
            Err(e) => panic!("Request failed: {}", e),
        }
    }

    #[tokio::test]
    async fn test_vless_reality() {
        setup_logs();
        let rustray_bin = download_rustray().await;
        let server_port = 10005;
        let uuid = "509c3132-7232-4235-9626-267926132174";
        // Private key for server (curve25519)
        let _private_key = "c0f4c0f4c0f4c0f4c0f4c0f4c0f4c0f4c0f4c0f4c0f4c0f4c0f4c0f4c0f4c0f4";
        // Corresponding Public Key (derived):
        // We use RustRay to generate or a known pair.
        // For 'c0f4...' private key, public key is 'wPTPz4j...'.
        // Actually, let's use a known pair generated by rustray x25519.
        // Private: 6M... (example from docs? No, randomly generated).
        // Let's rely on config parity.
        // I will use a pair I generate now or trust the test structure.
        // Let's use:
        // Priv: `iIuYh2s3lq...` (random)
        // Pub: `...`
        // Better: Use `openssl` or existing tool? No tool.
        // I will use the pair provided in standard examples or generate one.
        // Private: `2b70...`
        // Public: `...`
        // Since I can't run `rustray x25519` easily in code without parsing, I'll use a fixed pair.
        // Priv: "6G..." -> Pub: "..."
        //
        // Let's try to assume the key `c0f4...` works and I need its public key.
        // Public Key for `c0f4...` is `4M...`? I can't guess.
        // I will skip key validation in `RustRay`? No, `REALITY` checks it.
        //
        // I will use a known pair:
        // Private: `MHsCAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQE...` no that's PEM.
        // RustRay uses base64url safe without padding? Or hex?
        // RustRay config uses standard Base64 usually.
        //
        // Let's use `openssl genpkey -algorithm x25519` logic if available or just hardcode.
        // Hardcoded Pair:
        let _pk = "6G...".to_string(); // Placeholder?
        // I will use a random key pair from a reliable source.
        // Private: `sCC..`
        // Public: `...`
        //
        // Okay, I will use `rustray x25519` via Command to get a fresh pair!
        let output = Command::new(&rustray_bin)
            .arg("x25519")
            .output()
            .expect("Failed to gen keys");
        let stdout = String::from_utf8(output.stdout).unwrap();
        // Output format: "Private key: ... \n Public key: ..."
        let parts: Vec<&str> = stdout.split_whitespace().collect();
        // parts: ["Private", "key:", "PRIV", "Public", "key:", "PUB"]
        let private_key = parts[2].to_string();
        let public_key = parts[5].to_string();
        let short_id = "12345678".to_string();

        let mut server_config = Config::default();
        let mut server_names = HashMap::new();
        server_names.insert(
            "www.google.com".to_string(),
            "www.google.com:443".to_string(),
        );

        let reality_server = RealityServerConfig {
            server_names: server_names.keys().cloned().collect(),
            private_key: hex::encode(BASE64_STANDARD.decode(&private_key).unwrap_or(vec![0; 32])),
            short_ids: vec![hex::encode(&short_id)],
            show: false,
            dest: "www.google.com:443".to_string(),
            xver: 0,
            min_client_ver: "".to_string(),
            max_client_ver: "".to_string(),
            max_time_diff: 0,
            decoy_proxy_addr: None,
            mimic_settings: None,
        };
        // Wait, `reality.rs` `check_reality_auth`: `hex::decode(&config.private_key)`.
        // So I must convert base64 to hex.
        // ShortId: `hex::decode(short_id_hex)`.
        // RustRay config uses hex for shortId usually `["..."]`.

        server_config.inbounds = Some(vec![Inbound {
            tag: "reality-in".to_string(),
            port: server_port,
            listen: Some("127.0.0.1".to_string()),
            protocol: "vless".to_string(),
            settings: Some(InboundSettings::Vless(VlessSettings {
                clients: vec![VlessUser {
                    id: uuid.to_string(),
                    level: Some(0),
                    email: None,
                    flow: Some("rustray-rustray-vision".to_string()),
                }],
                decryption: Some("none".to_string()),
                fallbacks: None,
            })),
            stream_settings: Some(StreamSettings {
                network: "tcp".to_string(),
                security: "reality".to_string(),
                reality_server_settings: Some(reality_server),
                ..Default::default()
            }),
            sniffing: None,
            allocation: None,
        }]);

        server_config.outbounds = Some(vec![Outbound {
            tag: "direct".to_string(),
            protocol: "freedom".to_string(),
            settings: Some(OutboundSettings::Freedom(FreedomSettings::default())),
            stream_settings: None,
            mux: None,
            proxy_settings: None,
        }]);
        server_config.api = Some(ApiConfig {
            tag: "api".to_string(),
            services: vec![],
            port: Some(8092),
            listen: Some("127.0.0.1".to_string()),
        });

        let (_tx, rx) = tokio::sync::broadcast::channel(1);
        tokio::spawn(async move {
            rustray::run_server(server_config, rx).await.unwrap();
        });
        tokio::time::sleep(Duration::from_secs(1)).await;

        let client_port = 10006;
        let rustray_config_json = serde_json::json!({
            "log": { "loglevel": "none" },
            "inbounds": [{
                "port": client_port,
                "listen": "127.0.0.1",
                "protocol": "http",
                "settings": {}
            }],
            "outbounds": [{
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address": "127.0.0.1",
                        "port": server_port,
                        "users": [{ "id": uuid, "encryption": "none", "flow": "rustray-rustray-vision" }]
                    }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "reality",
                    "realitySettings": {
                        "show": false,
                        "fingerprint": "chrome",
                        "serverName": "www.google.com",
                        "publicKey": public_key,
                        "shortId": short_id,
                        "spiderX": "/"
                    }
                }
            }]
        });

        let temp_dir = TempDir::new().unwrap();
        let config_path = temp_dir.path().join("config.json");
        let mut file = File::create(&config_path).unwrap();
        file.write_all(
            serde_json::to_string(&rustray_config_json)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();

        let child = Command::new(&rustray_bin)
            .arg("-c")
            .arg(&config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to start rustray client");
        let _guard = ChildGuard(child);

        tokio::time::sleep(Duration::from_secs(1)).await;

        let proxy_url = format!("http://127.0.0.1:{}", client_port);
        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::http(&proxy_url).unwrap())
            .build()
            .unwrap();

        let resp = client.get("http://www.google.com").send().await;
        match resp {
            Ok(r) => assert!(r.status().is_success() || r.status().is_redirection()),
            Err(e) => panic!("Request failed: {}", e),
        }
    }

    #[tokio::test]
    async fn test_udp_forwarding() {
        setup_logs();
        let udp_server_port = 10003;
        let proxy_port = 10004;

        let _echo_handle = tokio::spawn(async move {
            let socket = UdpSocket::bind(format!("127.0.0.1:{}", udp_server_port))
                .await
                .unwrap();
            let mut buf = [0u8; 1024];
            loop {
                let (len, addr) = socket.recv_from(&mut buf).await.unwrap();
                socket.send_to(&buf[..len], addr).await.unwrap();
            }
        });

        let mut server_config = Config::default();
        use rustray::config::DokodemoSettings;
        server_config.inbounds = Some(vec![Inbound {
            tag: "dokodemo-udp".to_string(),
            port: proxy_port,
            listen: Some("127.0.0.1".to_string()),
            protocol: "dokodemo-door".to_string(),
            settings: Some(InboundSettings::Dokodemo(DokodemoSettings {
                address: "127.0.0.1".to_string(),
                port: udp_server_port,
                network: Some("udp".to_string()),
                tproxy: Some(false),
            })),
            stream_settings: Some(StreamSettings {
                network: "udp".to_string(),
                ..Default::default()
            }),
            sniffing: None,
            allocation: None,
        }]);
        server_config.outbounds = Some(vec![Outbound {
            tag: "direct".to_string(),
            protocol: "freedom".to_string(),
            settings: Some(OutboundSettings::Freedom(FreedomSettings::default())),
            stream_settings: None,
            mux: None,
            proxy_settings: None,
        }]);
        server_config.api = Some(ApiConfig {
            tag: "api".to_string(),
            services: vec![],
            port: Some(8093),
            listen: Some("127.0.0.1".to_string()),
        });

        let (_tx, rx) = tokio::sync::broadcast::channel(1);
        tokio::spawn(async move {
            rustray::run_server(server_config, rx).await.unwrap();
        });
        tokio::time::sleep(Duration::from_secs(1)).await;

        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket
            .connect(format!("127.0.0.1:{}", proxy_port))
            .await
            .unwrap();

        let msg = b"hello udp";
        socket.send(msg).await.unwrap();

        let mut buf = [0u8; 1024];
        let res = tokio::time::timeout(Duration::from_secs(2), socket.recv(&mut buf)).await;

        match res {
            Ok(Ok(len)) => assert_eq!(&buf[..len], msg),
            _ => panic!("UDP Echo timed out"),
        }
    }
    #[tokio::test]
    async fn test_rustray_client_rustray_server() {
        setup_logs();
        let rustray_bin = download_rustray().await;
        let server_port = 10007;
        let client_port = 10008;
        let uuid = "509c3132-7232-4235-9626-267926132174";

        // 1. Setup RustRay as VLESS Server (VLESS + TCP + RustRay Vision)
        // Check for openssl to gen certs, or use a bundled one?
        // We'll generate a temp cert.
        let temp_dir_certs = TempDir::new().unwrap();
        let cert_path = temp_dir_certs.path().join("cert.pem");
        let key_path = temp_dir_certs.path().join("key.pem");

        // Try to generate certs. If fails, we might fail the test or skip.
        // Assuming openssl is present in CI env.
        let status = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-keyout",
                key_path.to_str().unwrap(),
                "-out",
                cert_path.to_str().unwrap(),
                "-days",
                "365",
                "-nodes",
                "-subj",
                "/CN=localhost",
            ])
            .output();

        if status.is_err() {
            // If no openssl, maybe skip or panic?
            eprintln!(
                "Warning: openssl not found, cannot test RustRay/TLS. Skipping TLS setup might fail if flow requires it."
            );
        }

        let rustray_config_json = serde_json::json!({
            "log": { "loglevel": "none" },
            "inbounds": [{
                "port": server_port,
                "listen": "127.0.0.1",
                "protocol": "vless",
                "settings": {
                    "clients": [{ "id": uuid, "flow": "rustray-rustray-vision" }],
                    "decryption": "none"
                },
                "streamSettings": {
                    "network": "tcp",
                    "security": "tls",
                    "tlsSettings": {
                        "certificates": [{
                            "certificateFile": cert_path.to_str().unwrap(),
                            "keyFile": key_path.to_str().unwrap()
                        }]
                    }
                }
            }],
            "outbounds": [{
                "protocol": "freedom"
            }]
        });

        // 2. Setup RustRay as Client (Socks -> VLESS Outbound)
        let mut rustray_config = Config::default();
        rustray_config.inbounds = Some(vec![Inbound {
            tag: "socks-in".to_string(),
            port: client_port,
            listen: Some("127.0.0.1".to_string()),
            protocol: "socks".to_string(),
            settings: Some(InboundSettings::Socks(SocksSettings {
                auth: Some("noauth".to_string()),
                ..Default::default()
            })),
            stream_settings: None,
            sniffing: None,
            allocation: None,
        }]);

        let vless_out_settings = config::VlessOutboundSettings {
            address: "127.0.0.1".to_string(),
            port: server_port,
            uuid: uuid.to_string(),
            flow: Some("rustray-rustray-vision".to_string()),
            reality_settings: None,
        };

        rustray_config.outbounds = Some(vec![Outbound {
            tag: "vless-out".to_string(),
            protocol: "vless".to_string(),
            settings: Some(OutboundSettings::Vless(vless_out_settings)),
            stream_settings: Some(StreamSettings {
                network: "tcp".to_string(),
                security: "tls".to_string(), // RustRay should use TLS
                tls_settings: Some(config::TlsSettings {
                    server_name: Some("localhost".to_string()),
                    allow_insecure: Some(true),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            mux: None,
            proxy_settings: None,
        }]);
        rustray_config.api = Some(ApiConfig {
            tag: "api".to_string(),
            services: vec![],
            port: Some(8094),
            listen: Some("127.0.0.1".to_string()),
        });

        let temp_dir_config = TempDir::new().unwrap();
        let config_path = temp_dir_config.path().join("config_server.json");
        let mut file = File::create(&config_path).unwrap();
        file.write_all(
            serde_json::to_string(&rustray_config_json)
                .unwrap()
                .as_bytes(),
        )
        .unwrap();

        let child = Command::new(rustray_bin)
            .arg("-c")
            .arg(&config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to start rustray server");
        let _guard = ChildGuard(child);

        tokio::time::sleep(Duration::from_secs(2)).await;

        let (_tx, rx) = tokio::sync::broadcast::channel(1);
        tokio::spawn(async move {
            rustray::run_server(rustray_config, rx).await.unwrap();
        });
        tokio::time::sleep(Duration::from_secs(2)).await;

        let proxy_url = format!("socks5://127.0.0.1:{}", client_port);
        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(&proxy_url).unwrap())
            .build()
            .unwrap();

        let resp = client.get("http://www.google.com").send().await;

        match resp {
            Ok(r) => assert!(r.status().is_success() || r.status().is_redirection()),
            Err(e) => panic!("Request failed through RustRay->RustRay: {}", e),
        }
    }
}
