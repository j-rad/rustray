use rustray::config::Config;
use rustray::run_server;
use std::time::Duration;
use tokio::sync::broadcast;

#[tokio::test]
#[cfg(feature = "minimal-server")]
async fn test_headless_dashboard_serving() {
    // 1. Setup Config
    let mut config = Config::default();
    config.api = Some(rustray::config::ApiConfig {
        port: Some(19000), // Metrics/Dashboard will be on 19001
        listen: Some("127.0.0.1".to_string()),
        ..Default::default()
    });
    // Disable other services to keep it light
    config.dns = None;
    config.inbounds = Some(vec![]);
    config.outbounds = Some(vec![]);

    // 2. Setup Shutdown Channel
    let (shutdown_tx, shutdown_rx) = broadcast::channel(1);

    // 3. Spawn Server
    let server_handle = tokio::spawn(async move { run_server(config, shutdown_rx).await });

    // Give it a moment to start
    tokio::time::sleep(Duration::from_secs(2)).await;

    // 4. Test Requests
    let client = reqwest::Client::new();
    let base_url = "http://127.0.0.1:19001";

    // Test 4.1: Helper index
    let resp = client
        .get(format!("{}/", base_url))
        .send()
        .await
        .expect("Failed to req root");
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.expect("Failed to read body");
    assert!(
        body.to_lowercase().contains("<!doctype html"),
        "Body did not contain doctype: {}",
        body
    );

    // Test 4.2: Stats endpoint
    let resp_stats = client
        .get(format!("{}/node/stats", base_url))
        .send()
        .await
        .expect("Failed to req stats");
    assert_eq!(resp_stats.status(), 200);
    let stats_json: serde_json::Value =
        resp_stats.json().await.expect("Failed to parse stats json");
    assert!(stats_json.get("connection_state").is_some());

    // 5. Shutdown
    shutdown_tx.send(()).unwrap();

    // Wait for shutdown (server waits 1s)
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(server_handle.is_finished());
}
