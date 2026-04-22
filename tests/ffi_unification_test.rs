#![cfg(not(target_arch = "wasm32"))]
use rustray::ffi::{EngineManager, RustRayResult};

#[test]
fn test_engine_lifecycle() {
    let engine = EngineManager::new();

    // 1. Initial State
    let stats = engine.get_stats_json();
    assert!(
        stats.contains("connection_state"),
        "Stats should contain state"
    );

    // 2. Start Engine (with valid config)
    let config = r#"
    {
        "address": "127.0.0.1",
        "port": 1080,
        "uuid": "00000000-0000-0000-0000-000000000000",
        "protocol": "vless",
        "network": "tcp",
        "security": "none"
    }
    "#;

    let res = engine.start_engine(config.to_string(), None);
    // It might fail to bind if port is taken, or succeed.
    // Since we are mocking or running locally, let's treat AlreadyRunning as semi-success or expect Ok.

    // Note: run_server spawns tasks. If address is in use, it might error asyncly, but start_engine returns Ok if spawn succeeds.
    // However, build_internal_config might fail if config is bad.

    assert_eq!(res, RustRayResult::Ok);

    // 3. Check Running State
    // Attempting to start again should fail
    let res2 = engine.start_engine(config.to_string(), None);
    assert_eq!(res2, RustRayResult::AlreadyRunning);

    // 4. Stop Engine
    let stop_res = engine.stop_engine();
    assert_eq!(stop_res, RustRayResult::Ok);

    // 5. Stop again should fail (NotRunning)
    let stop_res2 = engine.stop_engine();
    assert_eq!(stop_res2, RustRayResult::NotRunning);
}

#[test]
fn test_invalid_config() {
    let engine = EngineManager::new();
    let res = engine.start_engine("{{}".to_string(), None); // Invalid JSON
    assert!(matches!(res, RustRayResult::ConfigError(_)));
}
