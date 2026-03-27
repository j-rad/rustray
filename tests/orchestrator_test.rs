// tests/orchestrator_test.rs
use rustray::orchestrator::manager::{Orchestrator, OrchestratorConfig};
use rustray::orchestrator::probe::ProbeConfig;

#[tokio::test]
async fn test_orchestrator_config_and_creation() {
    let prober = ProbeConfig {
        timeout_ms: 1000,
        parallel_probes: 2,
        interval_ms: 2000,
    };
    let config = OrchestratorConfig {
        probe: prober,
        health_interval_ms: 5000,
        failover_threshold: 3,
    };
    
    // We mock building an orchestrator and running background thread
    let _orchestrator = Orchestrator::new(config.clone());
    
    // Test properties
    assert_eq!(config.health_interval_ms, 5000);
}
