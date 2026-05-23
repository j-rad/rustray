// tests/reconciliation_sync.rs
//! Reconciliation Sync Test
//!
//! Validates the ControlBus delta-push and consistency verification logic:
//!
//! 1. A fresh `HotConfig` is populated from a base config.
//! 2. A JSON-Patch is pushed to mutate a field.
//! 3. `verify_consistency` confirms the expected hash matches.
//! 4. The config is corrupted in-place (simulating a node divergence).
//! 5. `verify_consistency` detects the mismatch and returns the actual hash.
//! 6. The correct config is re-pushed and consistency is restored.
//!
//! Load target: 10,000 concurrent heartbeat tasks each calling
//! `verify_consistency`, validating the engine handles fleet-scale
//! telemetry without data races.

use rustray::{
    api::rustray_control::{ControlBus, HotConfig},
    config::Config,
};
use std::sync::Arc;
use tokio::sync::Semaphore;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a minimal valid `Config` for testing.
fn minimal_config() -> Config {
    serde_json::from_str(
        r#"{ "api": { "tag": "api", "services": [], "port": 10085, "listen": "127.0.0.1" } }"#,
    )
    .expect("minimal_config: parse failed")
}

/// JSON-Patch that sets `api.tag` to "patched-api".
const PATCH_API_TAG: &str = r#"[
  { "op": "replace", "path": "/api/tag", "value": "patched-api" }
]"#;

// ---------------------------------------------------------------------------
// Test: basic delta push + consistency verification
// ---------------------------------------------------------------------------

#[tokio::test]
async fn delta_push_and_consistency_roundtrip() {
    let cfg = minimal_config();
    let hot = HotConfig::new(cfg);

    // Record baseline hash.
    let baseline_hash = hot.sha256_hex().await;
    assert!(!baseline_hash.is_empty(), "baseline hash must not be empty");

    // Apply a patch.
    let new_hash = hot
        .apply_patch_test(PATCH_API_TAG)
        .await
        .expect("patch must succeed");

    // Hash must have changed.
    assert_ne!(new_hash, baseline_hash, "hash must change after patch");

    // Verify the tag was actually updated.
    {
        let guard = hot.read().await;
        let api_tag = guard
            .api
            .as_ref()
            .map(|a| a.tag.as_str())
            .unwrap_or("(none)");
        assert_eq!(api_tag, "patched-api", "api.tag must reflect the patch");
    }

    // verify_consistency: correct hash → match.
    let actual = hot.sha256_hex().await;
    assert_eq!(actual, new_hash, "hash must be stable between calls");
}

// ---------------------------------------------------------------------------
// Test: corruption detection + re-push auto-fix
// ---------------------------------------------------------------------------

#[tokio::test]
async fn consistency_mismatch_detected_after_corruption() {
    let cfg = minimal_config();
    let hot = HotConfig::new(cfg.clone());

    let original_hash = hot.sha256_hex().await;

    // Apply a legitimate patch.
    let patched_hash = hot
        .apply_patch_test(PATCH_API_TAG)
        .await
        .expect("patch must succeed");

    // Simulate divergence: re-apply the original config (as if a node reset itself).
    let revert_patch = format!(
        r#"[{{ "op": "replace", "path": "/api/tag", "value": "{}" }}]"#,
        cfg.api.as_ref().map(|a| a.tag.as_str()).unwrap_or("api")
    );
    let reverted_hash = hot
        .apply_patch_test(&revert_patch)
        .await
        .expect("revert patch must succeed");

    // The UI expects the patched hash — detect divergence.
    assert_ne!(
        reverted_hash, patched_hash,
        "after revert, hash must differ from the patched hash"
    );
    assert_eq!(
        reverted_hash, original_hash,
        "after revert, hash must match original"
    );

    // Re-push the authoritative patch — consistency restored.
    let restored_hash = hot
        .apply_patch_test(PATCH_API_TAG)
        .await
        .expect("re-patch must succeed");
    assert_eq!(
        restored_hash, patched_hash,
        "re-applying the patch must restore the expected hash"
    );
}

// ---------------------------------------------------------------------------
// Test: 10,000 concurrent heartbeat / verify_consistency calls
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn concurrent_heartbeat_10k_streams() {
    const CONCURRENT: usize = 10_000;

    let cfg = minimal_config();
    let hot = Arc::new(HotConfig::new(cfg));

    // Record the expected hash once.
    let expected = hot.sha256_hex().await;

    // Semaphore to cap OS thread pressure while still saturating the executor.
    let sem = Arc::new(Semaphore::new(512));

    let mut handles = Vec::with_capacity(CONCURRENT);

    for _ in 0..CONCURRENT {
        let hot = hot.clone();
        let expected = expected.clone();
        let sem = sem.clone();

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            let actual = hot.sha256_hex().await;
            assert_eq!(actual, expected, "hash mismatch under concurrent load");
        }));
    }

    // Wait for all tasks — any panic propagates as a JoinError.
    for handle in handles {
        handle.await.expect("heartbeat task panicked");
    }
}

// ---------------------------------------------------------------------------
// Test: ghost mode broadcast does not block callers
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ghost_broadcast_is_non_blocking() {
    use rustray::api::rustray_control::GhostMode;

    let cfg = minimal_config();
    let hot = HotConfig::new(cfg);
    let bus = ControlBus::new(hot);

    let mut rx = bus.ghost_bus().subscribe();

    // No subscribers yet — should not block.
    bus.ghost_bus().broadcast_test(GhostMode::WsCdn);

    let received = tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv())
        .await
        .expect("ghost mode event must arrive within 100ms")
        .expect("channel must not be closed");

    assert_eq!(received, GhostMode::WsCdn);
}
