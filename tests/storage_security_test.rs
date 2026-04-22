use rustray::app::secure_storage::SurrealProvider;
use rustray::config::Outbound;
use tempfile::tempdir;

#[tokio::test]
async fn test_secure_storage_lifecycle() {
    let dir = tempdir().expect("Failed to create temp dir");
    let db_path = dir.path().join("ray.db");
    let db_path_str = db_path.to_str().unwrap();

    // 1. Setup Master Key
    let master_key = [0xabu8; 32]; // Consistent key

    // 2. Initialize Provider
    let provider = SurrealProvider::new(db_path_str, master_key)
        .await
        .expect("Failed to init provider");

    // 3. Create Sensitive Data (Server)
    let outbound = Outbound {
        tag: "hidden-server".to_string(),
        protocol: "vless".to_string(),
        settings: None, // Simplified for test
        stream_settings: None,
        mux: None,
        proxy_settings: None,
    };

    let server_id = provider
        .save_server("Iran Direct", &outbound, None)
        .await
        .expect("Failed to save server"); // Returns String ID

    // 4. Verify Metadata Listing
    let servers = provider.list_servers().await.expect("Failed to list");
    assert_eq!(servers.len(), 1);

    // Check tuple: (id, model)
    let (_, model) = &servers[0];

    assert_eq!(model.name, "Iran Direct");
    // Verify encrypted data blob exists (Simulating "On Disk" encryption check)
    assert!(
        !model.encrypted_outbound.is_empty(),
        "Data should be encrypted"
    );

    // 5. Verify Decryption
    let retrieved = provider
        .get_server(&server_id)
        .await
        .expect("Failed to get server");
    assert_eq!(retrieved.tag, "hidden-server");

    // 6. Test Persistence (Simulate app restart)
    drop(provider); // Close connection

    let provider_reopen = SurrealProvider::new(db_path_str, master_key)
        .await
        .expect("Failed to reopen DB");

    let retrieved_reopen = provider_reopen
        .get_server(&server_id)
        .await
        .expect("Failed to get server after reopen");
    assert_eq!(retrieved_reopen.tag, "hidden-server");

    // 7. Security Test: Wrong Key (Hard Fail Expected)
    drop(provider_reopen);

    let mut wrong_key = master_key;
    wrong_key[0] = 0xff; // Flip a byte

    let provider_hacker = SurrealProvider::new(db_path_str, wrong_key)
        .await
        .expect("Failed to open DB with wrong key"); // Opening is fine, decryption should fail

    let hacker_attempt = provider_hacker.get_server(&server_id).await;
    assert!(
        hacker_attempt.is_err(),
        "Decryption MUST fail with wrong key"
    );

    println!("Security Test Passed: Data is unreadable with wrong key.");
}
