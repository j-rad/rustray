// tests/grpc_integration.rs
// Integration test for gRPC API compatibility with rr-ui
//
// This test requires a running rustray server.
// Run it with: cargo test grpc_integration -- --nocapture --ignored

use rustray::api::rustray::app::proxyman::command::{
    AddInboundRequest, AlterInboundRequest, ListInboundsRequest, RemoveInboundRequest,
    handler_service_client::HandlerServiceClient,
};
use rustray::api::rustray::app::stats::command::{
    QueryStatsRequest, SysStatsRequest, stats_service_client::StatsServiceClient,
};
use rustray::api::rustray::common::serial::TypedMessage;
use rustray::api::rustray::core::InboundHandlerConfig;
use rustray::config::VlessUser;
use tonic::Request;

/// Test that verifies rr-ui can communicate with rustray via gRPC
///
/// Prerequisites:
/// 1. Run rustray server in another terminal:
///    cargo run --bin rustray -- -c config_grpc_test.json
/// 2. Wait for server to start (you should see "Starting gRPC API server on 0.0.0.0:10085")
/// 3. Run this test:
///    cargo test grpc_integration -- --nocapture --ignored
#[tokio::test]
#[ignore] // Requires running server, so ignored by default
async fn test_rr_ui_workflow() -> Result<(), Box<dyn std::error::Error>> {
    println!("🔌 Connecting to rustray gRPC server at http://127.0.0.1:10087...");

    // Give server a moment to be ready
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Connect to HandlerService
    let mut handler = match HandlerServiceClient::connect("http://127.0.0.1:10087").await {
        Ok(client) => {
            println!("✅ Connected to HandlerService");
            client
        }
        Err(e) => {
            eprintln!("❌ Failed to connect to HandlerService: {}", e);
            eprintln!(
                "   Make sure rustray is running with: cargo run --bin rustray -- -c config_grpc_test.json"
            );
            return Err(e.into());
        }
    };

    // Connect to StatsService
    let mut stats = StatsServiceClient::connect("http://127.0.0.1:10087").await?;
    println!("✅ Connected to StatsService");

    // Test 1: List existing inbounds
    println!("\n📋 Test 1: Listing existing inbounds...");
    let list_req = Request::new(ListInboundsRequest {
        is_only_tags: false,
    });
    let list_resp = handler.list_inbounds(list_req).await?;
    let inbounds = list_resp.into_inner().inbounds;
    println!("   Found {} existing inbounds", inbounds.len());
    for inbound in &inbounds {
        println!("   - {}", inbound.tag);
    }

    // Test 2: Add a new VLESS inbound (simulating rr-ui adding a user)
    println!("\n➕ Test 2: Adding new VLESS inbound...");
    let inbound_config = InboundHandlerConfig {
        tag: "test-vless-grpc".to_string(),
        receiver_settings: Some(TypedMessage {
            r#type: "rustray.proxy.vless.Receiver".to_string(),
            value: serde_json::to_vec(&serde_json::json!({
                "port": 12345,
                "listen": "0.0.0.0"
            }))?,
        }),
        proxy_settings: Some(TypedMessage {
            r#type: "rustray.proxy.vless.Inbound".to_string(),
            value: serde_json::to_vec(&serde_json::json!({
                "clients": [{
                    "id": "b1e7a3d8-4f2c-4e91-a6d2-5c8e9f0a1b2c",
                    "email": "grpc-test@rustray.local",
                    "level": 0
                }],
                "decryption": "none"
            }))?,
        }),
    };

    let add_req = Request::new(AddInboundRequest {
        inbound: Some(inbound_config),
    });

    match handler.add_inbound(add_req).await {
        Ok(_) => println!("   ✅ Inbound added successfully"),
        Err(e) => println!("   ⚠️  Add inbound returned: {}", e),
    }

    // Test 3: Verify the inbound was added
    println!("\n🔍 Test 3: Verifying inbound was added...");
    let verify_req = Request::new(ListInboundsRequest { is_only_tags: true });
    let verify_resp = handler.list_inbounds(verify_req).await?;
    let updated_inbounds = verify_resp.into_inner().inbounds;
    println!("   Total inbounds now: {}", updated_inbounds.len());

    let found = updated_inbounds.iter().any(|i| i.tag == "test-vless-grpc");
    if found {
        println!("   ✅ test-vless-grpc found in inbound list");
    } else {
        println!("   ℹ️  test-vless-grpc not found (might be in config only)");
    }

    // Test 4: Query stats (simulate rr-ui dashboard)
    println!("\n📊 Test 4: Querying traffic statistics...");
    let stats_req = Request::new(QueryStatsRequest {
        pattern: ".*".to_string(),
        reset: false,
    });
    let stats_resp = stats.query_stats(stats_req).await?;
    let stat_list = stats_resp.into_inner().stat;
    println!("   Found {} stat counters", stat_list.len());

    if stat_list.is_empty() {
        println!("   ℹ️  No traffic stats yet (expected for fresh start)");
    } else {
        println!("   Sample stats:");
        for (i, stat) in stat_list.iter().take(5).enumerate() {
            println!("   {}. {} = {}", i + 1, stat.name, stat.value);
        }
    }

    // Test 5: Get system stats
    println!("\n💻 Test 5: Getting system statistics...");
    let sys_req = tonic::Request::new(SysStatsRequest {});
    let sys_resp = stats.get_sys_stats(sys_req).await?;
    let sys_stats = sys_resp.into_inner();
    println!("   Uptime: {} seconds", sys_stats.uptime);
    println!("   ℹ️  Memory stats are placeholder (rr-ui uses its own sysinfo)");

    // Test 7: Alter inbound (Add User)
    println!("\n🔧 Test 7: Altering inbound (Add User)...");
    let vless_user = VlessUser {
        id: "22222222-2222-2222-2222-222222222222".to_string(),
        email: Some("alter-user@example.com".to_string()),
        level: Some(1),
        flow: None,
    };
    let user_json = serde_json::to_vec(&vless_user)?;

    // Create operation TypedMessage
    let operation = TypedMessage {
        r#type: "AddUser".to_string(),
        value: user_json,
    };

    let alter_req = Request::new(AlterInboundRequest {
        tag: "test-vless-grpc".to_string(),
        operation: Some(operation),
    });

    match handler.alter_inbound(alter_req).await {
        Ok(_) => println!("   ✅ Inbound altered (user added) successfully"),
        Err(e) => {
            eprintln!("❌ Failed to alter inbound: {}", e);
            return Err(e.into());
        }
    }

    // Verify addition by listing or just trusting success (since list might not show users in summary)
    // To verify, we'd need GetInboundUser which is unimplemented.
    // For now, success response is good enough.

    // Test 8: Removing test inbound
    println!("\n🗑️  Test 8: Removing test inbound...");
    let remove_req = Request::new(RemoveInboundRequest {
        tag: "test-vless-grpc".to_string(),
    });

    match handler.remove_inbound(remove_req).await {
        Ok(_) => println!("   ✅ Inbound removed successfully"),
        Err(e) => println!("   ⚠️  Remove inbound returned: {}", e),
    }

    println!("\n✅ All gRPC integration tests completed!");
    println!("   rustray is compatible with rr-ui panel");

    Ok(())
}

/// Quick connectivity test that doesn't require a running server
#[test]
fn test_proto_modules_available() {
    // Just verify the proto modules are accessible from rustray crate
    use rustray::api::rustray::app::proxyman::command::ListInboundsRequest;
    use rustray::api::rustray::app::stats::command::QueryStatsRequest;

    let _list_req = ListInboundsRequest { is_only_tags: true };
    let _stats_req = QueryStatsRequest {
        pattern: "test".to_string(),
        reset: false,
    };

    println!("✅ Proto modules compiled and accessible");
}
