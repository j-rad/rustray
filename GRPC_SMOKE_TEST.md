# gRPC Integration Smoke Test

This guide walks you through verifying that `rustray` can communicate with `rr-ui` via gRPC.

## Quick Start

### 1. Start Server

```bash
cargo run --release --bin rustray -- -c config_grpc_test.json
```

The server should start and listen on port **10087** for gRPC.

### 2. Run Test Client

In a separate terminal:

```bash
cargo test --test grpc_integration -- --nocapture --ignored
```

### Manual Verification (Optional)

If you have `grpcurl` installed:

```bash
grpcurl -plaintext -d '{}' localhost:10087 rustray.app.proxyman.command.HandlerService/ListInbounds
```

## Expected Test Output

```
🔌 Connecting to rustray gRPC server at http://127.0.0.1:10087...
✅ Connected to HandlerService
✅ Connected to StatsService

📋 Test 1: Listing existing inbounds...
   Found 1 existing inbounds
   - api-inbound

➕ Test 2: Adding new VLESS inbound...
   ✅ Inbound added successfully

🔍 Test 3: Verifying inbound was added...
   Total inbounds now: 2
   ✅ test-vless-grpc found in inbound list

🛠️  Test 4: Altering inbound (Adding User)...
   ✅ User added successfully via AlterInbound

📊 Test 5: Querying traffic statistics...
   Found 2 stat counters
   ✅ Counters for 'test-vless-grpc' active

💻 Test 6: Getting system statistics...
   Uptime: 45 seconds
   ✅ Memory and CPU metrics reported

🗑️  Test 7: Removing test inbound...
   ✅ Inbound removed successfully

✅ All gRPC integration tests completed!
   rustray is compatible with rr-ui panel
```

## What This Tests

The integration test simulates a typical `rr-ui` workflow:

1. **Connection**: Establishes gRPC clients for HandlerService and StatsService
2. **List Inbounds**: Queries existing inbound configurations (equivalent to dashboard loading)
3. **Add Inbound**: Simulates adding a new VLESS user via the panel
4. **Alter Inbound**: Dynamically adds/removes users from an existing inbound
5. **Verify**: Confirms the inbound was added to the configuration
6. **Query Stats**: Fetches traffic statistics (for dashboard display)
7. **System Stats**: Gets uptime and system metrics
8. **Remove Inbound**: Cleans up by removing the test inbound

## Manual Testing with grpcurl

If you prefer manual testing, install `grpcurl` and try:

### List Services

```bash
grpcurl -plaintext localhost:10085 list
```

### Query All Stats

```bash
grpcurl -plaintext -d '{"pattern": ".*", "reset": false}' \
  localhost:10085 \
  rustray.app.stats.command.StatsService/QueryStats
```

### List Inbounds

```bash
grpcurl -plaintext -d '{"isOnlyTags": false}' \
  localhost:10085 \
  rustray.app.proxyman.command.HandlerService/ListInbounds
```

### Alter Inbound (Add User Example)

```bash
grpcurl -plaintext -d '{
  "tag": "manual-test",
  "operation": {
    "type": "AddUser",
    "value": "eyJlbWFpbCI6ICJ0ZXN0QGV4YW1wbGUuY29tIiwgImlkIjogIm5ldy11dWlkIn0="
  }
}' localhost:10085 \
  rustray.app.proxyman.command.HandlerService/AlterInbound
```

## Troubleshooting

### "Connection refused"

- Ensure rustray is running in another terminal
- Check that port 10085 is not blocked by firewall
- Verify config_grpc_test.json has `"port": 10085` in the `api` section

### "Proto not found" errors

- Run `cargo build` first to generate proto files via build.rs
- The generated files are in `target/release/build/rustray-*/out/`

### Test passes but rr-ui doesn't work

- Check that rr-ui is configured to connect to `http://127.0.0.1:10085`
- Ensure rr-ui's gRPC client is compatible with tonic 0.12
- Verify network connectivity between rr-ui and rustray

## Next Steps

Once the smoke test passes:

1. **Deploy**: Use rustray as the backend for rr-ui
2. **Monitor**: Check logs for gRPC requests from the panel
3. **Scale**: Implement PQC handshake for signaling security

## Known Limitations

- `get_stats_online_ip_list`: Returns placeholder empty list
- `GetSysStats`: Memory stats are calculated via `sysinfo`, but may vary by OS

These are **non-blocking** for rr-ui integration.
