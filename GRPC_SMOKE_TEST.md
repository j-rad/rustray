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

📊 Test 4: Querying traffic statistics...
   Found 0 stat counters
   ℹ️  No traffic stats yet (expected for fresh start)

💻 Test 5: Getting system statistics...
   Uptime: 15 seconds
   ℹ️  Memory stats are placeholder (rr-ui uses its own sysinfo)

🗑️  Test 6: Removing test inbound...
   ✅ Inbound removed successfully

✅ All gRPC integration tests completed!
   rustray is compatible with rr-ui panel
```

## What This Tests

The integration test simulates a typical `rr-ui` workflow:

1. **Connection**: Establishes gRPC clients for HandlerService and StatsService
2. **List Inbounds**: Queries existing inbound configurations (equivalent to dashboard loading)
3. **Add Inbound**: Simulates adding a new VLESS user via the panel
4. **Verify**: Confirms the inbound was added to the configuration
5. **Query Stats**: Fetches traffic statistics (for dashboard display)
6. **System Stats**: Gets uptime and system metrics
7. **Remove Inbound**: Cleans up by removing the test inbound

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

### Add Inbound (Complex Example)

```bash
grpcurl -plaintext -d '{
  "inbound": {
    "tag": "manual-test",
    "receiverSettings": {
      "type": "rustray.proxy.vless.Receiver",
      "value": "eyJwb3J0IjogMTIzNDV9"
    },
    "proxySettings": {
      "type": "rustray.proxy.vless.Inbound",
      "value": "eyJjbGllbnRzIjogW3siaWQiOiAidGVzdCJ9XX0="
    }
  }
}' localhost:10085 \
  rustray.app.proxyman.command.HandlerService/AddInbound
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
3. **Iterate**: Implement missing methods (AlterInbound) as needed

## Known Limitations

- `AlterInbound`/`AlterOutbound`: Returns "Unimplemented" (rr-ui uses delete+add pattern)
- `GetSysStats`: Returns placeholder memory stats (rr-ui has its own sysinfo)
- `GetInboundUsers`: Needs user enumeration logic

These are **non-blocking** for rr-ui integration.
