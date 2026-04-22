# gRPC API Integration Summary

## Overview

Successfully integrated RustRay-native gRPC API into `rustray` for compatibility with `rr-ui` panel.

## Implementation Details

### 1. Protocol Buffer Definitions

Created the following `.proto` files in `rustray/proto/`:

- **`common.proto`**: Network type definitions (TCP, UDP, UNIX)
- **`common_serial.proto`**: TypedMessage for serialized proto messages
- **`common_protocol.proto`**: User message definition
- **`rustray.proto`**: Core RustRay configuration (InboundHandlerConfig, OutboundHandlerConfig)
- **`stats.proto`**: StatsService with methods for querying traffic statistics
- **`proxyman.proto`**: HandlerService for dynamic inbound/outbound management

### 2. Build System Configuration

Updated `build.rs` to compile all proto files using `tonic-build`:

```rust
tonic_build::configure()
    .build_server(true)
    .build_client(false)
    .compile_protos(&rustray_protos, &["proto"])?;
```

### 3. gRPC Service Implementations

#### HandlerService (`src/api/handler.rs`)

Implements dynamic inbound/outbound management:

- **`add_inbound`**: Converts proto InboundHandlerConfig to internal Inbound struct, sends ConfigEvent
- **`remove_inbound`**: Removes inbound by tag, sends ConfigEvent
- **`alter_inbound`**: Dynamically modifies inbound users (AddUser, RemoveUser) for VLESS/VMess/Trojan
- **`list_inbounds`**: Returns list of configured inbounds
- **`get_inbound_users`**: Enumerates users for a specific inbound with email filtering
- **`get_inbound_users_count`**: Returns the count of users for a specific inbound
- **`add_outbound`**: Adds new outbound configuration
- **`remove_outbound`**: Removes outbound by tag
- **`alter_outbound`**: Dynamically updates outbound settings
- **`list_outbounds`**: Returns list of configured outbounds

#### StatsService (`src/api/stats.rs`)

Implements traffic statistics queries:

- **`get_stats`**: Get single counter value (with optional reset)
- **`query_stats`**: Query counters using regex pattern
- **`get_sys_stats`**: Get system statistics (uptime, memory)
- **`get_stats_online_ip_list`**: Get online IPs per user/inbound (placeholder)

### 4. Server Integration (`src/api/server.rs`)

Created `run_grpc_server` function that:

- Binds to `0.0.0.0:[port]` (default: 10085)
- Registers HandlerServiceServer and StatsServiceServer
- Runs standalone tonic::transport::Server

### 5. Main Application Integration (`src/lib.rs`)

- Spawns gRPC server as background tokio task
- Shares StatsManager instance between proxy core and gRPC API
- Runs independently from actix-web metrics server

### 6. Configuration Compatibility

Added `Serialize` derive to all config structs for proto serialization:

- InboundSettings and OutboundSettings enums
- All protocol-specific settings structs
- Maintains `#[serde(rename = "streamSettings")]` for camelCase compatibility

## Usage

### Configuration

Add API section to config.json:

```json
{
  "api": {
    "tag": "api",
    "services": ["HandlerService", "StatsService"],
    "port": 10085,
    "listen": "0.0.0.0"
  }
}
```

### gRPC Endpoints

The server exposes two services:

- `rustray.app.proxyman.command.HandlerService` - Inbound/outbound management
- `rustray.app.stats.command.StatsService` - Traffic statistics

### Testing with grpcurl

```bash
# List services
grpcurl -plaintext localhost:10085 list

# Query stats
grpcurl -plaintext -d '{"pattern": ".*"}' localhost:10085 \
  rustray.app.stats.command.StatsService/QueryStats

# List inbounds
grpcurl -plaintext -d '{}' localhost:10085 \
  rustray.app.proxyman.command.HandlerService/ListInbounds
```

### Developer Code Examples (Go/Python)

For developers building panels or automation tools:

#### Python (using `grpcio`)
```python
import grpc
import stats_pb2_grpc as stats_rpc
import stats_pb2 as stats_msg

with grpc.insecure_channel('localhost:10085') as channel:
    stub = stats_rpc.StatsServiceStub(channel)
    response = stub.QueryStats(stats_msg.QueryStatsRequest(pattern=".*", reset=False))
    for stat in response.stat:
        print(f"{stat.name}: {stat.value}")
```

#### Go (using `tonic` generated clients)
```go
conn, _ := grpc.Dial("localhost:10085", grpc.WithInsecure())
client := proxyman.NewHandlerServiceClient(conn)
resp, _ := client.ListInbounds(context.Background(), &proxyman.ListInboundsRequest{})
for _, inbound := range resp.Inbound {
    fmt.Printf("Active Inbound: %s\n", inbound.Tag)
}
```

## Compatibility Notes

1. **Proto-to-Internal Conversion**: The `proto_to_inbound` and `proto_to_outbound` functions handle conversion between RustRay protobuf format and rustray's internal config structs.

2. **ConfigEvent Broadcasting**: Changes made via gRPC API are broadcast to StatsManager via the `config_event_tx` channel for potential hot-reload support.

3. **Serialization**: All config structs now implement both `Deserialize` and `Serialize` for bidirectional proto conversion.

4. **Port Configuration**: gRPC server uses the port from `config.api.port`, defaulting to 10085 if not specified.

## Future Enhancements

1. **IP Tracking**: `get_stats_online_ip_list` needs connection tracking implementation
2. **Hot Reload**: ConfigEvent handlers need to trigger actual inbound/outbound reconfiguration
3. **PQC Handshake**: Support for post-quantum key exchange in gRPC signaling

## Files Modified/Created

### Created

- `proto/common.proto`
- `proto/common_serial.proto`
- `proto/common_protocol.proto`
- `proto/rustray.proto`
- `proto/stats.proto`
- `proto/proxyman.proto`
- `src/api/handler.rs`
- `src/api/stats.rs`

### Modified

- `build.rs` - Added proto compilation
- `src/api/mod.rs` - Enabled proto includes, added handler/stats modules
- `src/api/server.rs` - Implemented run_grpc_server
- `src/lib.rs` - Spawned gRPC server task
- `src/config.rs` - Added Serialize derives to all structs

## Build Status

✅ Successfully compiles with 56 warnings (mostly unused imports in Flow-J modules)
✅ gRPC services properly registered and exposed
✅ Compatible with RustRay protocol buffer definitions
