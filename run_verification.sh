#!/bin/bash
set -e

# Start Server in background
echo "Starting server..."
cargo run --release --bin rustray -- -c config_grpc_test.json > server.log 2>&1 &
SERVER_PID=$!
echo "Server PID: $SERVER_PID"

# Use a trap to ensure server is killed on exit
cleanup() {
  echo "Stopping server..."
  kill $SERVER_PID || true
  wait $SERVER_PID || true
}
trap cleanup EXIT

# Wait for server
echo "Waiting for server to initialize..."
sleep 30

# Run test
echo "Running smoke test..."
cargo test --test grpc_integration -- --nocapture --ignored > test.log 2>&1

echo "Test finished. Displaying logs..."
echo "=== SERVER LOG ==="
cat server.log
echo "=== TEST LOG ==="
cat test.log
