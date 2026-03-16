#!/bin/bash
set -e

# Build RustRay
cargo build --release

# Config
PORT=10005
CONFIG_FILE="memory_test_config.json"

cat > $CONFIG_FILE <<EOF
{
  "inbounds": [{
    "port": $PORT,
    "protocol": "dokodemo-door",
    "settings": {
      "address": "127.0.0.1",
      "port": 10006,
      "network": "tcp"
    }
  }],
  "outbounds": [{
    "protocol": "freedom"
  }]
}
EOF

# Start Dummy Sink
nc -l -k -p 10006 > /dev/null &
SINK_PID=$!

# Start RustRay
./target/release/rustray --config $CONFIG_FILE &
RUSTRAY_PID=$!

# Wait for startup
sleep 2

# Get Initial Memory (RSS in KB)
RSS_START=$(ps -o rss= -p $RUSTRAY_PID)
echo "Initial Memory: ${RSS_START} KB"

echo "Starting Data Pump (10GB)..."
# Using dd to nc
dd if=/dev/zero bs=1M count=10000 | nc 127.0.0.1 $PORT

# Wait for GC/cleanup
sleep 5

# Get Final Memory
RSS_END=$(ps -o rss= -p $RUSTRAY_PID)
echo "Final Memory: ${RSS_END} KB"

# Check growth
GROWTH=$((RSS_END - RSS_START))
echo "Memory Growth: ${GROWTH} KB"

# Threshold: 50MB = 51200 KB
THRESHOLD=51200

# Cleanup
kill $RUSTRAY_PID
kill $SINK_PID
rm $CONFIG_FILE

if [ "$GROWTH" -gt "$THRESHOLD" ]; then
  echo "FAILURE: Memory leak detected! Growth exceeded ${THRESHOLD} KB."
  exit 1
else
  echo "SUCCESS: Memory usage stable."
  exit 0
fi
