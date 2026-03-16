#!/bin/bash
set -e

# Ensure tools are installed
if ! command -v valgrind &> /dev/null; then
    echo "valgrind could not be found"
    exit 1
fi

# Build
echo "Building Release..."
cargo build --release

# Setup
SERVER_PORT=9999
PROXY_PORT=10080
CONFIG_FILE="leak_test_config.json"

# Create Config for RustRay (Socks -> Freedom)
cat > $CONFIG_FILE <<EOF
{
  "log": { "loglevel": "none" },
  "inbounds": [{
    "port": $PROXY_PORT,
    "listen": "127.0.0.1",
    "protocol": "socks",
    "settings": { "auth": "noauth" }
  }],
  "outbounds": [{
    "protocol": "freedom"
  }]
}
EOF

# Start Sink Server (using netcat or python)
# Python is usually more reliable for simple sink across distros
python3 -c "import socket; 
s=socket.socket(); 
s.bind(('127.0.0.1', $SERVER_PORT)); 
s.listen(1); 
conn, addr = s.accept(); 
while True: 
    data = conn.recv(65536); 
    if not data: break" &
SINK_PID=$!

echo "Sink server started at $SINK_PID"

# Run RustRay
echo "Starting RustRay under Valgrind (Massif)..."
# We use massif to visualize heap usage over time to see if it returns to baseline
valgrind --tool=massif --massif-out-file=massif.out ./target/release/rustray -c $CONFIG_FILE &
PROXY_PID=$!

sleep 5

# Pump 1GB Traffic
echo "Pumping 1GB traffic..."
# Use nc with proxy support (BSD nc supports -x, ncat supports --proxy-type)
# If standard unix nc (netcat-openbsd), -x works.
# Assuming standard environment with socat or nc.
# We'll use curl through socks proxy to download a large file?
# Or just use socat:
# socat - TCP:127.0.0.1:$SERVER_PORT,proxyport=$PROXY_PORT,socks5-host=127.0.0.1
# Simplest fallback: curl
# But we need a server sending 1GB.
# Let's verify via upload.
# dd if=/dev/zero bs=1M count=1000 | curl -x socks5h://127.0.0.1:$PROXY_PORT -T - http://127.0.0.1:$SERVER_PORT/upload || true

# Actually, the python sink above just reads.
# We need to send data.
# We can use python to send data through proxy too, but that's complex.
# We'll try `nc -x`.
if command -v nc > /dev/null; then
    dd if=/dev/zero bs=1M count=1000 | nc -x 127.0.0.1:$PROXY_PORT 127.0.0.1 $SERVER_PORT
else
    echo "nc not found, skipping traffic pump"
fi

echo "Traffic done. Waiting for memory to settle..."
sleep 5

kill -TERM $PROXY_PID
wait $PROXY_PID || true
kill $SINK_PID || true

rm $CONFIG_FILE

# Output result
if [ -f massif.out ]; then
    ms_print massif.out | head -n 40
    echo "Full report in massif.out"
else
    echo "Massif output not found"
fi
