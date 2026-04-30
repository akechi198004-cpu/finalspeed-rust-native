#!/usr/bin/env bash
# examples/client-http.sh
#
# Description: Starts an fspeed-rs client configured for HTTP forwarding.
# This script binds the local TCP port 18080 and forwards it securely via UDP
# to the fspeed-rs server running on 198.51.100.1 (replace with your server IP),
# requesting it to connect to the server's local TCP port 8080 (a sample HTTP server).

# Note: Ensure the remote server is actually running the fspeed-rs server
# and that a Web server is active on its port 8080. Update the SERVER_IP variable below.

SERVER_IP="127.0.0.1" # Change this to your remote VPS server IP for real-world tests
EXEC_PATH="../target/release/fspeed-rs"

if [ ! -f "$EXEC_PATH" ]; then
    echo "Error: fspeed-rs binary not found. Please run 'cargo build --release' first."
    exit 1
fi

echo "Starting fspeed-rs client for HTTP mapping..."
echo "Mapping Local TCP 127.0.0.1:18080 -> UDP Tunnel -> Target Server TCP 127.0.0.1:8080"

"$EXEC_PATH" client \
    --server "${SERVER_IP}:15000" \
    --secret "test123_secure" \
    --map "127.0.0.1:18080=127.0.0.1:8080"

# To test this connection while the client is running, you would run in another terminal:
# curl http://127.0.0.1:18080
