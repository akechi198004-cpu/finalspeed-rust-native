#!/usr/bin/env bash
# examples/server-local.sh
#
# Description: Starts an fspeed-rs server locally.
# This example listens on UDP port 15000 on all network interfaces.
# It uses 'test123_secure' as the shared secret.
# It explicitly allows clients to forward traffic to the local TCP port 22 (SSH) and 8080 (HTTP).

# Ensure you have compiled fspeed-rs with `cargo build --release` before running this.
EXEC_PATH="../target/release/fspeed-rs"

if [ ! -f "$EXEC_PATH" ]; then
    echo "Error: fspeed-rs binary not found. Please run 'cargo build --release' first."
    exit 1
fi

echo "Starting fspeed-rs server..."
echo "Listening on UDP: 0.0.0.0:15000"
echo "Allowing targets: 127.0.0.1:22, 127.0.0.1:8080"

"$EXEC_PATH" server \
    --listen "0.0.0.0:15000" \
    --secret "test123_secure" \
    --allow "127.0.0.1:22,127.0.0.1:8080"
