#!/usr/bin/env bash
# examples/client-ssh.sh
#
# Description: Starts an fspeed-rs client configured for SSH forwarding.
# This script binds the local TCP port 2222 and forwards it securely via UDP
# to the fspeed-rs server running on localhost:15000, requesting it to connect
# to the server's local TCP port 22 (the default SSH port).

# Note: Ensure the target server is actually running the fspeed-rs server
# and that an SSH daemon is available on its port 22.

EXEC_PATH="../target/release/fspeed-rs"

if [ ! -f "$EXEC_PATH" ]; then
    echo "Error: fspeed-rs binary not found. Please run 'cargo build --release' first."
    exit 1
fi

echo "Starting fspeed-rs client for SSH mapping..."
echo "Mapping Local TCP 127.0.0.1:2222 -> UDP Tunnel -> Target Server TCP 127.0.0.1:22"

"$EXEC_PATH" client \
    --server "127.0.0.1:15000" \
    --secret "test123_secure" \
    --map "127.0.0.1:2222=127.0.0.1:22"

# To test this connection while the client is running, you would run in another terminal:
# ssh -p 2222 <user>@127.0.0.1
