#!/usr/bin/env bash
set -euo pipefail

# Starts a client-side SOCKS5 listener and tunnels requests over UDP.
# Test with: curl --socks5-hostname 127.0.0.1:1080 http://example.com

EXEC_PATH="${EXEC_PATH:-../target/release/fspeed-rs}"
SERVER="${SERVER:-127.0.0.1:15000}"
SECRET="${SECRET:-test123_secure}"
SOCKS5="${SOCKS5:-127.0.0.1:1080}"

"$EXEC_PATH" client \
  --server "$SERVER" \
  --secret "$SECRET" \
  --socks5 "$SOCKS5" \
  --transport udp
