#!/usr/bin/env bash
set -euo pipefail

# Starts an fspeed-rs server on UDP transport.
# Allows clients to request only the server-local SSH target.

EXEC_PATH="${EXEC_PATH:-../target/release/fspeed-rs}"
LISTEN="${LISTEN:-0.0.0.0:15000}"
SECRET="${SECRET:-test123_secure}"
ALLOW="${ALLOW:-127.0.0.1:22}"

"$EXEC_PATH" server \
  --listen "$LISTEN" \
  --secret "$SECRET" \
  --allow "$ALLOW" \
  --transport udp
