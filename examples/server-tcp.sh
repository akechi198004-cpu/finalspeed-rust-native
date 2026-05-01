#!/usr/bin/env bash
set -euo pipefail

# Starts an fspeed-rs server on TCP transport fallback.
# Use this when UDP cannot reach the server.

EXEC_PATH="${EXEC_PATH:-../target/release/fspeed-rs}"
LISTEN="${LISTEN:-0.0.0.0:15000}"
SECRET="${SECRET:-test123_secure}"
ALLOW="${ALLOW:-127.0.0.1:22}"

"$EXEC_PATH" server \
  --listen "$LISTEN" \
  --secret "$SECRET" \
  --allow "$ALLOW" \
  --transport tcp
