#!/usr/bin/env bash
set -euo pipefail

# Maps local 127.0.0.1:2222 to the server-side 127.0.0.1:22 target over TCP fallback.
# Server must also be started with --transport tcp.

EXEC_PATH="${EXEC_PATH:-../target/release/fspeed-rs}"
SERVER="${SERVER:-127.0.0.1:15000}"
SECRET="${SECRET:-test123_secure}"
MAP="${MAP:-127.0.0.1:2222=127.0.0.1:22}"

"$EXEC_PATH" client \
  --server "$SERVER" \
  --secret "$SECRET" \
  --map "$MAP" \
  --transport tcp
