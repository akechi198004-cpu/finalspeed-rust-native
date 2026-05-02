#!/usr/bin/env bash
set -euo pipefail

# Linux only, experimental fake-TCP transport.
# Requires root or CAP_NET_RAW/CAP_NET_ADMIN because fake-TCP uses Linux raw
# packet send/receive through pnet datalink/AF_PACKET. Cloud firewalls and
# security groups should allow the selected TCP port, not UDP.
# The current MVP auto-selects a usable IPv4 interface and does not support IPv6.
#
# Linux may send kernel RST packets for fake-TCP traffic. You may need to add a
# manual rule such as:
#   sudo iptables -A OUTPUT -p tcp --sport 443 --tcp-flags RST RST -j DROP
#
# This example does not run sudo and does not change firewall rules.

EXEC_PATH="${EXEC_PATH:-./target/release/fspeed-rs}"

"$EXEC_PATH" server \
  --listen "0.0.0.0:443" \
  --secret "test123" \
  --transport faketcp
