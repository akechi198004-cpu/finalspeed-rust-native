$ErrorActionPreference = "Stop"

# Starts a client-side SOCKS5 listener and tunnels requests over TCP fallback.
# Server must also be started with --transport tcp.

$ExecPath = if ($env:EXEC_PATH) { $env:EXEC_PATH } else { "..\target\release\fspeed-rs.exe" }
$Server = if ($env:SERVER) { $env:SERVER } else { "127.0.0.1:15000" }
$Secret = if ($env:SECRET) { $env:SECRET } else { "test123_secure" }
$Socks5 = if ($env:SOCKS5) { $env:SOCKS5 } else { "127.0.0.1:1080" }

& $ExecPath client `
  --server $Server `
  --secret $Secret `
  --socks5 $Socks5 `
  --transport tcp
