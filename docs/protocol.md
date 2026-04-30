# FinalSpeed RUDP Protocol Specification

This document provides a deep analysis of the custom RUDP protocol used by FinalSpeed, focusing solely on the original implementation's wire format, connection lifecycle, queuing, rate limiting, and compatibility constraints.

## 1. Complete list of message types / sType values

The message types (`sType`) define the purpose of a FinalSpeed packet. These are defined in `src/net/fs/rudp/message/MessageType.java`.

| Class Name | sType Value | Purpose | File Path |
| --- | --- | --- | --- |
| `DataMessage` | 80 | Carries payload data along with sequence number and time window. | `src/net/fs/rudp/message/DataMessage.java` |
| `AckListMessage` | 60 | Carries cumulative ACK (`lastRead`) and a selective ACK list (`ackList`), plus sender statistics for rate limit/loss calculation. | `src/net/fs/rudp/message/AckListMessage.java` |
| `PingMessage` | 301 | Initiates a ping (RTT measurement) and exchanges the peer's configured download/upload speeds. | `src/net/fs/rudp/message/PingMessage.java` |
| `PingMessage2` | 302 | Responds to a `PingMessage` to complete the RTT measurement. | `src/net/fs/rudp/message/PingMessage2.java` |
| `CloseMessage_Stream` | 75 | Signals that the data stream is closed at a specific sequence number (`closeOffset`). | `src/net/fs/rudp/message/CloseMessage_Stream.java` |
| `CloseMessage_Conn` | 76 | Forces an immediate close of the connection. | `src/net/fs/rudp/message/CloseMessage_Conn.java` |

*(Note: There are many other `sType` constants defined in `MessageType.java` (like `101`, `131`, `500`, etc.), but they appear to be unused relics or for auxiliary P2P features not part of the core data tunnel. The above 6 are the active ones used in the `Route.java` and `Receiver.java` packet processing loops).*

## 2. Common message header format

All messages share a common 12-byte header, defined conceptually in `Message.java` and serialized manually in each subclass using `ByteShortConvert` and `ByteIntConvert` (which use **Big-Endian** byte order).

| Byte Offset | Field Name | Field Size | Endian | Source File / Method |
| --- | --- | --- | --- | --- |
| 0 | `ver` | 2 bytes (short) | Big-Endian | `Message.java`, `RUDPConfig.protocal_ver` (value 0) |
| 2 | `sType` | 2 bytes (short) | Big-Endian | e.g. `DataMessage.java:47` |
| 4 | `connectId` | 4 bytes (int) | Big-Endian | e.g. `DataMessage.java:49` |
| 8 | `clientId` | 4 bytes (int) | Big-Endian | e.g. `DataMessage.java:50` |

*Note: The `clientId` field serves as a session/node identifier to look up `ClientControl`.*

## 3. DataMessage exact wire format

The `DataMessage` carries the actual stream payload.

| Offset | Field | Size | Meaning |
| --- | --- | --- | --- |
| 0 | `ver` | 2 | Protocol version (0). |
| 2 | `sType` | 2 | Message type (80). |
| 4 | `connectId` | 4 | Connection ID. |
| 8 | `clientId` | 4 | Client ID. |
| 12 | `sequence` | 4 | The packet sequence number (0, 1, 2...). |
| 16 | `length` | 2 | Length of the payload data. |
| 18 | `timeId` | 4 | Time window ID when this packet was created/sent. |
| 22 | `data` | `length` | **Payload Start Offset**. The actual data bytes. |

*(Source: `src/net/fs/rudp/message/DataMessage.java:45-56`)*

## 4. AckListMessage exact wire format

The `AckListMessage` is the most complex. It confirms received sequences and transmits rate statistics.

| Offset | Field | Size | Meaning |
| --- | --- | --- | --- |
| 0 | `ver` | 2 | Protocol version (0). |
| 2 | `sType` | 2 | Message type (60). |
| 4 | `connectId` | 4 | Connection ID. |
| 8 | `clientId` | 4 | Client ID. |
| 12 | `lastRead` | 4 | The highest continuously read sequence number (Cumulative ACK). |
| 16 | `ackList.size()` | 2 | The number of selective ACKs in the list (let's call it `N`). |
| 18 | `ackList[0]` | 4 | Selective ACK sequence 0. |
| 18+4*i | `ackList[i]` | 4 | Selective ACK sequence `i`. |
| 18+4*N | `u1` | 4 | Time ID `T-2` (where `T` is current `timeId`). |
| 22+4*N | `s1` | 4 | Bytes successfully sent by peer during `u1`. |
| 26+4*N | `u2` | 4 | Time ID `T-1`. |
| 30+4*N | `s2` | 4 | Bytes successfully sent by peer during `u2`. |
| 34+4*N | `u3` | 4 | Time ID `T` (Current). |
| 38+4*N | `s3` | 4 | Bytes successfully sent by peer during `u3`. |

*(Source: `src/net/fs/rudp/message/AckListMessage.java:32-76`. Note: there are odd hardcoded offset math like `10+4*i+8` = `18+4*i` for the list.)*

## 5. Ping / Ping2 / Close message formats

### PingMessage (sType = 301)
Used to measure RTT and declare bandwidth limits.
- `0..11`: Common Header (ver, sType, connectId, clientId)
- `12`: `pingId` (4 bytes, int) - A random ID to match the response.
- `16`: `downloadSpeed` (2 bytes, short) - Client's max download speed in KB/s.
- `18`: `uploadSpeed` (2 bytes, short) - Client's max upload speed in KB/s.
*(Source: `PingMessage.java`)*

### PingMessage2 (sType = 302)
Response to a PingMessage.
- `0..11`: Common Header
- `12`: `pingId` (4 bytes, int) - The ID from the PingMessage.
*(Source: `PingMessage2.java`)*

### CloseMessage_Conn (sType = 76)
Immediate forceful close.
- `0..11`: Common Header only.
*(Source: `CloseMessage_Conn.java`)*

### CloseMessage_Stream (sType = 75)
Graceful stream close at a specific sequence.
- `0..11`: Common Header
- `12`: `closeOffset` (4 bytes, int) - The sequence number after which the stream is considered closed.
*(Source: `CloseMessage_Stream.java`)*

## 6. Connection lifecycle

- **clientId Creation**: The `clientId` is generated based on the hash of the remote endpoint string (`IP:Port`) using `Math.abs(key.hashCode())` or assigned dynamically. It is managed by `ClientManager.java` via `ClientControl`.
- **connectId Creation**: When initiating a new connection, `Route.java` generates a random positive integer: `int connectId = Math.abs(ran.nextInt());`.
- **Connection Start**: 
  - Client side: `Route.getConnection()` creates a `ConnectionUDP` with `mode=1`.
  - Server side: When `Route` receives a packet with an unknown `connectId`, it calls `getConnection2()` (mode 2) to implicitly create a new `ConnectionUDP`.
  - There is no explicit "SYN" packet in the RUDP layer. The connection is considered established as soon as data starts flowing.
- **Connection Close**:
  - Graceful: Calling `closeStream_Local()` sends `CloseMessage_Stream`. The receiver enters `streamClose=true` when its `lastRead` reaches the `closeOffset-1`.
  - Forceful: Sending `CloseMessage_Conn` immediately destroys the connection state (`ConnectionUDP.destroy()`).
  - Timeout: Handled by `ClientManager.scanClientControl()` which checks if `lastReceivePingTime` exceeds 8 seconds.

## 7. Sender behavior

- **Sequence Number**: Starts at `0` for every new `ConnectionUDP`. It increments by 1 for **each packet** (not by bytes). (See `Sender.java:94`).
- **Send Queue**: `sendTable` (a `HashMap<Integer, DataMessage>`) stores unacknowledged packets.
- **Resend Queue**: Managed by `ResendManage.java`. When a packet is sent, it is added to a `LinkedBlockingQueue<ResendItem>`.
- **Timeout Calculation**: 
  - Dynamic base: `delayAdd = pingDelay + (pingDelay * 0.37)`.
  - Minimum delay: clamped to `RUDPConfig.reSendDelay_min` (100ms).
  - A thread loop in `ResendManage` sleeps until the deadline, then checks if the sequence is still in `sendTable`. If so, it calls `Sender.reSend()`. Max retries = 10.
- **Window Blocking**: 
  - If unacknowledged packets (`sendOffset - lastRead2`) >= `availWin` (5120), the sender calls `winOb.wait()` blocking the thread until an `AckListMessage` arrives that moves the window. (See `Sender.java:78`).

## 8. Receiver behavior

- **Out-of-order Buffer**: `receiveTable` (a `HashMap<Integer, DataMessage>`) buffers packets that arrive out of order (sequence > `lastRead`).
- **ACK Generation**: 
  - Triggered periodically via `AckListManage.java` and `AckListTask.java`.
  - Collects all missing packets and received packets to construct the selective `ackList` array and updates the `lastRead`.
- **lastRead Update**: 
  - `Receiver.receive()` loops pulling from `receiveTable.get(lastRead + 1)`. As it consumes packets in order, `lastRead` increments by 1.
- **Delivery**: 
  - The `UDPInputStream` calls `Receiver.receive()`, which blocks on `availOb.wait()` if the next in-order packet (`lastRead + 1`) is not yet available. Once available, it returns the byte array to be written to the socket.

## 9. Rate limit / timeId behavior

- **timeId Calculation**:
  - `timeId = (System.currentTimeMillis() - startSendTime) / 1000`.
  - Essentially, it represents the number of seconds since the connection started.
- **Traffic Statistics**:
  - Sent via `AckListMessage`. The receiver tracks how many bytes it received per `timeId`. It sends the stats for `T-2`, `T-1`, and `T` back to the sender.
  - The sender (`Sender.java`) logs how much it originally sent during those windows to cross-reference packet loss/throughput.
- **sendSleep Mechanism**:
  - In `ClientControl.sendSleep(startTime, length)`: After sending 10KB (`sended > 10*1024`), it calculates `needTime = 10^9 * sended / currentSpeed` (in nanoseconds).
  - If actual `usedTime` < `needTime`, it calculates the delta `sleepTime` and calls `Thread.sleep(s, n)` to artificially delay the thread, capping the transmission rate to `currentSpeed`.

## 10. Compatibility risks for Rust rewrite

- **Must be Exactly Replicated**:
  - The 12-byte header format (`ver`, `sType`, `connectId`, `clientId`).
  - Sequence number tracking (1 per packet, not per byte).
  - `DataMessage` structure (must include `timeId`).
  - `AckListMessage` structure. Even if Rust doesn't use the `timeId` statistics to throttle, it **must** serialize the `u1, s1, u2, s2, u3, s3` fields at the tail, otherwise the Java server will throw a Buffer Underflow error when parsing the packet.
  - Initial port mapping JSON payload injected as the very first data bytes: `{"dst_address":"...","dst_port":...,"password_proxy_md5":"..."}`.

- **Can be Simplified (If targeting Rust ↔ Rust only)**:
  - **`timeId` and `AckListMessage` stats**: Can be entirely stripped. Rate limiting can be handled using standard Token Bucket algorithms locally without complex cross-network time-window synchronization.
  - **PingMessage Speeds**: Speeds could be negotiated once instead of continuously sent in Pings.
  - **ResendManage Threading**: Java uses an active sleeper thread queue. Rust can elegantly handle this using `tokio::time::sleep` futures or a `DelayQueue` without the complex locking seen in the Java codebase.
  - **Fake-TCP (pcap)**: Can be ignored entirely. Rust clients and servers can just bind to standard UDP sockets.
