# alpha50 transport investigation

Base: aafba9affd7a940d0127aa83870a9248b9040547 (alpha49).

## Evidence and limits

The reported alpha49 failure is a TCP connect timeout below MITM, including
SAFE_DIRECT DoH. The supplied STATUS does not show per-flow packet stages.
128 concurrent TCP echo connections pass against a second gVisor stack through
both a plain socketpair and real loopback WG and AWG encryption, on alpha49 as
well as this change. **The mass failure on the user's device is not reproduced
and is not claimed fixed.** This build repairs specific ownership/cleanup defects
and supplies the missing failure-localization evidence.

Changes alpha45–49: DoH/DoT 2.5-second deadline; TCP retry; selective QUIC and
its reversal; larger outer UDP buffers. None establishes where a failed SYN is
lost. These policies and all filtering/CA/cosmetic/Yandex files are unchanged.

## Confirmed defects repaired

* Upstream deliberately used a blocking socket fd because it confused a dup of
  the Java-side endpoint with the **opposite** engine-side socketpair endpoint.
  Closing a blocking Go os.File does not interrupt an in-flight syscall read.
  The replacement makes only the upstream side pollable, closes its socket and
  channel, and joins both I/O loops before installing a replacement session.
  The test verifies the engine-side fd flags are unchanged.
* Pinned gonet.DialTCPWithBind allocates an endpoint and returns without Close
  for an already-cancelled context and Bind failure. The tracked dial owns the
  endpoint on every exit, closes failed endpoints before returning, and preserves
  normal TCPConn half-close methods. Normal in-flight gonet timeout cleanup was
  already present; it is not misrepresented as a newly found leak.
* An MTU-sized SOCK_SEQPACKET read silently discards the remainder of an oversized
  inbound packet. Read a complete IP packet into a reusable scratch buffer, then
  copy only its actual bytes into gVisor-owned storage. This is not proof that
  the reported (small) SYN-ACK packets were oversized.

## Diagnostics

`wgUpstreamStats` includes tcpDialStarted, synTx, synAckRx, connectOk,
connectTimeout, endpointClosed, activeEndpoints, packetRxDropped,
packetTxDropped, outer RX/TX/errors, I/O loop state, registered/cleanup endpoints,
and gVisor TCP checksum/invalid-segment counts. activeEndpoints counts owned TCP
handles, while registered/cleanup endpoint counts expose gVisor's own lifecycle.
Eight failed handshakes are retained independently of the busy general flow log.
No packet payload, credentials, keys, or certificates are logged.

A failed handshake records DIAL_START, SYN_TX (gVisor submitted to link queue),
PACKET_SOCKET_TX (successful socket write), PACKET_TO_WG (engine read),
PACKET_FROM_WG (decrypted matching SYN-ACK at engine TUN write), SYNACK_RX
(upstream socket read), GVISOR_DELIVER (network-dispatch handoff). CONNECT_OK
is counted without adding a success log. Queue/write drops are counted.
Missing stages remain missing; they are never synthesized.

Correlate inner packets by local/remote IP+port and SYN sequence / SYN-ACK
acknowledgment; stale responses cannot match a new sequence on a reused port.
Outer encrypted datagrams cannot be attributed to one TCP flow at the bind
boundary: WG_OUTER_TX/RX deltas explicitly say `session_not_flow`. An outer RX
increment alone does **not** prove that a SYN-ACK arrived. GVISOR_DELIVER means
handoff, not successful TCP validation; use connectOk and TCP error counts too.

## Comparison with Config VPN 5.1.3

Read-only reference: Config_dns tag v5.1.3. It uses Android WG GoBackend
1.0.20260102 / AWG Android 2.3.7 directly on the Android TUN. Kernel TCP creates
and owns application TCP endpoints. Project 4 adds an application gVisor stack,
a separate upstream gVisor stack and a SOCK_SEQPACKET bridge to the userspace
engine, so its extra endpoint/queue/fd ownership is not exercised by the stable
app. The stable app emits MTU only when configured; unified uses its configured
MTU (typically 1280). No MTU/routing/WG settings were changed here. The packet
engine protects outer sockets before Up; packetTun is pollable and writes
synchronously before the engine releases its packet buffers. Upstream packets
have independent buffer lifetime. Original Config VPN was not modified.

## Validation

* go test ./...: PASS.
* go test -race ./...: PASS. Old packetvpn tests previously reconfigured a live
  device and raced inside the dependency; they now bring it down while setting
  peers, keep its selected port, then bring it back up, matching production's
  configure-before-Up ordering.
* 128 concurrent TCP echo dials each over socketpair, encrypted WG, encrypted
  AWG: PASS. Linux test bind lacks Android's protect-fd interface; protection is
  covered separately by packetvpn tests. This does not substitute for Android
  networking/device validation.
* Silent-peer deadlines, 32 failed endpoint cleanups, cancelled-before-allocation,
  idle shutdown, stale SYN-ACK rejection: PASS.
* Android SDK is unavailable in the local workspace; Android AAR/APK validation
  must run in the existing GitHub Actions workflow after push.
