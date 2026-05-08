# lanturn

A Lantern circumvention transport that mimics WebRTC TURN-relayed media
flow on plain UDP/3478 with self-hosted coturn on Lantern's
international VPS fleet.

**Status: Phase 5 (lantern-box integration skeleton)**.

Design draft v0.2:
[circumvention-corpus-private/text/2026-05-lanturn-design.md](https://github.com/getlantern/circumvention-corpus-private/blob/main/text/2026-05-lanturn-design.md)
(private repo).

Cover-protocol catalog entry:
[circumvention-protocols/text/cover-turn.md](https://github.com/getlantern/circumvention-protocols/blob/main/text/cover-turn.md)
(public repo).

## Architecture in one diagram

```
   Lantern client                              International coturn VPS
+----------------+                       +------------------------------+
| lantern-box    |                       |  coturn (real install,       |
|  + lanturn     |   UDP/3478 plain TURN |   listening 3478 + 5349)     |
|  (Go in        | <-------------------> |                              |
|   lantern-box) |   or TURNS TCP/5349   |    + Lantern egress process  |
|                |   (TLS-wrapped TURN)  |      (lanturn.Listen)        |
+----------------+                       +------------------------------+
       ▲                                                  ▲
       │                                                  │
       │ ====== inner peer DTLS-SRTP (relayed opaquely by coturn) ====== │
       │      handshake → SRTP-shaped media packets → application bytes │
```

## What's been validated, in 5 spikes

| Phase | Binary | Validates | Result |
| --- | --- | --- | --- |
| 0 | `cmd/lanturn-phase0` | Hand-rolled STUN+TURN wire format (magic cookie at offset 4, ChannelData range, FINGERPRINT, 401-NONCE-then-creds dance, OAUTH credentials) | All wire-format claims confirmed |
| 1 | `cmd/lanturn-phase1` | DTLS handshake bytes traversing TURN ChannelData; RFC 5764 SRTP key extraction; SRTP-shaped Opus packets through the relay | Handshake ~2ms; 60B keying material; 100% delivery |
| 2 | `cmd/lanturn-phase2` | covert-dtls fingerprint randomization (mimic mode = real Chrome ClientHello); session rotation (fresh cred/handshake/SSRC); pacing fidelity (jitter / DTX / RTCP-SR every 5s); coturn-fleet rotation with recency weighting | 20/20 mimic-mode handshakes; per-session DTX/active distributions match real-call ensemble |
| 3 | `cmd/lanturn-phase3` | 4 media profiles (opus / vp8-720p / vp9-720p / screen-share) with per-session selection; keyframe state machine | Distinct wire shapes per profile; first-packet keyframes work |
| 4 | `cmd/lanturn-phase4` | TURNS-on-5349 fallback (TLS-wrapped TURN over TCP); auto-fallback when UDP/3478 unreachable | UDP-works / forced-TLS / UDP-blackholed all pass |
| 5 | `pkg/lanturn` (skeleton) + `docs/INTEGRATION.md` | API surface for lantern-box import + integration plan | Skeleton compiles; integration doc complete |

## Repo layout

```
cmd/
  lanturn-phase0/main.go    hand-rolled STUN/TURN dance (validation spike)
  lanturn-phase1/main.go    DTLS-through-relay + SRTP shaping
  lanturn-phase2/main.go    covert-dtls + session rotation + pacing fidelity + fleet
  lanturn-phase3/main.go    media profiles (opus / vp8 / vp9 / screen-share)
  lanturn-phase4/main.go    TURNS-on-5349 fallback (TLS/TCP)

internal/
  stun/                     hand-rolled STUN encode/decode (used by all phases)
  turn/                     TURN allocate flow + RelayConn

pkg/
  lanturn/                  Phase-5 lantern-box-importable public API (skeleton)

docs/
  INTEGRATION.md            lantern-box wiring guide

testdata/validate.sh        tshark wire-format validation
```

## Library API (Phase 5 skeleton)

```go
import "github.com/getlantern/lanturn/pkg/lanturn"

// CLIENT side (in lantern-box outbound dialer):
conn, err := lanturn.Dial(ctx, lanturn.ClientConfig{
    CoturnEndpoints: []lanturn.CoturnEndpoint{ /* fleet from Lantern config */ },
    Credential:      lanternConfig.IssueOAuthCredFor,
    FingerprintMode: lanturn.FingerprintMimic,
    Profile:         lanturn.ProfileRandom,
    SessionDuration: 30 * time.Minute,
})
// conn is a net.Conn carrying application bytes through the full stack

// SERVER side (in Lantern egress process colocated with coturn):
listener, err := lanturn.Listen(lanturn.ServerConfig{ ListenUDP: "127.0.0.1:9999" })
for {
    conn, _ := listener.Accept()
    go handleProxyConn(conn)
}
```

The skeleton in `pkg/lanturn/lanturn.go` defines the API surface;
implementation bodies are marked `PHASE-5-TODO` and would be filled
in by porting code from `cmd/lanturn-phase{2,3,4}/main.go`.

See [`docs/INTEGRATION.md`](docs/INTEGRATION.md) for the full
lantern-box wiring guide, including:

- sing-box-style outbound type registration
- Config-service integration (credential issuance + fleet refresh)
- Per-jurisdiction transport-selection policy (Iran enabled → Russia
  experimental → China disabled in v0.1, per design §11)
- Bytes-to-media chunking (the novel design constraint for converting
  caller byte writes into SRTP-paced chunks with backpressure)

## Quick-start: end-to-end demo (Phase 4)

The most complete spike demonstration combines outer-transport
fallback with the basic relay flow. Run all three components on the
same box:

```sh
# Build
go build -o /tmp/lanturn-phase4 ./cmd/lanturn-phase4

# Terminal 1: TURN server (UDP/3478 + TLS/5349)
/tmp/lanturn-phase4 server -udp-listen 127.0.0.1:3478 \
    -tls-listen 127.0.0.1:5349 -realm lanturn.test -secret demo

# Terminal 2: egress
/tmp/lanturn-phase4 egress -listen 127.0.0.1:9999 -count 5

# Terminal 3: client — UDP works
/tmp/lanturn-phase4 client -udp-server 127.0.0.1:3478 -tls-server 127.0.0.1:5349 \
    -secret demo -peer 127.0.0.1:9999

# Terminal 3 alt: client — point at a dead UDP port to force fallback
/tmp/lanturn-phase4 client -udp-server 127.0.0.1:3477 -tls-server 127.0.0.1:5349 \
    -secret demo -peer 127.0.0.1:9999 -udp-timeout 800ms
# → falls over to TLS automatically
```

The Phase 1-3 stack (DTLS handshake + SRTP shaping + covert-dtls
fingerprint + session rotation + media profiles + fleet rotation)
runs against `cmd/lanturn-phase{1,2,3}` binaries with similar
quick-start patterns; see each binary's source for command-line
options.

## Hard rules

- **Do NOT use stock pion/dtls fingerprint for the inner client-side
  DTLS handshake in production.** The pion-default DTLS ClientHello
  has been TSPU-fingerprint-blocked since March 2026 (net4people/bbs#603,
  see [cover-dtls catalog §Censor Practice](https://github.com/getlantern/circumvention-protocols/blob/main/text/cover-dtls.md)).
  Phase 2+ uses covert-dtls mimic mode (random Chrome ClientHello
  per session); Phase 1 used the pion-default and is **for spike
  validation only, not deployment**.
- pion/turn for the **server-side** TURN protocol is fine — TSPU's
  matcher is on DTLS ClientHello, not on TURN bytes.
- pion/dtls for the **server-side** of the inner DTLS (the egress) is
  fine — DTLS-server-fingerprinting in deployed censors is less mature
  than client-fingerprinting as of 2026-05.
- WATER (WebAssembly Transport Executables Runtime) does NOT support
  UDP transports as of 2026-05; lanturn ships as Go code in
  lantern-box, not as a WATER plugin. The TURNS-on-5349 TCP fallback
  path IS WATER-compatible if cross-tool packaging becomes desirable
  for that variant later.

## Per-jurisdiction rollout (per design §11)

| Jurisdiction | v0.1 status | Why |
| --- | --- | --- |
| Iran | **enabled (rollout target #1)** | Highest international-WebRTC dependency (Bale/Soroush/Eitaa weak on video → users on Zoom/Teams/Meet/FaceTime); least sophisticated DPI; diaspora-run Jitsi/Matrix on same European VPS providers as lanturn fleet — IP-blending defense works |
| Russia | **experimental (rollout target #2)** | TSPU March 2026 pion-DTLS matcher is real but covert-dtls inner layer defeats it; faster cat-and-mouse than Iran |
| China | **disabled (rollout target #3 only after measurement)** | Most-sophisticated DPI + lowest WebRTC-collateral budget (DingTalk / Tencent Meeting / WeChat Work / Feishu, not international WebRTC) — unfavorable asymmetry; may need China-specific design pivot |
