# lantern-box integration guide

This document describes how `getlantern/lantern-box` (the open-source
sing-box-compatible Lantern proxy) integrates the `lanturn` transport
once the `pkg/lanturn` library is filled in (currently a Phase-5
skeleton).

## Where lanturn fits in lantern-box's protocol family

lantern-box already supports several Lantern-written transports as
sing-box outbound types:

- **samizdat** — uTLS Chrome ClientHello + HTTP/2 to a real cover-site SNI
- **reflex** — TLS handshake role reversal
- **tlsmasq** — TLS-fingerprint mimicry on a custom path
- **unbounded** — WebRTC DataChannel via pion-webrtc + covert-dtls

**lanturn** slots in alongside these as a new outbound type. Its
distinguishing properties (per design §11):

| | samizdat | reflex | tlsmasq | unbounded | **lanturn** |
| --- | --- | --- | --- | --- | --- |
| Outer wire | TLS @ byte 0 | TLS @ byte 0 | TLS @ byte 0 | DTLS-SRTP / WebRTC | **plain TURN @ UDP/3478** |
| Mimics | HTTPS | HTTPS | HTTPS | WebRTC P2P | **WebRTC-via-TURN-relay** |
| Wire-distinct from TLS-at-byte-0? | no | no | no | yes (DTLS shape) | **yes (STUN magic cookie + ChannelData range)** |
| Backing service | real CDN sites | self-hosted | self-hosted | n/a (P2P) | **self-hosted coturn** |
| TSPU-resistant inner DTLS? | n/a | n/a | n/a | yes (covert-dtls) | **yes (covert-dtls reuse)** |
| Recommended jurisdictions | global | global | global | global | **Iran first; Russia ok; China only after measurement** (per §11) |

## API surface

The `pkg/lanturn` package exposes a Dial / Listen pair:

```go
import "github.com/getlantern/lanturn/pkg/lanturn"

// CLIENT side (in lantern-box's outbound dialer):
conn, err := lanturn.Dial(ctx, lanturn.ClientConfig{
    CoturnEndpoints: []lanturn.CoturnEndpoint{
        {UDPAddr: "vps-de-1.example.com:3478", TLSAddr: "vps-de-1.example.com:5349", ServerName: "vps-de-1.example.com"},
        {UDPAddr: "vps-de-2.example.com:3478", TLSAddr: "vps-de-2.example.com:5349", ServerName: "vps-de-2.example.com"},
        // ... 20-50 endpoints from Lantern config service
    },
    Credential: func(ep lanturn.CoturnEndpoint) (lanturn.Credential, error) {
        return lantern_config.IssueOAuthCredFor(ep.UDPAddr)
    },
    FingerprintMode: lanturn.FingerprintMimic,
    Profile:         lanturn.ProfileRandom,
    SessionDuration: 30 * time.Minute,
    IdleGapMin:      30 * time.Second,
    IdleGapMax:      5 * time.Minute,
})
// conn is a net.Conn; bytes you Write traverse the full stack

// SERVER side (in the Lantern egress process colocated with coturn):
listener, err := lanturn.Listen(lanturn.ServerConfig{
    ListenUDP: "127.0.0.1:9999",
})
for {
    conn, err := listener.Accept()
    if err != nil { ... }
    go handleProxyConn(conn) // bytes are application-layer Lantern bytes
}
```

## Wiring in lantern-box

### sing-box-style outbound type registration

lantern-box's outbound mux (in `lantern-box/outbound/lanturn/`) would
register a new outbound type:

```go
type lanturnOutbound struct {
    config lanturn.ClientConfig
    fleet  lanturn.FleetSelector // shared across dials
}

func (o *lanturnOutbound) DialContext(ctx context.Context, network string, dest M.Socksaddr) (net.Conn, error) {
    // For TCP dest: open lanturn conn, bridge bytes
    underlying, err := lanturn.Dial(ctx, o.config)
    if err != nil { return nil, err }
    return underlying, nil
}
```

The Lantern egress side of the deployment ships a small Go binary
(separate from lantern-box) that runs `lanturn.Listen` + a sing-box-
direct outbound to the public Internet — i.e. the egress acts as a
transparent SOCKS-like proxy receiving bytes from lanturn clients
and forwarding them onward.

### Config-service integration

The `Credential` callback is the integration seam with Lantern's
existing config-service plumbing:

```go
func (c *LanternConfig) IssueOAuthCredFor(coturnAddr string) (lanturn.Credential, error) {
    // 1. Look up the static-auth-secret for this coturn instance from
    //    the rotated-secrets table the config service maintains.
    // 2. Generate USERNAME = "<unix_expiry>:<random_id>"
    // 3. Generate PASSWORD = base64(HMAC-SHA1(secret, username))
    // 4. Return.
    secret := c.coturnSecrets[coturnAddr]
    expiry := time.Now().Add(30 * time.Second).Unix()
    username := fmt.Sprintf("%d:lanturn-%s", expiry, randID())
    mac := hmac.New(sha1.New, []byte(secret))
    mac.Write([]byte(username))
    password := base64.StdEncoding.EncodeToString(mac.Sum(nil))
    return lanturn.Credential{Username: username, Password: password}, nil
}
```

Coturn-fleet membership comes from Lantern's existing config service
too:

```go
func (c *LanternConfig) RefreshLanturnFleet(ctx context.Context) ([]lanturn.CoturnEndpoint, error) {
    var fleet []lanturn.CoturnEndpoint
    for _, ep := range c.activeCoturnEndpoints() {
        fleet = append(fleet, lanturn.CoturnEndpoint{
            UDPAddr:    fmt.Sprintf("%s:3478", ep.Hostname),
            TLSAddr:    fmt.Sprintf("%s:5349", ep.Hostname),
            ServerName: ep.Hostname,
        })
    }
    return fleet, nil
}
```

### Transport-selection policy (per design §11.4)

Per the design's per-jurisdiction effectiveness assessment, lantern-
box's transport-selection logic should default lanturn:

- **Enabled by default** for Iran-routed sessions (best WebRTC-
  collateral story, weakest DPI of the three priority markets)
- **Experimental** for Russia (TSPU pion-DTLS matcher exists but
  covert-dtls inner layer defeats it; faster cat-and-mouse than Iran)
- **Disabled** for China in v0.1 (lower WebRTC-collateral budget +
  more sophisticated DPI = unfavorable; needs measurement-driven
  confidence first or a China-specific pivot)

Encoded in lantern-box as a per-region transport-selection policy:

```go
case "IR":
    transports = append(transports, lanturnTransport)  // primary
case "RU":
    if c.ExperimentalEnabled { transports = append(transports, lanturnTransport) }
case "CN":
    // skip lanturn for v0.1
}
```

## Bytes-to-media chunking (the novel design constraint)

The most subtle part of the lanturn integration: caller bytes flow
through `conn.Write(p)` immediately, but the wire emits at media
cadence (e.g. Opus 50pps with 110-170B payloads = ~64kbps maximum
throughput). The library must:

1. Buffer caller bytes in a bounded write-buffer
2. Drain into SRTP-shaped chunks at the profile's pacing
3. Apply backpressure: `conn.Write` blocks when the buffer is full
4. On the receive side: reassemble SRTP payloads back into a
   contiguous byte stream

For high-throughput proxy traffic, lantern-box should pick the video
profiles (vp8: ~1Mbps, vp9: ~2Mbps, screen-share: lower but bursty).
The default `ProfileRandom` is good for *aggregate* fleet diversity
(different sessions look different) but mixed-throughput workloads
may benefit from explicit profile selection per connection.

PHASE-5-TODO: a streaming-chunker implementation in `pkg/lanturn`.
This is the most non-trivial part of completing the library; the
spike's cmd/lanturn-phase{1,2,3}/ programs sent random bytes, not
caller-supplied data.

## What lantern-box does NOT need to deploy

- coturn itself: that's a separate operational deployment, not a Go
  dependency. coturn binaries already exist on Lantern's international
  VPS fleet; the Lantern-side code is just the egress process
  (calling `lanturn.Listen`) running alongside coturn on the same
  box (per design §4.3).
- lanturn config service plumbing: this is the *same* config service
  Lantern already runs (the one that distributes proxy lists, AMP
  tokens, etc.). Adding coturn-fleet endpoints + per-instance
  static-auth-secrets to that service is a config-schema addition,
  not a new service.

## Migration / rollout

Per design §11.4 + §11.4 cross-cutting #5:

1. **Phase 5a (this skeleton)** — `pkg/lanturn` API contract; tests
   stubbed.
2. **Phase 5b** — fill in `pkg/lanturn` implementation by porting code
   from `cmd/lanturn-phase{2,3,4}/main.go`. Add streaming-chunker.
   E2E test against a local coturn instance.
3. **Phase 5c** — wire into lantern-box outbound; ship `lantern-box`
   release with lanturn behind a feature flag.
4. **Phase 5d** — deploy first egress instance on a Lantern Hetzner
   VPS alongside an existing coturn install. Add to config-service
   fleet table.
5. **Phase 5e** — Iran rollout: enable lanturn for Iran-routed
   lantern-box clients via remote config. Measure: session-success
   rate, throughput, DTLS-handshake success rate, fallback-to-TLS
   rate.
6. **Phase 5f** — Russia rollout if Iran metrics are healthy.
7. **Phase 5g** — China only after measurement-driven confidence
   from Iran + Russia, or a China-specific design pivot.

Per design §11 cross-cutting #6 (volume sensitivity is jurisdiction-
dependent), instrumentation requirements are tighter for China than
for Iran — the rollout plan above reflects this.
