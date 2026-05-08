// Package lanturn is the lantern-box-importable public API for the
// lanturn TURN-as-cover circumvention transport.
//
// See the design draft at
// circumvention-corpus-private/text/2026-05-lanturn-design.md (private
// repo) for the full architectural picture. This package consolidates
// the validation-spike work in cmd/lanturn-phase{0,1,2,3,4}/ into the
// minimal API surface lantern-box needs:
//
//   - Dial: client-side. Opens a connection through a TURN relay to a
//     remote lanturn server. Returns a net.Conn whose Write/Read carry
//     application bytes through the full lanturn stack — outer plain
//     UDP/3478 (or TLS/5349 on fallback), inner DTLS-SRTP between
//     client and server, with all bytes shaped at a media-realistic
//     cadence (one of opus | vp8 | vp9 | screen profiles).
//
//   - Listen: server-side (Lantern egress). Accepts inbound lanturn
//     connections from clients via coturn's relay. Returns a
//     net.Listener whose Accept yields net.Conn for each client.
//
// API status: SKELETON. The Phase-5 first-pass exposes the right types
// and signatures so lantern-box can be wired up against this package
// in parallel with completing the implementation. Method bodies marked
// with PHASE-5-TODO either delegate to existing cmd/lanturn-phase4
// code that needs porting in, or call out cross-cutting design
// questions to resolve before production deploy.
//
// This package does NOT cover the coturn server itself (a real coturn
// install is the production backing service per design §7); it covers
// the LANTERN-WRITTEN client and egress code that ride on top of
// coturn.
package lanturn

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/pion/dtls/v3"
)

// ============================================================================
// Configuration types
// ============================================================================

// ClientConfig configures a lanturn client.
type ClientConfig struct {
	// CoturnEndpoints is the fleet of coturn instances the client may
	// allocate from. Per design §6.2, production target is 20-50 active
	// endpoints per region with recency-weighted selection. The fleet
	// is normally populated from Lantern's config service; lantern-box
	// integration code is expected to refresh this list periodically.
	//
	// Each endpoint is a CoturnEndpoint specifying the plain-UDP
	// (TURN/3478) and TURNS-TCP (TURNS/5349) addresses for that
	// instance.
	CoturnEndpoints []CoturnEndpoint

	// Credential pulls a fresh OAUTH-shaped credential pair (per
	// design §5) for the given coturn endpoint. lantern-box would
	// implement this against Lantern's config service. Returning an
	// error fails the session attempt.
	Credential func(endpoint CoturnEndpoint) (Credential, error)

	// FingerprintMode controls covert-dtls behavior on the inner DTLS
	// handshake. See design §4.4. "mimic" replays a real Chrome
	// fingerprint (recommended for production); "randomize" produces
	// per-session diversity (~85% handshake success rate, retry on
	// failure); "none" uses the pion-default fingerprint (TSPU-blocked
	// since 2026-03; do NOT deploy).
	FingerprintMode FingerprintMode

	// Profile selects the media-shape profile for the SRTP-layer
	// pacing. "" = random per session.
	Profile MediaProfile

	// SessionDuration is the target lifetime of one "call" — the
	// session is torn down and a new one opens after this. Per design
	// §6.1, production target is 25-35 minutes (uniformly distributed).
	// Default if zero: 25 min.
	SessionDuration time.Duration

	// IdleGap is the random pause between sessions. Default: 30s-5min.
	IdleGapMin, IdleGapMax time.Duration

	// UDPTimeout caps how long the client waits on UDP/3478 Allocate
	// before falling over to TURNS-on-5349. Default: 1500ms.
	UDPTimeout time.Duration

	// PreferTransport overrides the default UDP-first selection.
	// Useful for jurisdictions / network conditions known to require
	// a specific path. Empty string = auto.
	PreferTransport TransportType

	// TLSConfig controls the TURNS-TLS handshake when falling back to
	// 5349. If nil, lanturn uses uTLS-style Chrome ClientHello mimicry
	// per design §8.
	TLSConfig *tls.Config

	// DTLSConfig (advanced) overrides the inner DTLS handshake config.
	// Most callers should leave this nil — the package configures
	// covert-dtls and AES-128-CM-HMAC-SHA1-80 SRTP profile correctly
	// by default.
	DTLSConfig *dtls.Config
}

// ServerConfig configures a lanturn server (Lantern egress).
type ServerConfig struct {
	// ListenUDP is the UDP address the egress listens on for relayed
	// packets from coturn. Required.
	ListenUDP string

	// FingerprintMode controls the server-side DTLS behavior. The
	// design §4.4 anti-pion rule applies to client-side; the server
	// can use the pion default safely.
	FingerprintMode FingerprintMode

	// DTLSConfig (advanced) overrides the inner DTLS handshake config.
	DTLSConfig *dtls.Config
}

// CoturnEndpoint describes one entry in the fleet.
type CoturnEndpoint struct {
	// UDPAddr is "host:port" of the plain-TURN UDP listener (3478).
	UDPAddr string
	// TLSAddr is "host:port" of the TURNS TCP+TLS listener (5349).
	// Empty if this endpoint doesn't offer TURNS fallback.
	TLSAddr string
	// ServerName for TLS SNI / cert verification on the TURNS path.
	ServerName string
}

// Credential is an OAUTH-shaped TURN credential (per design §5,
// matching coturn's use-auth-secret / Twilio NTS pattern).
type Credential struct {
	// Username = "<unix_ts>:<id>" where unix_ts is the expiry.
	Username string
	// Password = base64(HMAC-SHA1(static_secret, username)).
	Password string
}

// FingerprintMode controls covert-dtls behavior.
type FingerprintMode string

const (
	FingerprintMimic     FingerprintMode = "mimic"
	FingerprintRandomize FingerprintMode = "randomize"
	FingerprintNone      FingerprintMode = "none" // for diagnostic A/B only
)

// MediaProfile selects the SRTP-layer media shape per design §4.5.
type MediaProfile string

const (
	ProfileOpus        MediaProfile = "opus"
	ProfileVP8         MediaProfile = "vp8"
	ProfileVP9         MediaProfile = "vp9"
	ProfileScreenShare MediaProfile = "screen"
	ProfileRandom      MediaProfile = "random"
)

// TransportType is the outer TURN transport (per design §8).
type TransportType string

const (
	TransportUDP TransportType = "udp"
	TransportTLS TransportType = "tls"
)

// ============================================================================
// Public API — Dial / Listen
// ============================================================================

// Dial opens a lanturn client connection. The returned net.Conn carries
// application bytes through the full lanturn stack:
//
//	caller bytes
//	  → SRTP-shaped chunks at the chosen profile's cadence
//	  → AES-128-CM-HMAC-SHA1-80 encryption (SRTP)
//	  → DTLS-derived keying material
//	  → TURN ChannelData wrapping
//	  → TURN allocation on a coturn instance from cfg.CoturnEndpoints
//	  → outer transport: plain UDP/3478 by default with auto-fallback
//	    to TURNS on TCP/5349 (cfg.PreferTransport overrides)
//
// Sessions automatically rotate every SessionDuration with idle gaps,
// fresh OAUTH creds, fresh DTLS handshake, fresh SRTP keys, fresh
// fingerprint, and (when fleet has >=2 endpoints) recency-rotated
// coturn endpoint. The returned Conn is the LOGICAL stream — it
// outlives individual underlying sessions seamlessly.
//
// The remote endpoint (Lantern egress) is implicit: it's whatever
// peer-IP+port the coturn endpoint forwards to. Production deployment
// has the egress colocated with coturn (per design §4.3), so the peer
// address is part of the coturn-endpoint config.
//
// Cancel ctx to tear down the connection.
//
// PHASE-5-TODO: implementation. Body should compose
// cmd/lanturn-phase4/main.go's UDP-or-TLS-fallback logic with
// cmd/lanturn-phase3/main.go's session rotation + media-profile
// streaming. The net.Conn wrapping that converts caller bytes into
// SRTP-paced chunks is the most novel piece — see
// docs/INTEGRATION.md §"Bytes-to-media chunking" for the design
// constraints (caller writes can't be returned synchronously because
// the stream emits at media cadence; needs a write-buffer of bounded
// size with backpressure).
func Dial(ctx context.Context, cfg ClientConfig) (net.Conn, error) {
	panic("lanturn.Dial not yet implemented — port from cmd/lanturn-phase4/main.go")
}

// Listen opens a lanturn server (Lantern egress) listener. Each
// Accept returns a net.Conn for one inbound client session.
//
// The egress listens for UDP packets on cfg.ListenUDP — these are the
// packets coturn's relay forwards from each client allocation. The
// server demuxes incoming packets by source UDP address (each coturn
// allocation gets a fresh source port), runs DTLS-server handshake on
// each new source, derives SRTP keys, and de-frames SRTP-shaped
// packets back into the application byte stream the caller sees on
// the returned Conn.
//
// PHASE-5-TODO: implementation. Body should port the egress code from
// cmd/lanturn-phase2/main.go (egressDemuxer, sessionConn, packetMux)
// plus the SRTP receive logic. The net.Listener wrapping that converts
// SRTP packets back into a contiguous byte stream is the inverse of
// Dial's chunking.
func Listen(cfg ServerConfig) (net.Listener, error) {
	panic("lanturn.Listen not yet implemented — port from cmd/lanturn-phase2/main.go")
}

// ============================================================================
// Internal types — exposed for Phase-5b implementation porting
// ============================================================================

// FleetSelector is the recency-weighted health-tracking endpoint
// selector from design §6.2. Made public to enable lantern-box's
// config-service integration to share the selection state across
// multiple Dial calls.
//
// PHASE-5-TODO: port from cmd/lanturn-phase2/main.go (fleetSelector).
type FleetSelector interface {
	// Pick returns the next endpoint to try, or false if the fleet is
	// empty / all unhealthy.
	Pick() (CoturnEndpoint, bool)
	// RecordSuccess marks an endpoint as having completed a session.
	RecordSuccess(addr CoturnEndpoint)
	// RecordFailure marks a session-failure on this endpoint;
	// consecFails-threshold marks unhealthy with cool-off.
	RecordFailure(addr CoturnEndpoint)
}

// MediaProfileSpec is the parameters of one media profile from
// design §4.5. Exposed for lantern-box telemetry / debug only —
// callers should normally use the MediaProfile string constants.
type MediaProfileSpec struct {
	Name           string
	PayloadType    uint8
	ClockRate      uint32
	ActivePPS      float64
	ActiveSizeMin  int
	ActiveSizeMax  int
	HasKeyframes   bool
	KeyframeMin    int
	KeyframeMax    int
	HasDTX         bool
	DTXPPS         float64
}

// Profiles returns the per-profile MediaProfileSpec for the given
// MediaProfile name (or all profiles for "random").
//
// PHASE-5-TODO: implement from cmd/lanturn-phase3/main.go's profile
// constants.
func Profiles(p MediaProfile) []MediaProfileSpec {
	panic("lanturn.Profiles not yet implemented")
}
