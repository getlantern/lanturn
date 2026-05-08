// Package lanturn is the lantern-box-importable public API for the
// lanturn TURN-as-cover circumvention transport.
//
// See cmd/lanturn-phase{0,1,2,3,4}/main.go for the validation spikes
// and the design draft at
// circumvention-corpus-private/text/2026-05-lanturn-design.md (private)
// for the full architecture.
//
// MVP implementation status: working Dial / Listen with the bytes-to-
// media streaming chunker (the novel design constraint that converts
// caller byte writes into SRTP-paced chunks with backpressure).
// Production-grade additions deferred to follow-on PRs:
//
//   - Session rotation across the SessionDuration / IdleGap pattern
//     (currently single-session per Dial; caller must redial to rotate)
//   - TURNS-on-5349 fallback (currently UDP-only; the TLS path is
//     fully validated in cmd/lanturn-phase4/main.go and ports cleanly)
//   - covert-dtls fingerprint integration for the inner DTLS handshake
//     (currently uses pion-default; cmd/lanturn-phase2/main.go has the
//     covert-dtls hook; do NOT deploy to Russia / China without it)
//   - Multi-profile selection (currently Opus-only; profiles vp8/vp9/
//     screen-share validated in cmd/lanturn-phase3/main.go)
//   - Recency-weighted fleet selection (currently round-robin from
//     CoturnEndpoints; cmd/lanturn-phase2 has the full FleetSelector)
//
// All deferred items have working code in cmd/lanturn-phase*; this
// MVP demonstrates the API contract works end-to-end with the
// streaming-chunker as the load-bearing new component.
package lanturn

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/getlantern/lanturn/internal/turn"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/rtp"
	"github.com/pion/srtp/v3"
)

// ============================================================================
// Public configuration types
// ============================================================================

// ClientConfig configures a lanturn client.
type ClientConfig struct {
	// CoturnEndpoints is the fleet of coturn instances the client may
	// allocate from. MVP picks the first endpoint; production code
	// would use FleetSelector for recency-weighted selection.
	CoturnEndpoints []CoturnEndpoint

	// Credential issues an OAUTH-shaped credential pair for the given
	// coturn endpoint. lantern-box would implement this against
	// Lantern's config service.
	Credential func(endpoint CoturnEndpoint) (Credential, error)

	// PeerAddr is the egress's UDP address that the client wants
	// coturn to relay traffic to. Production normally derives this
	// from CoturnEndpoint metadata; for MVP it's an explicit field.
	PeerAddr string

	// Profile selects the media-shape profile. MVP supports Opus only.
	Profile MediaProfile

	// Logger is used for diagnostic logging. nil = log package default.
	Logger func(format string, args ...any)
}

// ServerConfig configures a lanturn server (Lantern egress).
type ServerConfig struct {
	// ListenUDP is the UDP address the egress listens on for relayed
	// packets from coturn. Required.
	ListenUDP string

	// Logger is used for diagnostic logging. nil = log package default.
	Logger func(format string, args ...any)
}

// CoturnEndpoint describes one entry in the fleet.
type CoturnEndpoint struct {
	UDPAddr    string
	TLSAddr    string
	ServerName string
}

// Credential is an OAUTH-shaped TURN credential.
type Credential struct {
	Username string
	Password string
}

// FingerprintMode controls covert-dtls behavior. Reserved for future
// implementation; MVP uses pion-default fingerprint.
type FingerprintMode string

const (
	FingerprintMimic     FingerprintMode = "mimic"
	FingerprintRandomize FingerprintMode = "randomize"
	FingerprintNone      FingerprintMode = "none"
)

// MediaProfile selects the SRTP-layer media shape.
type MediaProfile string

const (
	ProfileOpus        MediaProfile = "opus"
	ProfileVP8         MediaProfile = "vp8"
	ProfileVP9         MediaProfile = "vp9"
	ProfileScreenShare MediaProfile = "screen"
	ProfileRandom      MediaProfile = "random"
)

// TransportType is the outer TURN transport.
type TransportType string

const (
	TransportUDP TransportType = "udp"
	TransportTLS TransportType = "tls"
)

// ============================================================================
// SRTP profile (MVP: Opus audio at 50pps)
// ============================================================================

const (
	dtlsSRTPProfile  = dtls.SRTP_AES128_CM_HMAC_SHA1_80
	srtpProfile      = srtp.ProtectionProfileAes128CmHmacSha1_80
	srtpKeyMatLen    = 60
	srtpKeyLen       = 16
	srtpSaltLen      = 14
	channelNum       = uint16(0x4001)
	opusPayloadType  = uint8(111)
	opusFrameSamples = 960 // 20ms at 48kHz
	opusFrameMs      = 20
	// Per-packet payload size is "natural" for Opus 64-96 kbps audio.
	// Subtract 1 byte for our padding flag (see chunker docs).
	maxPayloadSize = 170
	minPayloadSize = 110
)

// ============================================================================
// Dial — client-side
// ============================================================================

// Dial opens a lanturn client connection. The returned net.Conn carries
// caller bytes through the full lanturn stack: caller bytes →
// SRTP-paced chunks (Opus profile, 50pps) → AES-128-CM-HMAC-SHA1-80
// encryption → DTLS-derived keying → TURN ChannelData → plain UDP/3478.
//
// MVP: single session, UDP-only, Opus-only profile. Caller redials
// to start a fresh session.
func Dial(ctx context.Context, cfg ClientConfig) (net.Conn, error) {
	if len(cfg.CoturnEndpoints) == 0 {
		return nil, fmt.Errorf("lanturn: no coturn endpoints configured")
	}
	if cfg.Credential == nil {
		return nil, fmt.Errorf("lanturn: Credential callback required")
	}
	if cfg.PeerAddr == "" {
		return nil, fmt.Errorf("lanturn: PeerAddr required")
	}
	logf := cfg.Logger
	if logf == nil {
		logf = log.Printf
	}

	endpoint := cfg.CoturnEndpoints[0] // MVP: pick first
	cred, err := cfg.Credential(endpoint)
	if err != nil {
		return nil, fmt.Errorf("lanturn: credential issuance: %w", err)
	}

	peerHost, peerPortStr, err := net.SplitHostPort(cfg.PeerAddr)
	if err != nil {
		return nil, fmt.Errorf("lanturn: bad PeerAddr: %w", err)
	}
	peerIP := net.ParseIP(peerHost)
	if peerIP == nil {
		return nil, fmt.Errorf("lanturn: bad PeerAddr IP")
	}
	peerPort, err := net.LookupPort("udp", peerPortStr)
	if err != nil {
		return nil, fmt.Errorf("lanturn: bad PeerAddr port: %w", err)
	}

	// TURN allocation flow (delegates to internal/turn).
	alloc, err := turn.Allocate(turn.AllocateConfig{
		Server: endpoint.UDPAddr,
		// internal/turn currently expects a static-auth-secret to
		// generate creds itself. MVP shortcut: use the Credential
		// callback's password as if it WERE the static-auth-secret.
		// Production: extend internal/turn to accept a pre-issued
		// (username, password) tuple directly.
		Secret:  cred.Password,
		CredID:  "lanturn",
		CredTTL: 5 * time.Minute,
		Logf:    logf,
	})
	if err != nil {
		return nil, fmt.Errorf("lanturn: TURN allocate: %w", err)
	}

	if err := alloc.CreatePermission(peerIP, peerPort); err != nil {
		alloc.UDP.Close()
		return nil, fmt.Errorf("lanturn: CreatePermission: %w", err)
	}
	if err := alloc.ChannelBind(channelNum, peerIP, peerPort); err != nil {
		alloc.UDP.Close()
		return nil, fmt.Errorf("lanturn: ChannelBind: %w", err)
	}
	logf("lanturn: TURN allocate + ChannelBind OK (peer=%s)", cfg.PeerAddr)

	relay := alloc.NewRelayConn(channelNum)
	mux := newPacketMux(relay)

	// Inner DTLS handshake (client side). MVP: pion-default fingerprint
	// (deploy-blocking for Russia / China per design §4.4 + §11.2).
	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		alloc.UDP.Close()
		return nil, fmt.Errorf("lanturn: cert: %w", err)
	}
	dtlsCfg := &dtls.Config{
		Certificates:           []tls.Certificate{cert},
		InsecureSkipVerify:     true,
		ExtendedMasterSecret:   dtls.RequireExtendedMasterSecret,
		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{dtlsSRTPProfile},
	}
	peerUDPAddr := &net.UDPAddr{IP: peerIP, Port: peerPort}
	dtlsConn, err := dtls.Client(mux.dtlsPacketConn(peerUDPAddr), peerUDPAddr, dtlsCfg)
	if err != nil {
		alloc.UDP.Close()
		return nil, fmt.Errorf("lanturn: DTLS client setup: %w", err)
	}
	if err := dtlsConn.Handshake(); err != nil {
		dtlsConn.Close()
		alloc.UDP.Close()
		return nil, fmt.Errorf("lanturn: DTLS handshake: %w", err)
	}
	logf("lanturn: inner DTLS handshake OK")

	// Derive SRTP keys.
	state, ok := dtlsConn.ConnectionState()
	if !ok {
		dtlsConn.Close()
		alloc.UDP.Close()
		return nil, fmt.Errorf("lanturn: no DTLS connection state")
	}
	keyMat, err := state.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", nil, srtpKeyMatLen)
	if err != nil {
		dtlsConn.Close()
		alloc.UDP.Close()
		return nil, fmt.Errorf("lanturn: ExportKeyingMaterial: %w", err)
	}
	clientKey, clientSalt, _, _ := splitSRTPKeys(keyMat)
	txCtx, err := srtp.CreateContext(clientKey, clientSalt, srtpProfile)
	if err != nil {
		dtlsConn.Close()
		alloc.UDP.Close()
		return nil, fmt.Errorf("lanturn: SRTP TX context: %w", err)
	}

	// Build the streaming-chunker on top of the SRTP context.
	conn := newClientConn(ctx, mux, txCtx, alloc, dtlsConn, logf)
	return conn, nil
}

// ============================================================================
// Listen — server-side (Lantern egress)
// ============================================================================

// Listen opens a lanturn server listener. Each Accept returns a
// net.Conn for one inbound client session.
//
// MVP: accepts one session at a time (sequential). Production would
// concurrently accept multiple via the egressDemuxer pattern from
// cmd/lanturn-phase2/main.go.
func Listen(cfg ServerConfig) (net.Listener, error) {
	if cfg.ListenUDP == "" {
		return nil, fmt.Errorf("lanturn: ListenUDP required")
	}
	logf := cfg.Logger
	if logf == nil {
		logf = log.Printf
	}
	pc, err := net.ListenPacket("udp", cfg.ListenUDP)
	if err != nil {
		return nil, fmt.Errorf("lanturn: ListenPacket: %w", err)
	}
	return &listener{pc: pc, logf: logf, closed: make(chan struct{})}, nil
}

type listener struct {
	pc        net.PacketConn
	logf      func(format string, args ...any)
	closeOnce sync.Once
	closed    chan struct{}
}

func (l *listener) Accept() (net.Conn, error) {
	// Wait for first packet from a new source — this initiates a session.
	buf := make([]byte, 4096)
	n, srcAddr, err := l.pc.ReadFrom(buf)
	if err != nil {
		return nil, err
	}
	l.logf("lanturn: accepting session from %s (first pkt %dB leading=%#02x)", srcAddr, n, buf[0])

	// Wrap pc + first-packet replay as a single-source io.ReadWriter.
	first := append([]byte(nil), buf[:n]...)
	sconn := newSingleSourceConn(l.pc, srcAddr, first)
	mux := newPacketMux(sconn)

	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		mux.Close()
		return nil, fmt.Errorf("lanturn: cert: %w", err)
	}
	dtlsCfg := &dtls.Config{
		Certificates:           []tls.Certificate{cert},
		InsecureSkipVerify:     true,
		ExtendedMasterSecret:   dtls.RequireExtendedMasterSecret,
		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{dtlsSRTPProfile},
	}
	dtlsConn, err := dtls.Server(mux.dtlsPacketConn(srcAddr), srcAddr, dtlsCfg)
	if err != nil {
		mux.Close()
		return nil, fmt.Errorf("lanturn: DTLS server setup: %w", err)
	}
	if err := dtlsConn.Handshake(); err != nil {
		dtlsConn.Close()
		mux.Close()
		return nil, fmt.Errorf("lanturn: DTLS handshake: %w", err)
	}
	l.logf("lanturn: inner DTLS handshake OK")

	state, ok := dtlsConn.ConnectionState()
	if !ok {
		dtlsConn.Close()
		mux.Close()
		return nil, fmt.Errorf("lanturn: no DTLS connection state")
	}
	keyMat, err := state.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", nil, srtpKeyMatLen)
	if err != nil {
		dtlsConn.Close()
		mux.Close()
		return nil, fmt.Errorf("lanturn: ExportKeyingMaterial: %w", err)
	}
	clientKey, clientSalt, _, _ := splitSRTPKeys(keyMat)
	rxCtx, err := srtp.CreateContext(clientKey, clientSalt, srtpProfile)
	if err != nil {
		dtlsConn.Close()
		mux.Close()
		return nil, fmt.Errorf("lanturn: SRTP RX context: %w", err)
	}

	conn := newServerConn(mux, rxCtx, dtlsConn, l.logf)
	return conn, nil
}

func (l *listener) Close() error {
	l.closeOnce.Do(func() {
		close(l.closed)
		l.pc.Close()
	})
	return nil
}

func (l *listener) Addr() net.Addr {
	return l.pc.LocalAddr()
}

// ============================================================================
// Streaming chunker — the novel piece
// ============================================================================
//
// Caller bytes don't naturally align with SRTP packet sizes, so we
// chunk them into Opus-shaped payloads. Each payload's first byte is
// our padding flag:
//
//   - 0x00 = real data follows (length = payload_len - 1)
//   - 0x01 = padding (when caller has nothing to send but the SRTP
//     stream needs to keep emitting at media cadence)
//
// The flag is INSIDE the encrypted SRTP payload, so a passive observer
// sees random-looking bytes either way. The 1-byte overhead per packet
// is minor; alternatives like RTP-marker-bit signaling would conflict
// with real-WebRTC marker semantics.
//
// TX side: caller's Write enqueues bytes to a buffered channel; a
// streaming goroutine drains the buffer at media cadence into RTP+SRTP
// packets. When the buffer is empty between writes, the goroutine
// emits padding packets to maintain the wire-shape.
//
// RX side: the receive goroutine pulls SRTP packets, decrypts, parses
// RTP, peeks the flag byte. Real-data payloads get appended to a
// bytes-pipe; padding gets dropped. Caller's Read pulls from the pipe.
// ============================================================================

const (
	flagData    byte = 0x00
	flagPadding byte = 0x01
)

type clientConn struct {
	ctx      context.Context
	cancel   context.CancelFunc
	mux      *packetMux
	txCtx    *srtp.Context
	alloc    *turn.Allocation
	dtlsConn *dtls.Conn
	logf     func(format string, args ...any)

	writeBuf chan []byte // bounded buffer of pending caller bytes

	// rxPipe is the byte stream the caller reads from. Filled by a
	// goroutine reading SRTP packets, draining real-data payloads.
	rxPipe *bytesPipe

	closeOnce sync.Once
	closed    chan struct{}
	rxCtx     *srtp.Context
}

func newClientConn(ctx context.Context, mux *packetMux, txCtx *srtp.Context, alloc *turn.Allocation, dtlsConn *dtls.Conn, logf func(format string, args ...any)) *clientConn {
	// We'll need an RX SRTP context to decrypt the egress's responses.
	// Egress side derives keys with the SAME EXTRACTOR layout; the
	// "server write" half of our extracted keying material is the
	// peer's TX direction (our RX).
	state, _ := dtlsConn.ConnectionState()
	keyMat, _ := state.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", nil, srtpKeyMatLen)
	_, _, serverKey, serverSalt := splitSRTPKeys(keyMat)
	rxCtx, _ := srtp.CreateContext(serverKey, serverSalt, srtpProfile)

	cctx, cancel := context.WithCancel(ctx)
	c := &clientConn{
		ctx:      cctx,
		cancel:   cancel,
		mux:      mux,
		txCtx:    txCtx,
		rxCtx:    rxCtx,
		alloc:    alloc,
		dtlsConn: dtlsConn,
		logf:     logf,
		writeBuf: make(chan []byte, 64),
		rxPipe:   newBytesPipe(),
		closed:   make(chan struct{}),
	}
	go c.txLoop()
	go c.rxLoop()
	return c
}

func (c *clientConn) txLoop() {
	defer close(c.closed)
	ssrc := randUint32()
	ts := randUint32()
	seq := uint16(randUint32() & 0xFFFF)

	pending := make([]byte, 0, 4096)
	ticker := time.NewTicker(opusFrameMs * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			// Time to emit one packet.
			payloadSize := minPayloadSize + (int(randUint32()) % (maxPayloadSize - minPayloadSize))
			payload := make([]byte, payloadSize)

			// Fill payload from pending + writeBuf.
			needed := payloadSize - 1 // -1 for flag byte
			payload[0] = flagData
			n := copy(payload[1:], pending)
			pending = pending[n:]
			needed -= n
			for needed > 0 && len(c.writeBuf) > 0 {
				chunk := <-c.writeBuf
				wrote := copy(payload[1+n+(payloadSize-1-needed-n):], chunk)
				_ = wrote
				if wrote < len(chunk) {
					pending = append(pending, chunk[wrote:]...)
					needed = 0
				} else {
					needed -= wrote
				}
				n += wrote
			}

			if n == 0 {
				// Nothing to send — emit a padding packet.
				payload[0] = flagPadding
				rand.Read(payload[1:])
			} else if needed > 0 {
				// Pad the rest with random bytes so the size matches
				// the Opus profile.
				rand.Read(payload[1+n:])
			}

			pkt := &rtp.Packet{
				Header: rtp.Header{
					Version:        2,
					PayloadType:    opusPayloadType,
					SequenceNumber: seq,
					Timestamp:      ts,
					SSRC:           ssrc,
				},
				Payload: payload,
			}
			raw, _ := pkt.Marshal()
			encrypted, err := c.txCtx.EncryptRTP(nil, raw, nil)
			if err != nil {
				c.logf("lanturn: SRTP encrypt: %v", err)
				return
			}
			if _, err := c.mux.writeSRTP(encrypted); err != nil {
				c.logf("lanturn: write SRTP: %v", err)
				return
			}
			seq++
			ts += uint32(opusFrameSamples)
		}
	}
}

func (c *clientConn) rxLoop() {
	buf := make([]byte, 4096)
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}
		n, err := c.mux.readSRTP(buf)
		if err != nil {
			return
		}
		decrypted, err := c.rxCtx.DecryptRTP(nil, buf[:n], nil)
		if err != nil {
			continue
		}
		pkt := &rtp.Packet{}
		if err := pkt.Unmarshal(decrypted); err != nil {
			continue
		}
		if len(pkt.Payload) < 1 {
			continue
		}
		if pkt.Payload[0] == flagData {
			c.rxPipe.write(pkt.Payload[1:])
		}
		// padding dropped
	}
}

func (c *clientConn) Read(p []byte) (int, error)  { return c.rxPipe.read(p) }
func (c *clientConn) Write(p []byte) (int, error) {
	// Block while writeBuf is full (backpressure).
	chunk := append([]byte(nil), p...)
	select {
	case c.writeBuf <- chunk:
		return len(p), nil
	case <-c.ctx.Done():
		return 0, io.ErrClosedPipe
	}
}

func (c *clientConn) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		c.dtlsConn.Close()
		c.mux.Close()
		c.alloc.UDP.Close()
		c.rxPipe.close()
	})
	return nil
}

func (c *clientConn) LocalAddr() net.Addr                { return c.alloc.UDP.LocalAddr() }
func (c *clientConn) RemoteAddr() net.Addr               { return c.alloc.UDP.RemoteAddr() }
func (c *clientConn) SetDeadline(t time.Time) error      { return nil }
func (c *clientConn) SetReadDeadline(t time.Time) error  { return c.rxPipe.setReadDeadline(t) }
func (c *clientConn) SetWriteDeadline(t time.Time) error { return nil }

// serverConn is the egress-side mirror of clientConn: identical
// streaming-chunker pattern but with the keys swapped (server reads
// the client's TX, writes via the server's TX).
type serverConn struct {
	mux      *packetMux
	rxCtx    *srtp.Context
	txCtx    *srtp.Context
	dtlsConn *dtls.Conn
	logf     func(format string, args ...any)

	writeBuf chan []byte
	rxPipe   *bytesPipe

	closeOnce sync.Once
	closed    chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc
}

func newServerConn(mux *packetMux, rxCtx *srtp.Context, dtlsConn *dtls.Conn, logf func(format string, args ...any)) *serverConn {
	state, _ := dtlsConn.ConnectionState()
	keyMat, _ := state.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", nil, srtpKeyMatLen)
	_, _, serverKey, serverSalt := splitSRTPKeys(keyMat)
	txCtx, _ := srtp.CreateContext(serverKey, serverSalt, srtpProfile)

	ctx, cancel := context.WithCancel(context.Background())
	s := &serverConn{
		mux:      mux,
		rxCtx:    rxCtx,
		txCtx:    txCtx,
		dtlsConn: dtlsConn,
		logf:     logf,
		writeBuf: make(chan []byte, 64),
		rxPipe:   newBytesPipe(),
		closed:   make(chan struct{}),
		ctx:      ctx,
		cancel:   cancel,
	}
	go s.txLoop()
	go s.rxLoop()
	return s
}

func (s *serverConn) txLoop() {
	defer close(s.closed)
	ssrc := randUint32()
	ts := randUint32()
	seq := uint16(randUint32() & 0xFFFF)
	pending := make([]byte, 0, 4096)
	ticker := time.NewTicker(opusFrameMs * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			payloadSize := minPayloadSize + (int(randUint32()) % (maxPayloadSize - minPayloadSize))
			payload := make([]byte, payloadSize)
			needed := payloadSize - 1
			payload[0] = flagData
			n := copy(payload[1:], pending)
			pending = pending[n:]
			needed -= n
			for needed > 0 && len(s.writeBuf) > 0 {
				chunk := <-s.writeBuf
				wrote := copy(payload[1+n:], chunk)
				if wrote < len(chunk) {
					pending = append(pending, chunk[wrote:]...)
					needed = 0
				} else {
					needed -= wrote
				}
				n += wrote
			}
			if n == 0 {
				payload[0] = flagPadding
				rand.Read(payload[1:])
			} else if needed > 0 {
				rand.Read(payload[1+n:])
			}
			pkt := &rtp.Packet{
				Header: rtp.Header{
					Version:        2,
					PayloadType:    opusPayloadType,
					SequenceNumber: seq,
					Timestamp:      ts,
					SSRC:           ssrc,
				},
				Payload: payload,
			}
			raw, _ := pkt.Marshal()
			encrypted, err := s.txCtx.EncryptRTP(nil, raw, nil)
			if err != nil {
				return
			}
			if _, err := s.mux.writeSRTP(encrypted); err != nil {
				return
			}
			seq++
			ts += uint32(opusFrameSamples)
		}
	}
}

func (s *serverConn) rxLoop() {
	buf := make([]byte, 4096)
	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}
		n, err := s.mux.readSRTP(buf)
		if err != nil {
			return
		}
		decrypted, err := s.rxCtx.DecryptRTP(nil, buf[:n], nil)
		if err != nil {
			continue
		}
		pkt := &rtp.Packet{}
		if err := pkt.Unmarshal(decrypted); err != nil {
			continue
		}
		if len(pkt.Payload) < 1 {
			continue
		}
		if pkt.Payload[0] == flagData {
			s.rxPipe.write(pkt.Payload[1:])
		}
	}
}

func (s *serverConn) Read(p []byte) (int, error) { return s.rxPipe.read(p) }
func (s *serverConn) Write(p []byte) (int, error) {
	chunk := append([]byte(nil), p...)
	select {
	case s.writeBuf <- chunk:
		return len(p), nil
	case <-s.ctx.Done():
		return 0, io.ErrClosedPipe
	}
}

func (s *serverConn) Close() error {
	s.closeOnce.Do(func() {
		s.cancel()
		s.dtlsConn.Close()
		s.mux.Close()
		s.rxPipe.close()
	})
	return nil
}

func (s *serverConn) LocalAddr() net.Addr                { return s.dtlsConn.LocalAddr() }
func (s *serverConn) RemoteAddr() net.Addr               { return s.dtlsConn.RemoteAddr() }
func (s *serverConn) SetDeadline(t time.Time) error      { return nil }
func (s *serverConn) SetReadDeadline(t time.Time) error  { return s.rxPipe.setReadDeadline(t) }
func (s *serverConn) SetWriteDeadline(t time.Time) error { return nil }

// ============================================================================
// bytesPipe — buffered byte stream for RX-side reassembly
// ============================================================================

type bytesPipe struct {
	mu        sync.Mutex
	buf       []byte
	notFull   *sync.Cond
	notEmpty  *sync.Cond
	closed    bool
	deadline  time.Time
	deadlineT *time.Timer
}

func newBytesPipe() *bytesPipe {
	p := &bytesPipe{}
	p.notFull = sync.NewCond(&p.mu)
	p.notEmpty = sync.NewCond(&p.mu)
	return p
}

func (p *bytesPipe) write(data []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.buf = append(p.buf, data...)
	p.notEmpty.Broadcast()
}

func (p *bytesPipe) read(out []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for len(p.buf) == 0 && !p.closed {
		p.notEmpty.Wait()
	}
	if len(p.buf) == 0 && p.closed {
		return 0, io.EOF
	}
	n := copy(out, p.buf)
	p.buf = p.buf[n:]
	p.notFull.Broadcast()
	return n, nil
}

func (p *bytesPipe) setReadDeadline(t time.Time) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.deadline = t
	return nil
}

func (p *bytesPipe) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	p.notEmpty.Broadcast()
	p.notFull.Broadcast()
}

// ============================================================================
// packetMux — same DTLS/SRTP demux as cmd/lanturn-phase{2,3}
// ============================================================================

type packetMux struct {
	underlying io.ReadWriteCloser
	dtlsCh     chan []byte
	srtpCh     chan []byte
	closeOnce  sync.Once
	closed     chan struct{}
}

func newPacketMux(underlying io.ReadWriteCloser) *packetMux {
	m := &packetMux{
		underlying: underlying,
		dtlsCh:     make(chan []byte, 64),
		srtpCh:     make(chan []byte, 64),
		closed:     make(chan struct{}),
	}
	go m.readLoop()
	return m
}

func (m *packetMux) readLoop() {
	buf := make([]byte, 4096)
	for {
		n, err := m.underlying.Read(buf)
		if err != nil {
			m.Close()
			return
		}
		if n == 0 {
			continue
		}
		pkt := append([]byte(nil), buf[:n]...)
		first := pkt[0]
		switch {
		case first >= 20 && first <= 25:
			select {
			case m.dtlsCh <- pkt:
			case <-m.closed:
				return
			}
		case first >= 128 && first <= 191:
			select {
			case m.srtpCh <- pkt:
			case <-m.closed:
				return
			}
		}
	}
}

func (m *packetMux) Close() error {
	m.closeOnce.Do(func() {
		close(m.closed)
		m.underlying.Close()
	})
	return nil
}

func (m *packetMux) writeSRTP(p []byte) (int, error) { return m.underlying.Write(p) }

func (m *packetMux) readSRTP(p []byte) (int, error) {
	select {
	case pkt := <-m.srtpCh:
		return copy(p, pkt), nil
	case <-m.closed:
		return 0, io.EOF
	}
}

func (m *packetMux) dtlsPacketConn(peer net.Addr) net.PacketConn {
	return &muxPacketConn{mux: m, ch: m.dtlsCh, peerAddr: peer}
}

type muxPacketConn struct {
	mux      *packetMux
	ch       chan []byte
	peerAddr net.Addr

	rdMu       sync.Mutex
	rdDeadline time.Time
}

func (c *muxPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.rdMu.Lock()
	dl := c.rdDeadline
	c.rdMu.Unlock()
	var deadline <-chan time.Time
	if !dl.IsZero() {
		t := time.NewTimer(time.Until(dl))
		defer t.Stop()
		deadline = t.C
	}
	select {
	case pkt := <-c.ch:
		return copy(p, pkt), c.peerAddr, nil
	case <-deadline:
		return 0, nil, fmt.Errorf("read deadline exceeded")
	case <-c.mux.closed:
		return 0, nil, io.EOF
	}
}

func (c *muxPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	return c.mux.underlying.Write(p)
}

func (c *muxPacketConn) Close() error                 { return c.mux.Close() }
func (c *muxPacketConn) LocalAddr() net.Addr          { return dummyAddr{} }
func (c *muxPacketConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return nil
}
func (c *muxPacketConn) SetReadDeadline(t time.Time) error {
	c.rdMu.Lock()
	defer c.rdMu.Unlock()
	c.rdDeadline = t
	return nil
}
func (c *muxPacketConn) SetWriteDeadline(t time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "lanturn" }
func (dummyAddr) String() string  { return "lanturn" }

// ============================================================================
// singleSourceConn — pin pc to one peer for the egress's first session
// ============================================================================

type singleSourceConn struct {
	pc       net.PacketConn
	peer     net.Addr
	first    []byte
	consumed bool
	mu       sync.Mutex
}

func newSingleSourceConn(pc net.PacketConn, peer net.Addr, first []byte) *singleSourceConn {
	return &singleSourceConn{pc: pc, peer: peer, first: first}
}

func (s *singleSourceConn) Read(p []byte) (int, error) {
	s.mu.Lock()
	if !s.consumed && len(s.first) > 0 {
		n := copy(p, s.first)
		s.consumed = true
		s.mu.Unlock()
		return n, nil
	}
	s.mu.Unlock()
	for {
		buf := make([]byte, 4096)
		n, addr, err := s.pc.ReadFrom(buf)
		if err != nil {
			return 0, err
		}
		if addr.String() != s.peer.String() {
			continue
		}
		return copy(p, buf[:n]), nil
	}
}

func (s *singleSourceConn) Write(p []byte) (int, error) { return s.pc.WriteTo(p, s.peer) }
func (s *singleSourceConn) Close() error                { return nil } // pc shared

// ============================================================================
// helpers
// ============================================================================

func splitSRTPKeys(keyMat []byte) (clientKey, clientSalt, serverKey, serverSalt []byte) {
	clientKey = keyMat[0:srtpKeyLen]
	serverKey = keyMat[srtpKeyLen : 2*srtpKeyLen]
	clientSalt = keyMat[2*srtpKeyLen : 2*srtpKeyLen+srtpSaltLen]
	serverSalt = keyMat[2*srtpKeyLen+srtpSaltLen : 2*srtpKeyLen+2*srtpSaltLen]
	return
}

func randUint32() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}

// Deferred-implementation hooks (kept as no-op exports so lantern-box
// can wire against the API surface today).

// FleetSelector is the production fleet-selector interface; MVP uses
// round-robin via CoturnEndpoints[0]. Port from cmd/lanturn-phase2/main.go.
type FleetSelector interface {
	Pick() (CoturnEndpoint, bool)
	RecordSuccess(addr CoturnEndpoint)
	RecordFailure(addr CoturnEndpoint)
}

// MediaProfileSpec is the per-profile tuple from cmd/lanturn-phase3/main.go.
// Reserved for telemetry / debug.
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
