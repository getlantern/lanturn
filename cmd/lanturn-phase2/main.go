// lanturn-phase2 — Phase 2 spike: behavioral mimicry on top of the
// Phase 1 DTLS-through-relay + SRTP foundation.
//
// Phase 2 deliverables (per design doc §9):
//
//   - covert-dtls fingerprint randomization on the inner DTLS handshake
//     (the design's hard requirement for Russia / China rollout — see
//     `cover-dtls` catalog §Censor Practice for the TSPU March 2026
//     attack against the pion-default fingerprint).
//   - Session rotation: ~30-min "calls" with brief idle gaps. Each
//     session is a fresh allocation, fresh OAUTH creds, fresh DTLS
//     handshake, fresh SRTP keys, fresh SSRC + sequence + timestamps.
//   - Pacing fidelity: jitter envelope on inter-packet timing,
//     RTCP SR/RR interleaving, DTX during quiet periods.
//   - coturn-fleet rotation: client picks endpoint per session from a
//     list, with recency weighting.
//
// This file lands those incrementally — Phase 2a covers the
// covert-dtls + pion/dtls/v3 migration; subsequent commits layer on
// session rotation, pacing fidelity, and fleet rotation.
//
// Architecture is the same as Phase 1; see design doc §4 and the
// Phase 1 main.go for the diagram.
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/getlantern/lanturn/internal/stun"
	"github.com/getlantern/lanturn/internal/turn"

	"github.com/pion/dtls/v3"
	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/rtp"
	"github.com/pion/srtp/v3"
	pionturn "github.com/pion/turn/v3"
	"github.com/theodorsm/covert-dtls/pkg/mimicry"
	"github.com/theodorsm/covert-dtls/pkg/randomize"
)

const (
	dtlsSRTPProfile = dtls.SRTP_AES128_CM_HMAC_SHA1_80
	srtpProfile     = srtp.ProtectionProfileAes128CmHmacSha1_80

	srtpKeyMaterialLen = 60
	srtpKeyLen         = 16
	srtpSaltLen        = 14
)

const (
	channelNum       uint16 = 0x4001
	opusPayloadType  uint8  = 111
	opusSampleRate          = 48000
	opusFrameMs             = 20
	opusFrameSamples        = opusSampleRate * opusFrameMs / 1000
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "server":
		fs := flag.NewFlagSet("server", flag.ExitOnError)
		listen := fs.String("listen", "0.0.0.0:3478", "TURN server udp listen addr")
		realm := fs.String("realm", "lanturn.example", "TURN realm")
		secret := fs.String("secret", "lanturn-phase2-shared-secret", "static-auth-secret")
		fs.Parse(os.Args[2:])
		if err := runServer(*listen, *realm, *secret); err != nil {
			log.Fatal(err)
		}
	case "egress":
		fs := flag.NewFlagSet("egress", flag.ExitOnError)
		listen := fs.String("listen", "127.0.0.1:9999", "egress udp listen addr")
		sessionCount := fs.Int("sessions", 3, "number of back-to-back sessions to accept")
		fs.Parse(os.Args[2:])
		if err := runEgress(*listen, *sessionCount); err != nil {
			log.Fatal(err)
		}
	case "client":
		fs := flag.NewFlagSet("client", flag.ExitOnError)
		server := fs.String("server", "127.0.0.1:3478", "TURN server")
		secret := fs.String("secret", "lanturn-phase2-shared-secret", "static-auth-secret")
		peer := fs.String("peer", "127.0.0.1:9999", "egress address")
		fpMode := fs.String("fingerprint", "mimic", "DTLS ClientHello fingerprint mode: mimic | randomize | none")
		sessionCount := fs.Int("sessions", 3, "number of back-to-back sessions to run")
		sessionDur := fs.Duration("session-duration", 1*time.Second, "duration of each session (production target: 25-35 min)")
		idleGapMin := fs.Duration("idle-gap-min", 200*time.Millisecond, "min idle gap between sessions (production target: 30s)")
		idleGapMax := fs.Duration("idle-gap-max", 1*time.Second, "max idle gap between sessions (production target: 5min)")
		retries := fs.Int("retries", 3, "DTLS handshake retries per session")
		fs.Parse(os.Args[2:])
		if err := runClient(*server, *secret, *peer, *fpMode, *sessionCount, *sessionDur, *idleGapMin, *idleGapMax, *retries); err != nil {
			log.Fatal(err)
		}
	default:
		usage()
		os.Exit(2)
	}
}

// ----------------------------------------------------------------------------
// Server subcommand: same as Phase 0/1.
// ----------------------------------------------------------------------------

func runServer(listen, realm, secret string) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	if host == "" {
		host = "0.0.0.0"
	}
	udpListener, err := net.ListenPacket("udp4", listen)
	if err != nil {
		return fmt.Errorf("listen UDP %s: %w", listen, err)
	}
	pubIP := net.ParseIP("127.0.0.1")
	if pip := os.Getenv("LANTURN_PUBLIC_IP"); pip != "" {
		pubIP = net.ParseIP(pip)
	}
	server, err := pionturn.NewServer(pionturn.ServerConfig{
		Realm:         realm,
		AuthHandler:   useAuthSecretHandler(secret),
		LoggerFactory: logging.NewDefaultLoggerFactory(),
		PacketConnConfigs: []pionturn.PacketConnConfig{
			{
				PacketConn: udpListener,
				RelayAddressGenerator: &pionturn.RelayAddressGeneratorStatic{
					RelayAddress: pubIP,
					Address:      host,
				},
			},
		},
	})
	if err != nil {
		return err
	}
	log.Printf("TURN server listening on %s (realm=%s, public-ip=%s)", listen, realm, pubIP)
	defer server.Close()
	select {}
}

func useAuthSecretHandler(secret string) pionturn.AuthHandler {
	return func(username, realm string, srcAddr net.Addr) ([]byte, bool) {
		parts := strings.SplitN(username, ":", 2)
		if len(parts) != 2 {
			return nil, false
		}
		exp, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil || time.Now().Unix() > exp {
			return nil, false
		}
		mac := hmac.New(sha1.New, []byte(secret))
		mac.Write([]byte(username))
		password := base64.StdEncoding.EncodeToString(mac.Sum(nil))
		log.Printf("server auth: %s OK", username)
		return stun.LongTermKey(username, realm, password), true
	}
}

// ----------------------------------------------------------------------------
// Client subcommand: orchestrates a series of sessions, each a fresh
// allocate / DTLS handshake / SRTP flow, with idle gaps in between.
// Each "session" simulates a single ~30-min "call" in production. For
// the spike, default duration is short so smoke tests run quickly.
// ----------------------------------------------------------------------------

func runClient(server, secret, peerStr, fpMode string, sessionCount int, sessionDur, idleMin, idleMax time.Duration, retries int) error {
	peerIP, peerPort, err := parseHostPort(peerStr)
	if err != nil {
		return err
	}

	for sessionNum := 1; sessionNum <= sessionCount; sessionNum++ {
		log.Printf("=== session %d/%d starting (target duration %s) ===", sessionNum, sessionCount, sessionDur)
		var lastErr error
		for attempt := 1; attempt <= retries; attempt++ {
			err := runClientSession(server, secret, peerIP, peerPort, fpMode, sessionDur)
			if err == nil {
				lastErr = nil
				break
			}
			lastErr = err
			log.Printf("session %d attempt %d failed: %v", sessionNum, attempt, err)
			if attempt < retries {
				time.Sleep(200 * time.Millisecond)
			}
		}
		if lastErr != nil {
			log.Printf("=== session %d gave up after %d attempts: %v ===", sessionNum, retries, lastErr)
		} else {
			log.Printf("=== session %d completed ===", sessionNum)
		}
		if sessionNum < sessionCount {
			gap := randomDuration(idleMin, idleMax)
			log.Printf("=== idle gap %s before next session ===", gap)
			time.Sleep(gap)
		}
	}
	return nil
}

// runClientSession runs one allocate→DTLS→SRTP flow for the given duration.
// On return (success or error), all resources are cleaned up.
func runClientSession(server, secret string, peerIP net.IP, peerPort int, fpMode string, dur time.Duration) error {
	alloc, err := turn.Allocate(turn.AllocateConfig{
		Server:  server,
		Secret:  secret,
		CredID:  "lanturn-phase2",
		CredTTL: 5 * time.Minute,
		Logf:    log.Printf,
	})
	if err != nil {
		return err
	}
	defer alloc.UDP.Close()

	if err := alloc.CreatePermission(peerIP, peerPort); err != nil {
		return err
	}
	if err := alloc.ChannelBind(channelNum, peerIP, peerPort); err != nil {
		return err
	}
	log.Printf("client: TURN allocate + ChannelBind OK (channel=%#04x peer=%s:%d)", channelNum, peerIP, peerPort)

	relay := alloc.NewRelayConn(channelNum)
	mux := newPacketMux(relay, "client")
	defer mux.Close()

	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return fmt.Errorf("self-signed cert: %w", err)
	}

	dtlsCfg := &dtls.Config{
		Certificates:           []tls.Certificate{cert},
		InsecureSkipVerify:     true,
		ExtendedMasterSecret:   dtls.RequireExtendedMasterSecret,
		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{dtlsSRTPProfile},
	}

	// Covert-DTLS fingerprint randomization. The pion-default DTLS
	// ClientHello has been TSPU-fingerprint-blocked since March 2026
	// (cover-dtls catalog §Censor Practice). Three modes:
	//
	//   - mimic: replay a real (recent Chrome) DTLS ClientHello,
	//     selected at random from covert-dtls's hardcoded fingerprint
	//     database. ~100% handshake success rate. Default.
	//   - randomize: shuffle + subset the cipher-suite list, randomize
	//     extensions. ~85% handshake success rate (random cipher
	//     subset occasionally lacks any cert-compatible cipher) —
	//     production usage MUST handle retry on InsufficientSecurity.
	//   - none: pion-default fingerprint. TSPU-blocked since March
	//     2026; do NOT deploy.
	switch strings.ToLower(fpMode) {
	case "mimic":
		hooker := &mimicry.MimickedClientHello{}
		if err := hooker.LoadRandomFingerprint(); err != nil {
			return fmt.Errorf("load random Chrome fingerprint: %w", err)
		}
		dtlsCfg.ClientHelloMessageHook = hooker.Hook
		log.Printf("client: covert-dtls mimic mode enabled (random Chrome fingerprint)")
	case "randomize":
		hooker := &randomize.RandomizedMessageClientHello{RandomALPN: true}
		dtlsCfg.ClientHelloMessageHook = hooker.Hook
		log.Printf("client: covert-dtls randomize mode enabled (RandomALPN=true)")
	case "none":
		log.Printf("client: covert-dtls DISABLED — using pion-default fingerprint (TSPU-blocked!)")
	default:
		return fmt.Errorf("unknown -fingerprint mode %q (want: mimic | randomize | none)", fpMode)
	}

	peerUDPAddr := &net.UDPAddr{IP: peerIP, Port: peerPort}

	log.Printf("client: starting DTLS handshake through TURN relay...")
	t0 := time.Now()
	dtlsConn, err := dtls.Client(mux.DTLSPacketConn(peerUDPAddr), peerUDPAddr, dtlsCfg)
	if err != nil {
		return fmt.Errorf("DTLS Client setup: %w", err)
	}
	defer dtlsConn.Close()
	if err := dtlsConn.Handshake(); err != nil {
		return fmt.Errorf("DTLS handshake: %w", err)
	}
	log.Printf("client: DTLS handshake OK in %s", time.Since(t0))

	profile, ok := dtlsConn.SelectedSRTPProtectionProfile()
	if !ok || profile != dtlsSRTPProfile {
		return fmt.Errorf("expected SRTP profile %d, got %d ok=%v", dtlsSRTPProfile, profile, ok)
	}
	log.Printf("client: negotiated SRTP profile: %#x (AES-128-CM-HMAC-SHA1-80)", uint16(profile))

	state, ok2 := dtlsConn.ConnectionState()
	if !ok2 {
		return fmt.Errorf("connection state not available")
	}
	keyMat, err := state.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", nil, srtpKeyMaterialLen)
	if err != nil {
		return fmt.Errorf("export keying material: %w", err)
	}
	log.Printf("client: extracted %d bytes of SRTP keying material", len(keyMat))

	clientWriteKey, clientWriteSalt, _, _ := splitSRTPKeys(keyMat)
	txCtx, err := srtp.CreateContext(clientWriteKey, clientWriteSalt, srtpProfile)
	if err != nil {
		return fmt.Errorf("create SRTP TX context: %w", err)
	}

	// Fresh per-session SSRC + sequence + timestamp, as a real WebRTC
	// session would. SSRC stable within a session.
	ssrc := randUint32()
	ts := randUint32()
	seq := uint16(randUint32() & 0xFFFF)

	deadline := time.Now().Add(dur)
	log.Printf("client: SRTP TX context ready (ssrc=%#x), streaming Opus-shaped packets for %s...", ssrc, dur)
	pktCount := 0
	for time.Now().Before(deadline) {
		payloadLen := 100 + (int(randUint32()) % 80)
		payload := make([]byte, payloadLen)
		rand.Read(payload)
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
		raw, err := pkt.Marshal()
		if err != nil {
			return err
		}
		encrypted, err := txCtx.EncryptRTP(nil, raw, nil)
		if err != nil {
			return err
		}
		if _, err := mux.WriteSRTP(encrypted); err != nil {
			return err
		}
		seq++
		ts += uint32(opusFrameSamples)
		pktCount++
		time.Sleep(time.Duration(opusFrameMs) * time.Millisecond)
	}
	log.Printf("client: session sent %d SRTP packets in %s (~%.0f pps)", pktCount, dur, float64(pktCount)/dur.Seconds())

	// Brief grace before tearing down so egress can drain. In a real
	// production teardown the client would also send a Refresh with
	// LIFETIME=0 to release the allocation cleanly; here we just close
	// the UDP socket and let the allocation expire.
	time.Sleep(200 * time.Millisecond)
	return nil
}

// ----------------------------------------------------------------------------
// Egress subcommand: accepts a series of sessions back-to-back, each
// starting on the first packet from a new source UDP port (a new
// coturn relay address allocated for a fresh client session).
//
// Architecture: ONE central reader goroutine drains the shared
// net.PacketConn and demuxes packets to per-session-source channels.
// Each session's mux pulls its own packets from a channel rather than
// racing the underlying socket. This is the standard
// listener-with-many-sessions pattern (also what pion/dtls.Listen()
// does internally).
// ----------------------------------------------------------------------------

func runEgress(listen string, sessionCount int) error {
	pc, err := net.ListenPacket("udp", listen)
	if err != nil {
		return fmt.Errorf("listen UDP %s: %w", listen, err)
	}
	defer pc.Close()
	log.Printf("egress: listening on %s, will accept %d sessions...", listen, sessionCount)

	demux := newEgressDemuxer(pc)
	defer demux.Close()

	for sessionNum := 1; sessionNum <= sessionCount; sessionNum++ {
		log.Printf("=== egress session %d/%d waiting for first packet ===", sessionNum, sessionCount)
		ev, ok := demux.NextSession()
		if !ok {
			return fmt.Errorf("demuxer closed before session %d", sessionNum)
		}
		log.Printf("egress: first packet from %s (%dB, leading=%#02x)", ev.addr, len(ev.firstPkt), ev.firstPkt[0])
		if err := runEgressSession(pc, demux, ev); err != nil {
			log.Printf("egress session %d failed: %v", sessionNum, err)
		} else {
			log.Printf("=== egress session %d completed ===", sessionNum)
		}
	}
	return nil
}

// runEgressSession handles one client session: wraps the demuxer's
// per-source channel as a net.Conn, runs DTLS server + SRTP receive,
// returns when peer goes silent.
func runEgressSession(pc net.PacketConn, demux *egressDemuxer, ev *sessionEvent) error {
	defer demux.endSession(ev.addr)

	sconn := &sessionConn{
		rxCh: ev.rxCh,
		pc:   pc,
		addr: ev.addr,
	}
	mux := newPacketMux(sconn, "egress")
	defer mux.Close()

	cert, err := selfsign.GenerateSelfSigned()
	if err != nil {
		return err
	}
	dtlsCfg := &dtls.Config{
		Certificates:           []tls.Certificate{cert},
		InsecureSkipVerify:     true,
		ExtendedMasterSecret:   dtls.RequireExtendedMasterSecret,
		SRTPProtectionProfiles: []dtls.SRTPProtectionProfile{dtlsSRTPProfile},
	}
	log.Printf("egress: starting DTLS server handshake...")
	t0 := time.Now()
	dtlsConn, err := dtls.Server(mux.DTLSPacketConn(ev.addr), ev.addr, dtlsCfg)
	if err != nil {
		return fmt.Errorf("DTLS Server setup: %w", err)
	}
	defer dtlsConn.Close()
	if err := dtlsConn.Handshake(); err != nil {
		return fmt.Errorf("DTLS handshake: %w", err)
	}
	log.Printf("egress: DTLS handshake OK in %s", time.Since(t0))

	state, ok2 := dtlsConn.ConnectionState()
	if !ok2 {
		return fmt.Errorf("connection state not available")
	}
	keyMat, err := state.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", nil, srtpKeyMaterialLen)
	if err != nil {
		return err
	}

	clientWriteKey, clientWriteSalt, _, _ := splitSRTPKeys(keyMat)
	rxCtx, err := srtp.CreateContext(clientWriteKey, clientWriteSalt, srtpProfile)
	if err != nil {
		return err
	}
	log.Printf("egress: SRTP RX context ready, receiving packets until peer goes silent...")

	rxBuf := make([]byte, 4096)
	pktCount := 0
	for {
		// 2-second silence threshold marks session end.
		mux.srtpReadDeadline(time.Now().Add(2 * time.Second))
		n, err := mux.ReadSRTP(rxBuf)
		if err != nil {
			break
		}
		_, err = rxCtx.DecryptRTP(nil, rxBuf[:n], nil)
		if err != nil {
			log.Printf("egress: decrypt err pkt %d: %v", pktCount, err)
			continue
		}
		pktCount++
	}
	log.Printf("egress: session received %d SRTP packets", pktCount)
	return nil
}

// ----------------------------------------------------------------------------
// packetMux — refactored from Phase 1 to provide net.PacketConn for
// pion/dtls/v3 (which switched from net.Conn to net.PacketConn-based
// constructors).
//
// Demux rules from RFC 5764 §5:
//   - 0x00-0x13 (decimal 0-19) = STUN (unused post-handshake here)
//   - 0x14-0x19 (decimal 20-25) = DTLS records
//   - 0x80-0xBF (decimal 128-191) = RTP/RTCP (RTP version 2)
// ----------------------------------------------------------------------------

type packetMux struct {
	underlying io.ReadWriteCloser
	label      string

	dtlsCh chan []byte
	srtpCh chan []byte

	srtpDeadlineMu sync.Mutex
	srtpDeadline   time.Time

	closeOnce sync.Once
	closed    chan struct{}
}

func newPacketMux(underlying io.ReadWriteCloser, label string) *packetMux {
	m := &packetMux{
		underlying: underlying,
		label:      label,
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
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
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
		default:
			log.Printf("[%s mux] dropping packet with leading byte %#02x (%dB)", m.label, first, n)
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

// DTLSPacketConn returns a net.PacketConn over the dtls-classified
// channel. peerAddr is reported as the remote on every ReadFrom.
func (m *packetMux) DTLSPacketConn(peerAddr net.Addr) net.PacketConn {
	return &muxPacketConn{mux: m, ch: m.dtlsCh, peerAddr: peerAddr, localAddr: dummyAddr{}}
}

func (m *packetMux) WriteSRTP(p []byte) (int, error) { return m.underlying.Write(p) }

func (m *packetMux) ReadSRTP(p []byte) (int, error) {
	m.srtpDeadlineMu.Lock()
	dl := m.srtpDeadline
	m.srtpDeadlineMu.Unlock()
	var deadline <-chan time.Time
	if !dl.IsZero() {
		t := time.NewTimer(time.Until(dl))
		defer t.Stop()
		deadline = t.C
	}
	select {
	case pkt := <-m.srtpCh:
		return copy(p, pkt), nil
	case <-deadline:
		return 0, fmt.Errorf("read SRTP timeout")
	case <-m.closed:
		return 0, io.EOF
	}
}

func (m *packetMux) srtpReadDeadline(t time.Time) {
	m.srtpDeadlineMu.Lock()
	defer m.srtpDeadlineMu.Unlock()
	m.srtpDeadline = t
}

type muxPacketConn struct {
	mux       *packetMux
	ch        chan []byte
	peerAddr  net.Addr
	localAddr net.Addr

	rdDeadlineMu sync.Mutex
	rdDeadline   time.Time
}

func (c *muxPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	c.rdDeadlineMu.Lock()
	dl := c.rdDeadline
	c.rdDeadlineMu.Unlock()
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

func (c *muxPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return c.mux.underlying.Write(p)
}

func (c *muxPacketConn) Close() error             { return c.mux.Close() }
func (c *muxPacketConn) LocalAddr() net.Addr      { return c.localAddr }
func (c *muxPacketConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return nil
}
func (c *muxPacketConn) SetReadDeadline(t time.Time) error {
	c.rdDeadlineMu.Lock()
	defer c.rdDeadlineMu.Unlock()
	c.rdDeadline = t
	return nil
}
func (c *muxPacketConn) SetWriteDeadline(t time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "muxed" }
func (dummyAddr) String() string  { return "muxed" }

// ----------------------------------------------------------------------------
// egressDemuxer — single shared reader over net.PacketConn; routes
// packets to per-source-address channels. Necessary so multiple
// sequential sessions on the same listener don't race each other.
// ----------------------------------------------------------------------------

type sessionEvent struct {
	addr     net.Addr
	firstPkt []byte
	rxCh     chan []byte
}

type egressDemuxer struct {
	pc        net.PacketConn
	sessions  sync.Map // addr.String() -> chan []byte
	newSess   chan *sessionEvent
	closeOnce sync.Once
	closed    chan struct{}
}

func newEgressDemuxer(pc net.PacketConn) *egressDemuxer {
	d := &egressDemuxer{
		pc:      pc,
		newSess: make(chan *sessionEvent, 4),
		closed:  make(chan struct{}),
	}
	go d.run()
	return d
}

func (d *egressDemuxer) run() {
	for {
		buf := make([]byte, 4096)
		n, addr, err := d.pc.ReadFrom(buf)
		if err != nil {
			d.Close()
			return
		}
		pkt := append([]byte(nil), buf[:n]...)
		key := addr.String()
		if v, ok := d.sessions.Load(key); ok {
			ch := v.(chan []byte)
			select {
			case ch <- pkt:
			default:
				// drop on full — pacing is sufficient that
				// this shouldn't fire in practice
			}
			continue
		}
		// New session.
		ch := make(chan []byte, 64)
		d.sessions.Store(key, ch)
		ch <- pkt // first packet
		select {
		case d.newSess <- &sessionEvent{addr: addr, firstPkt: pkt, rxCh: ch}:
		case <-d.closed:
			return
		}
	}
}

func (d *egressDemuxer) NextSession() (*sessionEvent, bool) {
	select {
	case ev, ok := <-d.newSess:
		return ev, ok
	case <-d.closed:
		return nil, false
	}
}

func (d *egressDemuxer) endSession(addr net.Addr) {
	if v, ok := d.sessions.LoadAndDelete(addr.String()); ok {
		close(v.(chan []byte))
	}
}

func (d *egressDemuxer) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed)
	})
	return nil
}

// sessionConn wraps the demuxer's per-session channel as an
// io.ReadWriteCloser for packetMux. Reads pull from rxCh; writes go
// out via pc.WriteTo. Close drops the channel reference (the
// underlying pc is shared and outlives any single session).
type sessionConn struct {
	rxCh chan []byte
	pc   net.PacketConn
	addr net.Addr

	closeOnce sync.Once
	closed    chan struct{}
}

func (c *sessionConn) Read(p []byte) (int, error) {
	if c.closed == nil {
		c.closed = make(chan struct{})
	}
	select {
	case pkt, ok := <-c.rxCh:
		if !ok {
			return 0, io.EOF
		}
		return copy(p, pkt), nil
	case <-c.closed:
		return 0, io.EOF
	}
}

func (c *sessionConn) Write(p []byte) (int, error) {
	return c.pc.WriteTo(p, c.addr)
}

func (c *sessionConn) Close() error {
	c.closeOnce.Do(func() {
		if c.closed == nil {
			c.closed = make(chan struct{})
		}
		close(c.closed)
	})
	return nil
}

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

func splitSRTPKeys(keyMat []byte) (clientKey, clientSalt, serverKey, serverSalt []byte) {
	clientKey = keyMat[0:srtpKeyLen]
	serverKey = keyMat[srtpKeyLen : 2*srtpKeyLen]
	clientSalt = keyMat[2*srtpKeyLen : 2*srtpKeyLen+srtpSaltLen]
	serverSalt = keyMat[2*srtpKeyLen+srtpSaltLen : 2*srtpKeyLen+2*srtpSaltLen]
	return
}

func parseHostPort(s string) (net.IP, int, error) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return nil, 0, err
	}
	port, _ := strconv.Atoi(p)
	ip := net.ParseIP(h)
	if ip == nil {
		return nil, 0, fmt.Errorf("bad ip %q", h)
	}
	return ip, port, nil
}

func randUint32() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// randomDuration picks a uniformly random duration in [min, max].
func randomDuration(min, max time.Duration) time.Duration {
	if max <= min {
		return min
	}
	span := max - min
	r := time.Duration(randUint32()) % span
	return min + r
}

func usage() {
	fmt.Fprintf(os.Stderr, `lanturn-phase2 — DTLS-through-relay + SRTP shaping with covert-dtls.

Subcommands (same shape as Phase 1):

  lanturn-phase2 server [-listen 0.0.0.0:3478] [-realm STR] [-secret STR]
  lanturn-phase2 egress [-listen 127.0.0.1:9999]
  lanturn-phase2 client [-server HOST:PORT] [-secret STR] [-peer HOST:PORT]
                        [-fingerprint randomize|none]

Phase 2a (this commit) adds:
  - pion/dtls/v3 migration (v2 lacks ClientHelloMessageHook)
  - covert-dtls per-session ClientHello randomization
  - net.PacketConn-shaped mux (v3 API change)

Phase 2b/c/d will layer on session rotation, jitter envelope, RTCP /
DTX / NACK-RTX, and coturn-fleet rotation.

`)
}
