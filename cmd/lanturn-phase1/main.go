// lanturn-phase1 — Phase 1 spike: DTLS handshake through TURN relay
// + SRTP-shaped steady-state packets.
//
// What this validates beyond Phase 0:
//
//   - The DTLS handshake bytes between client and egress flow
//     **inside ChannelData payloads** (TURN relay forwards them
//     opaquely). The client wraps its allocation as a RelayConn;
//     pion/dtls treats that RelayConn as a net.Conn and runs a
//     standard DTLS handshake.
//
//   - After handshake, both sides extract SRTP keying material via
//     RFC 5705 ExportKeyingMaterial("EXTRACTOR-dtls_srtp", ...) per
//     RFC 5764 §4.2.
//
//   - Steady-state packets are SRTP-shaped (RTP header v=2, PT=111
//     Opus, SSRC, sequence, timestamp) with AES-128-CM-HMAC-SHA1-80
//     encryption — the byte distribution a censor expects from a real
//     WebRTC-via-TURN media flow.
//
// Architecture:
//
//   client ──TURN/UDP──► coturn ──UDP relay──► egress
//     ║                                            ║
//     ╚══════════ DTLS handshake → SRTP ══════════╝
//                 (relayed opaquely by coturn)
//
// Limitations of Phase 1 (deferred to later phases per design §9):
//
//   - No covert-dtls fingerprint randomization. Plain pion/dtls is
//     used. **DO NOT deploy this to Russia / China without adding the
//     fingerprint hook.** See design doc §4.4 + cover-dtls catalog
//     §Censor Practice + the Phase 2 plan.
//   - No Opus codec emulation; payload is random bytes shaped at
//     opus-cadence. Phase 2/3 add codec-realistic shaping.
//   - No session rotation, jitter envelope, RTCP, NACK-RTX, DTX.
//     Phase 2.
//   - Single client, single egress, single channel. No fleet
//     rotation.
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
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

	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/pkg/crypto/selfsign"
	"github.com/pion/logging"
	"github.com/pion/rtp"
	"github.com/pion/srtp/v3"
	pionturn "github.com/pion/turn/v3"
)

// SRTP-DTLS profile we use throughout. AES-128-CM-HMAC-SHA1-80 is the
// classic SRTP profile, supported by every implementation; modern
// WebRTC favors AEAD-AES-128-GCM, but for Phase 1 validation either
// works and SHA1-80 has the cleaner key-extraction layout.
const (
	dtlsSRTPProfile = dtls.SRTP_AES128_CM_HMAC_SHA1_80
	srtpProfile     = srtp.ProtectionProfileAes128CmHmacSha1_80

	// Per RFC 5764 §4.2 + RFC 5705 the EXTRACTOR-dtls_srtp output
	// for AES-128-CM-HMAC-SHA1-80 is 2*(16-byte master key + 14-byte
	// master salt) = 60 bytes, laid out as:
	//   [0:16]  client write_SRTP_master_key
	//   [16:32] server write_SRTP_master_key
	//   [32:46] client write_SRTP_master_salt
	//   [46:60] server write_SRTP_master_salt
	srtpKeyMaterialLen = 60
	srtpKeyLen         = 16
	srtpSaltLen        = 14
)

// SRTP shaping constants for Opus-audio-call profile.
const (
	channelNum       uint16 = 0x4001
	opusPayloadType  uint8  = 111
	opusSampleRate          = 48000
	opusFrameMs             = 20
	opusFrameSamples        = opusSampleRate * opusFrameMs / 1000 // 960
	packetsPerFlow          = 10
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
		secret := fs.String("secret", "lanturn-phase1-shared-secret", "static-auth-secret")
		fs.Parse(os.Args[2:])
		if err := runServer(*listen, *realm, *secret); err != nil {
			log.Fatal(err)
		}
	case "egress":
		fs := flag.NewFlagSet("egress", flag.ExitOnError)
		listen := fs.String("listen", "127.0.0.1:9999", "egress udp listen addr")
		fs.Parse(os.Args[2:])
		if err := runEgress(*listen); err != nil {
			log.Fatal(err)
		}
	case "client":
		fs := flag.NewFlagSet("client", flag.ExitOnError)
		server := fs.String("server", "127.0.0.1:3478", "TURN server")
		secret := fs.String("secret", "lanturn-phase1-shared-secret", "static-auth-secret")
		peer := fs.String("peer", "127.0.0.1:9999", "egress address")
		fs.Parse(os.Args[2:])
		if err := runClient(*server, *secret, *peer); err != nil {
			log.Fatal(err)
		}
	default:
		usage()
		os.Exit(2)
	}
}

// ----------------------------------------------------------------------------
// Server subcommand: same as Phase 0.
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
// Client subcommand: TURN allocate → DTLS handshake through relay → SRTP send.
// ----------------------------------------------------------------------------

func runClient(server, secret, peerStr string) error {
	peerIP, peerPort, err := parseHostPort(peerStr)
	if err != nil {
		return err
	}

	alloc, err := turn.Allocate(turn.AllocateConfig{
		Server:  server,
		Secret:  secret,
		CredID:  "lanturn-phase1",
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

	// Wrap the allocation as a net.Conn that yields ChannelData
	// payloads. This is the inner-layer transport on which we run DTLS.
	relay := alloc.NewRelayConn(channelNum)

	// Demux the inner-layer bytes between DTLS records and SRTP packets.
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

	log.Printf("client: starting DTLS handshake through TURN relay...")
	t0 := time.Now()
	dtlsConn, err := dtls.Client(mux.DTLSConn(), dtlsCfg)
	if err != nil {
		return fmt.Errorf("DTLS handshake: %w", err)
	}
	defer dtlsConn.Close()
	log.Printf("client: DTLS handshake OK in %s", time.Since(t0))

	profile, ok := dtlsConn.SelectedSRTPProtectionProfile()
	if !ok || profile != dtlsSRTPProfile {
		return fmt.Errorf("expected SRTP profile %d, got %d ok=%v", dtlsSRTPProfile, profile, ok)
	}
	log.Printf("client: negotiated SRTP profile: %#x (AES-128-CM-HMAC-SHA1-80)", uint16(profile))

	state := dtlsConn.ConnectionState()
	keyMat, err := state.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", nil, srtpKeyMaterialLen)
	if err != nil {
		return fmt.Errorf("export keying material: %w", err)
	}
	log.Printf("client: extracted %d bytes of SRTP keying material", len(keyMat))

	// Client is the dtls-client side, so the EXPORTED layout's "client"
	// keys are OURS for the TX direction.
	clientWriteKey, clientWriteSalt, _, _ := splitSRTPKeys(keyMat)

	txCtx, err := srtp.CreateContext(clientWriteKey, clientWriteSalt, srtpProfile)
	if err != nil {
		return fmt.Errorf("create SRTP TX context: %w", err)
	}
	log.Printf("client: SRTP TX context ready, sending %d Opus-shaped packets...", packetsPerFlow)

	ssrc := randUint32()
	startTS := randUint32()
	startSeq := uint16(randUint32() & 0xFFFF)

	for i := 0; i < packetsPerFlow; i++ {
		// Build a fake-Opus payload: 100-200 bytes randomly varying
		// (real Opus at 64kbps over 20ms frames is ~160 bytes).
		payloadLen := 100 + (int(randUint32()) % 80)
		payload := make([]byte, payloadLen)
		rand.Read(payload)

		pkt := &rtp.Packet{
			Header: rtp.Header{
				Version:        2,
				PayloadType:    opusPayloadType,
				SequenceNumber: startSeq + uint16(i),
				Timestamp:      startTS + uint32(i*opusFrameSamples),
				SSRC:           ssrc,
			},
			Payload: payload,
		}
		raw, err := pkt.Marshal()
		if err != nil {
			return fmt.Errorf("marshal RTP[%d]: %w", i, err)
		}
		// Encrypt → produces SRTP packet bytes.
		encrypted, err := txCtx.EncryptRTP(nil, raw, nil)
		if err != nil {
			return fmt.Errorf("encrypt RTP[%d]: %w", i, err)
		}
		// Send via mux underlying (bypassing dtls.Conn — SRTP is
		// outside the DTLS-encryption path post-handshake).
		if _, err := mux.WriteSRTP(encrypted); err != nil {
			return fmt.Errorf("send SRTP[%d]: %w", i, err)
		}
		log.Printf("client: SRTP[%d] >>> seq=%d ts=%d ssrc=%#x %dB (encrypted=%dB) leading=%#02x",
			i, pkt.SequenceNumber, pkt.Timestamp, pkt.SSRC,
			len(payload), len(encrypted), encrypted[0])
		time.Sleep(time.Duration(opusFrameMs) * time.Millisecond)
	}
	log.Printf("client: all %d SRTP packets sent; phase 1 client run complete.", packetsPerFlow)

	// Brief grace period so the egress can drain before we close.
	time.Sleep(500 * time.Millisecond)
	return nil
}

// ----------------------------------------------------------------------------
// Egress subcommand: raw UDP listener → DTLS server → SRTP receiver.
// ----------------------------------------------------------------------------

func runEgress(listen string) error {
	pc, err := net.ListenPacket("udp", listen)
	if err != nil {
		return fmt.Errorf("listen UDP %s: %w", listen, err)
	}
	log.Printf("egress: listening on %s, waiting for first packet...", listen)

	buf := make([]byte, 4096)
	pc.SetReadDeadline(time.Time{})
	n, srcAddr, err := pc.ReadFrom(buf)
	if err != nil {
		return fmt.Errorf("read first packet: %w", err)
	}
	log.Printf("egress: first packet from %s (%dB, leading=%#02x)", srcAddr, n, buf[0])

	// Wrap the raw UDP listener as a single-source net.Conn for
	// the duration of this session.
	ssconn := &singleSourceConn{
		pc:         pc,
		remoteAddr: srcAddr,
		firstPkt:   append([]byte{}, buf[:n]...),
	}
	mux := newPacketMux(ssconn, "egress")
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
	log.Printf("egress: starting DTLS server handshake...")
	t0 := time.Now()
	dtlsConn, err := dtls.Server(mux.DTLSConn(), dtlsCfg)
	if err != nil {
		return fmt.Errorf("DTLS server: %w", err)
	}
	defer dtlsConn.Close()
	log.Printf("egress: DTLS handshake OK in %s", time.Since(t0))

	profile, ok := dtlsConn.SelectedSRTPProtectionProfile()
	if !ok {
		return fmt.Errorf("no SRTP profile negotiated")
	}
	log.Printf("egress: negotiated SRTP profile: %#x", uint16(profile))

	state := dtlsConn.ConnectionState()
	keyMat, err := state.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", nil, srtpKeyMaterialLen)
	if err != nil {
		return fmt.Errorf("export keying material: %w", err)
	}
	log.Printf("egress: extracted %d bytes of SRTP keying material", len(keyMat))

	// Egress is the dtls-server side, so the EXPORTED layout's
	// "client" keys are the PEER's TX → our RX direction.
	clientWriteKey, clientWriteSalt, _, _ := splitSRTPKeys(keyMat)

	rxCtx, err := srtp.CreateContext(clientWriteKey, clientWriteSalt, srtpProfile)
	if err != nil {
		return fmt.Errorf("create SRTP RX context: %w", err)
	}
	log.Printf("egress: SRTP RX context ready, listening for packets...")

	rxBuf := make([]byte, 4096)
	for i := 0; i < packetsPerFlow; i++ {
		mux.srtpReadDeadline(time.Now().Add(5 * time.Second))
		n, err := mux.ReadSRTP(rxBuf)
		if err != nil {
			return fmt.Errorf("read SRTP[%d]: %w", i, err)
		}
		// Decrypt SRTP packet.
		decrypted, err := rxCtx.DecryptRTP(nil, rxBuf[:n], nil)
		if err != nil {
			return fmt.Errorf("decrypt SRTP[%d]: %w", i, err)
		}
		// Parse the RTP header to verify shape.
		pkt := &rtp.Packet{}
		if err := pkt.Unmarshal(decrypted); err != nil {
			return fmt.Errorf("unmarshal RTP[%d]: %w", i, err)
		}
		log.Printf("egress: SRTP[%d] <<< seq=%d ts=%d ssrc=%#x PT=%d payload=%dB (encrypted=%dB)",
			i, pkt.SequenceNumber, pkt.Timestamp, pkt.SSRC, pkt.PayloadType, len(pkt.Payload), n)
	}
	log.Printf("egress: received all %d SRTP packets; phase 1 egress run complete.", packetsPerFlow)
	return nil
}

// ----------------------------------------------------------------------------
// packetMux — demuxes raw inner-layer bytes between DTLS records and
// SRTP/SRTCP packets by leading-byte inspection. Real WebRTC stacks
// have this same layer baked in (in pion it's pion/transport/v3/mux);
// we hand-roll a minimal version for the spike.
//
// Demux rules from RFC 5764 §5:
//   - 0x00-0x13 (decimal 0-19) = STUN (unused post-handshake here)
//   - 0x14-0x19 (decimal 20-25) = DTLS records
//   - 0x80-0xBF (decimal 128-191) = RTP/RTCP (RTP version 2)
//
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

// DTLSConn returns a net.Conn used by pion/dtls. Its Read returns
// the next DTLS-classified packet; Write goes straight to the
// underlying transport.
func (m *packetMux) DTLSConn() net.Conn {
	return &muxedConn{mux: m, ch: m.dtlsCh}
}

// WriteSRTP sends an SRTP packet on the underlying.
func (m *packetMux) WriteSRTP(p []byte) (int, error) {
	return m.underlying.Write(p)
}

// ReadSRTP returns the next SRTP-classified packet.
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

// muxedConn is the net.Conn wrapper handed to pion/dtls. Reads come
// from the mux's classified channel; writes pass through to the
// underlying transport.
type muxedConn struct {
	mux *packetMux
	ch  chan []byte

	rdDeadlineMu sync.Mutex
	rdDeadline   time.Time
}

func (c *muxedConn) Read(p []byte) (int, error) {
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
		return copy(p, pkt), nil
	case <-deadline:
		return 0, fmt.Errorf("read deadline exceeded")
	case <-c.mux.closed:
		return 0, io.EOF
	}
}

func (c *muxedConn) Write(p []byte) (int, error) {
	return c.mux.underlying.Write(p)
}

func (c *muxedConn) Close() error                 { return c.mux.Close() }
func (c *muxedConn) LocalAddr() net.Addr          { return dummyAddr{} }
func (c *muxedConn) RemoteAddr() net.Addr         { return dummyAddr{} }
func (c *muxedConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return nil
}
func (c *muxedConn) SetReadDeadline(t time.Time) error {
	c.rdDeadlineMu.Lock()
	defer c.rdDeadlineMu.Unlock()
	c.rdDeadline = t
	return nil
}
func (c *muxedConn) SetWriteDeadline(t time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "muxed" }
func (dummyAddr) String() string  { return "muxed" }

// ----------------------------------------------------------------------------
// singleSourceConn — wrap a packet listener as a net.Conn pinned to one peer.
// The first packet that arrived (passed in) is replayed on the first Read.
// ----------------------------------------------------------------------------

type singleSourceConn struct {
	pc         net.PacketConn
	remoteAddr net.Addr

	mu       sync.Mutex
	firstPkt []byte
	consumed bool
}

func (c *singleSourceConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if !c.consumed && len(c.firstPkt) > 0 {
		n := copy(p, c.firstPkt)
		c.consumed = true
		c.mu.Unlock()
		return n, nil
	}
	c.mu.Unlock()

	for {
		buf := make([]byte, 4096)
		n, addr, err := c.pc.ReadFrom(buf)
		if err != nil {
			return 0, err
		}
		if addr.String() != c.remoteAddr.String() {
			continue
		}
		return copy(p, buf[:n]), nil
	}
}

func (c *singleSourceConn) Write(p []byte) (int, error) {
	return c.pc.WriteTo(p, c.remoteAddr)
}

func (c *singleSourceConn) Close() error                       { return c.pc.Close() }
func (c *singleSourceConn) LocalAddr() net.Addr                { return c.pc.LocalAddr() }
func (c *singleSourceConn) RemoteAddr() net.Addr               { return c.remoteAddr }
func (c *singleSourceConn) SetDeadline(t time.Time) error      { return c.pc.SetDeadline(t) }
func (c *singleSourceConn) SetReadDeadline(t time.Time) error  { return c.pc.SetReadDeadline(t) }
func (c *singleSourceConn) SetWriteDeadline(t time.Time) error { return c.pc.SetWriteDeadline(t) }

// ----------------------------------------------------------------------------
// SRTP key extraction layout (RFC 5764 §4.2).
// ----------------------------------------------------------------------------

func splitSRTPKeys(keyMat []byte) (clientKey, clientSalt, serverKey, serverSalt []byte) {
	if len(keyMat) != srtpKeyMaterialLen {
		panic(fmt.Sprintf("expected %d bytes of keying material, got %d", srtpKeyMaterialLen, len(keyMat)))
	}
	clientKey = keyMat[0:srtpKeyLen]
	serverKey = keyMat[srtpKeyLen : 2*srtpKeyLen]
	clientSalt = keyMat[2*srtpKeyLen : 2*srtpKeyLen+srtpSaltLen]
	serverSalt = keyMat[2*srtpKeyLen+srtpSaltLen : 2*srtpKeyLen+2*srtpSaltLen]
	return
}

// ----------------------------------------------------------------------------
// helpers
// ----------------------------------------------------------------------------

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

func usage() {
	fmt.Fprintf(os.Stderr, `lanturn-phase1 — DTLS-through-TURN-relay + SRTP shaping spike.

Subcommands:

  lanturn-phase1 server [-listen 0.0.0.0:3478] [-realm STR] [-secret STR]
      TURN server (same as Phase 0).

  lanturn-phase1 egress [-listen 127.0.0.1:9999]
      Raw UDP listener → DTLS server → SRTP receiver.

  lanturn-phase1 client [-server HOST:PORT] [-secret STR] [-peer HOST:PORT]
      TURN allocate → ChannelBind → DTLS handshake through relay → send N
      Opus-shaped SRTP packets.

Quick start:

  go build -o /tmp/lanturn-phase1 ./cmd/lanturn-phase1
  /tmp/lanturn-phase1 server  &
  /tmp/lanturn-phase1 egress  &
  /tmp/lanturn-phase1 client

`)
	_ = hex.Dump // silence import if encodings move
}
