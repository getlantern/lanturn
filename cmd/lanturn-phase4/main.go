// lanturn-phase4 — Phase 4 spike: TURNS-on-5349 fallback + outer-wire
// transport-abstraction.
//
// Phase 4 narrows scope to the OUTER TURN transport. Phases 1-3 already
// validate the inner DTLS-SRTP layer through the TURN relay; that layer
// is unchanged here because coturn forwards inner-payload bytes
// opaquely regardless of whether the client↔coturn leg is plain UDP/3478
// or TLS-wrapped TCP/5349. So this spike specifically demonstrates:
//
//   - coturn server now listens on BOTH UDP/3478 (plain) and TCP/5349
//     (TLS-wrapped, TURNS).
//   - Client supports both transports: tlsAllocation does the same
//     RFC 8489 STUN dance over a tls.Conn instead of a UDP socket,
//     framing STUN messages with their built-in length field (each
//     STUN msg is self-delimiting; ChannelData on TCP is 4-byte
//     length-prefixed and 4-byte aligned per RFC 8656 §12.4).
//   - Fallback policy: client tries UDP/3478 first with a short
//     timeout; if Allocate fails, it falls over to TCP/5349 TLS.
//   - The egress side is unchanged from Phases 1-3 — coturn's relay
//     emits UDP to the egress regardless of inbound transport.
//
// Inner DTLS-SRTP + behavioral mimicry from Phases 1-3 is NOT re-
// implemented here (would be the same code). Lantern production
// composes Phase 4 (outer transport choice) with Phase 1-3 inner stack.
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/getlantern/lanturn/internal/stun"
	"github.com/getlantern/lanturn/internal/turn"

	"github.com/pion/dtls/v3/pkg/crypto/selfsign"
	"github.com/pion/logging"
	pionturn "github.com/pion/turn/v3"
)

const channelNum uint16 = 0x4001

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "server":
		fs := flag.NewFlagSet("server", flag.ExitOnError)
		udpListen := fs.String("udp-listen", "0.0.0.0:3478", "plain TURN UDP listen addr")
		tlsListen := fs.String("tls-listen", "0.0.0.0:5349", "TURNS TCP+TLS listen addr")
		realm := fs.String("realm", "lanturn.example", "TURN realm")
		secret := fs.String("secret", "lanturn-phase4-shared-secret", "static-auth-secret")
		fs.Parse(os.Args[2:])
		if err := runServer(*udpListen, *tlsListen, *realm, *secret); err != nil {
			log.Fatal(err)
		}
	case "egress":
		fs := flag.NewFlagSet("egress", flag.ExitOnError)
		listen := fs.String("listen", "127.0.0.1:9999", "egress udp listen addr")
		count := fs.Int("count", 5, "number of ChannelData frames to receive before exiting")
		fs.Parse(os.Args[2:])
		if err := runEgress(*listen, *count); err != nil {
			log.Fatal(err)
		}
	case "client":
		fs := flag.NewFlagSet("client", flag.ExitOnError)
		udpServer := fs.String("udp-server", "127.0.0.1:3478", "plain TURN UDP endpoint")
		tlsServer := fs.String("tls-server", "127.0.0.1:5349", "TURNS TCP+TLS endpoint")
		secret := fs.String("secret", "lanturn-phase4-shared-secret", "static-auth-secret")
		peer := fs.String("peer", "127.0.0.1:9999", "egress address")
		force := fs.String("force", "", "force a transport: udp | tls (default: try udp first, fall back to tls)")
		udpTimeout := fs.Duration("udp-timeout", 1*time.Second, "UDP allocate timeout before falling back to TLS")
		fs.Parse(os.Args[2:])
		if err := runClient(*udpServer, *tlsServer, *secret, *peer, *force, *udpTimeout); err != nil {
			log.Fatal(err)
		}
	default:
		usage()
		os.Exit(2)
	}
}

// ----------------------------------------------------------------------------
// Server: UDP/3478 plain + TCP/5349 TURNS (TLS-wrapped)
// ----------------------------------------------------------------------------

func runServer(udpListen, tlsListen, realm, secret string) error {
	host, _, err := net.SplitHostPort(udpListen)
	if err != nil {
		return err
	}
	if host == "" {
		host = "0.0.0.0"
	}

	udpListener, err := net.ListenPacket("udp4", udpListen)
	if err != nil {
		return fmt.Errorf("listen UDP %s: %w", udpListen, err)
	}

	tcpListener, err := net.Listen("tcp4", tlsListen)
	if err != nil {
		return fmt.Errorf("listen TCP %s: %w", tlsListen, err)
	}

	cert, err := selfsign.GenerateSelfSignedWithDNS("lanturn.test", "127.0.0.1")
	if err != nil {
		return fmt.Errorf("self-signed cert: %w", err)
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	tlsListener := tls.NewListener(tcpListener, tlsCfg)

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
		ListenerConfigs: []pionturn.ListenerConfig{
			{
				Listener: tlsListener,
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
	log.Printf("TURN server: plain UDP/%s + TURNS TCP+TLS/%s (realm=%s public-ip=%s)",
		udpListen, tlsListen, realm, pubIP)
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
		log.Printf("server auth: %s OK (transport=%s)", username, srcAddr.Network())
		return stun.LongTermKey(username, realm, password), true
	}
}

// ----------------------------------------------------------------------------
// Egress: receives UDP packets from coturn's relay regardless of
// whether client→coturn was UDP or TLS.
// ----------------------------------------------------------------------------

func runEgress(listen string, count int) error {
	pc, err := net.ListenPacket("udp", listen)
	if err != nil {
		return fmt.Errorf("listen UDP %s: %w", listen, err)
	}
	defer pc.Close()
	log.Printf("egress: listening on %s, expecting %d ChannelData frames", listen, count)

	buf := make([]byte, 4096)
	for i := 0; i < count; i++ {
		pc.SetReadDeadline(time.Now().Add(15 * time.Second))
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return fmt.Errorf("read pkt %d: %w", i, err)
		}
		log.Printf("egress: frame[%d] from %s — %dB leading=%#02x", i, addr, n, buf[0])
	}
	return nil
}

// ----------------------------------------------------------------------------
// Client: try UDP first, fall back to TLS on Allocate failure.
// ----------------------------------------------------------------------------

func runClient(udpServer, tlsServer, secret, peerStr, force string, udpTimeout time.Duration) error {
	peerIP, peerPort, err := parseHostPort(peerStr)
	if err != nil {
		return err
	}

	switch strings.ToLower(force) {
	case "tls":
		log.Printf("client: forced TLS path")
		return tryTLSClient(tlsServer, secret, peerIP, peerPort)
	case "udp":
		log.Printf("client: forced UDP path")
		return tryUDPClient(udpServer, secret, peerIP, peerPort, udpTimeout)
	case "":
		log.Printf("client: trying UDP/3478 first (timeout %s)...", udpTimeout)
		err := tryUDPClient(udpServer, secret, peerIP, peerPort, udpTimeout)
		if err == nil {
			return nil
		}
		log.Printf("client: UDP failed (%v), falling back to TLS/5349", err)
		return tryTLSClient(tlsServer, secret, peerIP, peerPort)
	default:
		return fmt.Errorf("unknown -force value %q (want: udp | tls)", force)
	}
}

func tryUDPClient(server, secret string, peerIP net.IP, peerPort int, timeout time.Duration) error {
	type result struct{ err error }
	ch := make(chan result, 1)
	go func() {
		alloc, err := turn.Allocate(turn.AllocateConfig{
			Server:  server,
			Secret:  secret,
			CredID:  "lanturn-phase4-udp",
			CredTTL: 30 * time.Second,
			Logf:    log.Printf,
		})
		if err != nil {
			ch <- result{err}
			return
		}
		defer alloc.UDP.Close()
		if err := alloc.CreatePermission(peerIP, peerPort); err != nil {
			ch <- result{err}
			return
		}
		if err := alloc.ChannelBind(channelNum, peerIP, peerPort); err != nil {
			ch <- result{err}
			return
		}
		log.Printf("client[UDP]: TURN OK (channel=%#04x peer=%s:%d)", channelNum, peerIP, peerPort)
		relay := alloc.NewRelayConn(channelNum)
		for i := 0; i < 5; i++ {
			pl := make([]byte, 80+i*20)
			rand.Read(pl)
			if _, err := relay.Write(pl); err != nil {
				ch <- result{err}
				return
			}
			log.Printf("client[UDP]: ChannelData[%d] >>> %dB", i, len(pl))
			time.Sleep(50 * time.Millisecond)
		}
		ch <- result{nil}
	}()
	select {
	case r := <-ch:
		return r.err
	case <-time.After(timeout):
		return fmt.Errorf("UDP timeout after %s", timeout)
	}
}

// ----------------------------------------------------------------------------
// TLS-TURN client (Phase 4 new)
// ----------------------------------------------------------------------------

func tryTLSClient(server, secret string, peerIP net.IP, peerPort int) error {
	conn, err := tls.Dial("tcp", server, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return fmt.Errorf("tls dial: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	alloc, err := allocateTLS(conn, secret, "lanturn-phase4-tls", 30*time.Second)
	if err != nil {
		return fmt.Errorf("TLS allocate: %w", err)
	}
	log.Printf("client[TLS]: ALLOCATED relay address %s:%d", alloc.relayedIP, alloc.relayedPort)

	if err := alloc.createPermission(peerIP, peerPort); err != nil {
		return fmt.Errorf("TLS CreatePerm: %w", err)
	}
	if err := alloc.channelBind(channelNum, peerIP, peerPort); err != nil {
		return fmt.Errorf("TLS ChannelBind: %w", err)
	}
	log.Printf("client[TLS]: TURN OK (channel=%#04x peer=%s:%d)", channelNum, peerIP, peerPort)

	for i := 0; i < 5; i++ {
		pl := make([]byte, 80+i*20)
		rand.Read(pl)
		if err := alloc.sendChannelData(channelNum, pl); err != nil {
			return fmt.Errorf("ChannelData[%d]: %w", i, err)
		}
		log.Printf("client[TLS]: ChannelData[%d] >>> %dB (over TLS)", i, len(pl))
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}

// tlsAllocation mirrors internal/turn.Allocation but over a tls.Conn.
// STUN messages are self-framed by their header length field; ChannelData
// over TCP is 4-byte length-prefixed and 4-byte aligned (RFC 8656 §12.4).
type tlsAllocation struct {
	conn        *tls.Conn
	relayedIP   net.IP
	relayedPort int
	username    string
	realm       string
	nonce       []byte
	key         []byte
}

func allocateTLS(conn *tls.Conn, secret, credID string, credTTL time.Duration) (*tlsAllocation, error) {
	// Step 1: Allocate without creds — expect 401 with REALM + NONCE.
	req := stun.NewRequest(stun.MsgAllocateRequest)
	req.AddAttr(stun.AttrRequestedTransport, []byte{stun.RequestedTransportUDP, 0, 0, 0})
	wire := req.Encode(nil, true)
	if _, err := conn.Write(wire); err != nil {
		return nil, fmt.Errorf("write Allocate-noauth: %w", err)
	}
	resp, err := readSTUNFromStream(conn)
	if err != nil {
		return nil, fmt.Errorf("read Allocate-noauth response: %w", err)
	}
	if resp.Type != stun.MsgAllocateError {
		return nil, fmt.Errorf("expected AllocateError, got %#04x", resp.Type)
	}
	realm, _ := resp.Attr(stun.AttrRealm)
	nonce, _ := resp.Attr(stun.AttrNonce)
	if realm == nil || nonce == nil {
		return nil, fmt.Errorf("AllocateError missing REALM/NONCE")
	}

	// Step 2: Allocate with creds.
	username, password := stun.OAuthCreds(secret, credID, credTTL)
	log.Printf("client[TLS]: OAUTH creds USERNAME=%q", username)
	key := stun.LongTermKey(username, string(realm), password)

	req = stun.NewRequest(stun.MsgAllocateRequest)
	req.AddAttr(stun.AttrRequestedTransport, []byte{stun.RequestedTransportUDP, 0, 0, 0})
	req.AddAttr(stun.AttrUsername, []byte(username))
	req.AddAttr(stun.AttrRealm, realm)
	req.AddAttr(stun.AttrNonce, nonce)
	lifetime := make([]byte, 4)
	binary.BigEndian.PutUint32(lifetime, 600)
	req.AddAttr(stun.AttrLifetime, lifetime)
	wire = req.Encode(key, true)
	if _, err := conn.Write(wire); err != nil {
		return nil, fmt.Errorf("write Allocate-creds: %w", err)
	}
	resp, err = readSTUNFromStream(conn)
	if err != nil {
		return nil, fmt.Errorf("read Allocate-creds response: %w", err)
	}
	if resp.Type != stun.MsgAllocateResponse {
		errBody, _ := resp.Attr(stun.AttrErrorCode)
		ec := stun.DecodeErrorCode(errBody)
		return nil, fmt.Errorf("Allocate failed: %d %s", ec.Class*100+ec.Number, ec.Reason)
	}
	relayedBody, ok := resp.Attr(stun.AttrXORRelayedAddress)
	if !ok {
		return nil, fmt.Errorf("Allocate response missing XOR-RELAYED-ADDRESS")
	}
	relayIP, relayPort, err := stun.DecodeXORAddr(relayedBody)
	if err != nil {
		return nil, fmt.Errorf("decode xor-relayed-address: %w", err)
	}

	return &tlsAllocation{
		conn:        conn,
		relayedIP:   relayIP,
		relayedPort: relayPort,
		username:    username,
		realm:       string(realm),
		nonce:       nonce,
		key:         key,
	}, nil
}

func (a *tlsAllocation) createPermission(peerIP net.IP, peerPort int) error {
	req := stun.NewRequest(stun.MsgCreatePermRequest)
	req.AddAttr(stun.AttrXORPeerAddress, stun.EncodeXORAddr(peerIP, peerPort))
	req.AddAttr(stun.AttrUsername, []byte(a.username))
	req.AddAttr(stun.AttrRealm, []byte(a.realm))
	req.AddAttr(stun.AttrNonce, a.nonce)
	wire := req.Encode(a.key, true)
	if _, err := a.conn.Write(wire); err != nil {
		return err
	}
	resp, err := readSTUNFromStream(a.conn)
	if err != nil {
		return err
	}
	if resp.Type != stun.MsgCreatePermResponse {
		errBody, _ := resp.Attr(stun.AttrErrorCode)
		ec := stun.DecodeErrorCode(errBody)
		return fmt.Errorf("CreatePerm failed: %d %s", ec.Class*100+ec.Number, ec.Reason)
	}
	return nil
}

func (a *tlsAllocation) channelBind(channel uint16, peerIP net.IP, peerPort int) error {
	if channel < 0x4000 || channel > 0x7FFF {
		return fmt.Errorf("channel %#x out of range", channel)
	}
	req := stun.NewRequest(stun.MsgChannelBindRequest)
	chBody := make([]byte, 4)
	binary.BigEndian.PutUint16(chBody[0:2], channel)
	req.AddAttr(stun.AttrChannelNumber, chBody)
	req.AddAttr(stun.AttrXORPeerAddress, stun.EncodeXORAddr(peerIP, peerPort))
	req.AddAttr(stun.AttrUsername, []byte(a.username))
	req.AddAttr(stun.AttrRealm, []byte(a.realm))
	req.AddAttr(stun.AttrNonce, a.nonce)
	wire := req.Encode(a.key, true)
	if _, err := a.conn.Write(wire); err != nil {
		return err
	}
	resp, err := readSTUNFromStream(a.conn)
	if err != nil {
		return err
	}
	if resp.Type != stun.MsgChannelBindResponse {
		errBody, _ := resp.Attr(stun.AttrErrorCode)
		ec := stun.DecodeErrorCode(errBody)
		return fmt.Errorf("ChannelBind failed: %d %s", ec.Class*100+ec.Number, ec.Reason)
	}
	return nil
}

// sendChannelData writes a ChannelData frame with 4-byte alignment
// padding (RFC 8656 §12.4 mandatory on TCP).
func (a *tlsAllocation) sendChannelData(channel uint16, payload []byte) error {
	if len(payload) > 65535-4 {
		return fmt.Errorf("payload %d > max", len(payload))
	}
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint16(frame[0:2], channel)
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(payload)))
	copy(frame[4:], payload)
	if pad := (4 - len(frame)%4) % 4; pad > 0 {
		frame = append(frame, make([]byte, pad)...)
	}
	_, err := a.conn.Write(frame)
	return err
}

// ----------------------------------------------------------------------------
// Stream-framed STUN reader
// ----------------------------------------------------------------------------

// readSTUNFromStream reads exactly one STUN message from a stream.
// STUN messages are self-delimiting via the 16-bit length field at
// header offset 2-3.
func readSTUNFromStream(r io.Reader) (*stun.Message, error) {
	hdr := make([]byte, 20)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, fmt.Errorf("read header: %w", err)
	}
	declaredLen := int(binary.BigEndian.Uint16(hdr[2:4]))
	body := make([]byte, declaredLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("read body (%dB): %w", declaredLen, err)
	}
	full := make([]byte, 0, 20+declaredLen)
	full = append(full, hdr...)
	full = append(full, body...)
	return stun.Decode(full)
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

func usage() {
	fmt.Fprintf(os.Stderr, `lanturn-phase4 — TURNS-on-5349 fallback spike.

Subcommands:

  lanturn-phase4 server [-udp-listen 0.0.0.0:3478] [-tls-listen 0.0.0.0:5349]
                        [-realm STR] [-secret STR]
      Spin up a coturn-equivalent listening on BOTH plain UDP/3478
      and TURNS TCP+TLS/5349 (self-signed cert).

  lanturn-phase4 egress [-listen 127.0.0.1:9999] [-count 5]
      Receives ChannelData frames from coturn's relay (UDP).

  lanturn-phase4 client [-udp-server H:P] [-tls-server H:P]
                        [-secret STR] [-peer H:P]
                        [-force udp|tls] [-udp-timeout 1s]
      Default: try UDP first; on failure fall back to TLS.
`)
}
