// lanturn-phase0 — Phase 0 validation spike for the lanturn
// circumvention transport design (see
// circumvention-corpus-private text/2026-05-lanturn-design.md).
//
// What this binary does:
//
//   - subcommand "server": spin up a local TURN test server
//     (using pion/turn, which is fine for server-side TURN —
//     the design's anti-pion rule is specifically for the
//     CLIENT-side DTLS handshake, not the TURN protocol
//     bytes themselves)
//
//   - subcommand "client": hand-rolled RFC 8489 STUN message
//     encoder/decoder + RFC 8656 TURN allocate / channel-bind
//     / channel-data flow. No third-party STUN/TURN library
//     on the client side — we want to KNOW the bytes that
//     hit the wire match the catalog claims byte-for-byte.
//
// Phase 0 wire-format claims to validate:
//
//   1. STUN magic cookie 0x2112A442 at offset 4 of every
//      STUN message (RFC 8489 §6).
//   2. ChannelData channel-number range 0x4000-0x7FFF
//      (RFC 8656 §12) — distinct from STUN's leading
//      0b00 bits at the type field.
//   3. FINGERPRINT attribute (RFC 8489 §14.7) with the XOR
//      constant 0x5354554e ("STUN" in ASCII).
//   4. 401-NONCE-then-credentials Allocate dance with
//      MESSAGE-INTEGRITY computed via HMAC-SHA1 over the
//      message-up-to-but-not-including the integrity attribute,
//      keyed with `MD5(USERNAME ":" REALM ":" PASSWORD)`
//      (RFC 8489 §14.5 long-term credential mechanism).
//   5. OAUTH-shaped (coturn use-auth-secret / Twilio NTS)
//      ephemeral creds: USERNAME = "<unix_ts>:<random_id>",
//      PASSWORD = base64(HMAC-SHA1(shared_secret, USERNAME)).
//
// After running the client, capture the dance with
// `tshark -i lo -d udp.port==3478,stun -V port 3478` and
// inspect against §4.4 of the design doc.
package main

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"hash/crc32"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/pion/logging"
	"github.com/pion/turn/v3"
)

// ----------------------------------------------------------------------------
// RFC 8489 / RFC 8656 wire-format constants
// ----------------------------------------------------------------------------

const stunMagicCookie uint32 = 0x2112A442
const fingerprintXOR uint32 = 0x5354554e // "STUN" in ASCII; RFC 8489 §14.7

// STUN message types (class+method packed into 14 bits).
const (
	msgAllocateRequest     = 0x0003
	msgAllocateResponse    = 0x0103
	msgAllocateError       = 0x0113
	msgRefreshRequest      = 0x0004
	msgRefreshResponse     = 0x0104
	msgCreatePermRequest   = 0x0008
	msgCreatePermResponse  = 0x0108
	msgCreatePermError     = 0x0118
	msgChannelBindRequest  = 0x0009
	msgChannelBindResponse = 0x0109
	msgChannelBindError    = 0x0119
)

// STUN attribute types.
const (
	attrMappedAddress      = 0x0001
	attrUsername           = 0x0006
	attrMessageIntegrity   = 0x0008
	attrErrorCode          = 0x0009
	attrUnknownAttributes  = 0x000a
	attrRealm              = 0x0014
	attrNonce              = 0x0015
	attrXORMappedAddress   = 0x0020
	attrChannelNumber      = 0x000c
	attrLifetime           = 0x000d
	attrXORPeerAddress     = 0x0012
	attrData               = 0x0013
	attrXORRelayedAddress  = 0x0016
	attrRequestedTransport = 0x0019
	attrSoftware           = 0x8022
	attrAlternateServer    = 0x8023
	attrFingerprint        = 0x8028
)

// REQUESTED-TRANSPORT protocol values (RFC 8656 §14.7).
const (
	requestedTransportUDP = 17
	requestedTransportTCP = 6
)

// ----------------------------------------------------------------------------
// STUN message encoding (hand-rolled)
// ----------------------------------------------------------------------------

type stunMessage struct {
	msgType uint16
	txid    [12]byte
	attrs   []stunAttribute
}

type stunAttribute struct {
	typ  uint16
	body []byte
}

func newRequest(msgType uint16) *stunMessage {
	m := &stunMessage{msgType: msgType}
	if _, err := rand.Read(m.txid[:]); err != nil {
		panic(err)
	}
	return m
}

func (m *stunMessage) addAttr(typ uint16, body []byte) {
	m.attrs = append(m.attrs, stunAttribute{typ: typ, body: body})
}

// Encode produces the wire bytes. If withMessageIntegrity is set,
// it's the long-term-credential password (already MD5'd into a key
// or in our use-auth-secret case the HMAC-SHA1 raw key); the
// MESSAGE-INTEGRITY attribute gets appended automatically.
// If withFingerprint, FINGERPRINT is appended last.
func (m *stunMessage) Encode(integrityKey []byte, withFingerprint bool) []byte {
	// Pass 1: layout attributes that go before MESSAGE-INTEGRITY.
	attrBuf := encodeAttrs(m.attrs)

	// If we're adding MESSAGE-INTEGRITY, fix up the length to
	// include the integrity attribute (4-byte attr header + 20
	// bytes HMAC-SHA1) and then later FINGERPRINT (4-byte attr
	// header + 4-byte CRC32) if present.
	addedLen := 0
	if integrityKey != nil {
		addedLen += 4 + 20
	}
	if withFingerprint {
		addedLen += 4 + 4
	}

	// Header: type (2B) | length (2B) | magic (4B) | txid (12B).
	// length is the message length AFTER the 20-byte header
	// (RFC 8489 §5).
	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header[0:2], m.msgType)
	binary.BigEndian.PutUint16(header[2:4], uint16(len(attrBuf)+addedLen))
	binary.BigEndian.PutUint32(header[4:8], stunMagicCookie)
	copy(header[8:20], m.txid[:])

	// MESSAGE-INTEGRITY computation: HMAC-SHA1 over header + attrs
	// with the length field set to "what the length would be if
	// MESSAGE-INTEGRITY were present" (RFC 8489 §14.5).
	if integrityKey != nil {
		// length-for-integrity-computation is up through the integrity
		// attribute, EXCLUDING any subsequent FINGERPRINT.
		intLen := len(attrBuf) + 4 + 20
		binary.BigEndian.PutUint16(header[2:4], uint16(intLen))

		mac := hmac.New(sha1.New, integrityKey)
		mac.Write(header)
		mac.Write(attrBuf)
		integrity := mac.Sum(nil)

		// Append integrity attr to attrBuf.
		intAttr := encodeAttr(attrMessageIntegrity, integrity)
		attrBuf = append(attrBuf, intAttr...)

		// Restore final length (now including FINGERPRINT if any).
		binary.BigEndian.PutUint16(header[2:4], uint16(len(attrBuf)+(addedLen-4-20)))
	}

	if withFingerprint {
		// CRC32 over header + attrs, XOR'd with fingerprintXOR.
		// Length field must reflect the final length (RFC 8489 §14.7).
		buf := append([]byte{}, header...)
		buf = append(buf, attrBuf...)
		crc := crc32.ChecksumIEEE(buf) ^ fingerprintXOR
		fpBody := make([]byte, 4)
		binary.BigEndian.PutUint32(fpBody, crc)
		fpAttr := encodeAttr(attrFingerprint, fpBody)
		attrBuf = append(attrBuf, fpAttr...)
	}

	return append(header, attrBuf...)
}

func encodeAttrs(attrs []stunAttribute) []byte {
	var out []byte
	for _, a := range attrs {
		out = append(out, encodeAttr(a.typ, a.body)...)
	}
	return out
}

func encodeAttr(typ uint16, body []byte) []byte {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint16(hdr[0:2], typ)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(body)))
	out := append(hdr, body...)
	// Pad to 4-byte alignment (RFC 8489 §14).
	pad := (4 - len(body)%4) % 4
	if pad > 0 {
		out = append(out, make([]byte, pad)...)
	}
	return out
}

// Decode parses the wire bytes into a stunMessage.
// Returns the message and the list of attributes including
// any MESSAGE-INTEGRITY / FINGERPRINT we want to inspect.
func Decode(buf []byte) (*stunMessage, error) {
	if len(buf) < 20 {
		return nil, fmt.Errorf("short STUN message: %dB", len(buf))
	}
	if binary.BigEndian.Uint32(buf[4:8]) != stunMagicCookie {
		return nil, fmt.Errorf("bad magic cookie: %#x", binary.BigEndian.Uint32(buf[4:8]))
	}
	m := &stunMessage{
		msgType: binary.BigEndian.Uint16(buf[0:2]),
	}
	copy(m.txid[:], buf[8:20])

	declaredLen := int(binary.BigEndian.Uint16(buf[2:4]))
	if 20+declaredLen > len(buf) {
		return nil, fmt.Errorf("declared length %d exceeds buffer %d", declaredLen, len(buf)-20)
	}

	pos := 20
	for pos < 20+declaredLen {
		if pos+4 > len(buf) {
			return nil, fmt.Errorf("truncated attribute at pos %d", pos)
		}
		atyp := binary.BigEndian.Uint16(buf[pos : pos+2])
		alen := int(binary.BigEndian.Uint16(buf[pos+2 : pos+4]))
		if pos+4+alen > len(buf) {
			return nil, fmt.Errorf("attribute body extends past message")
		}
		body := make([]byte, alen)
		copy(body, buf[pos+4:pos+4+alen])
		m.attrs = append(m.attrs, stunAttribute{typ: atyp, body: body})
		pad := (4 - alen%4) % 4
		pos += 4 + alen + pad
	}
	return m, nil
}

func (m *stunMessage) attr(typ uint16) ([]byte, bool) {
	for _, a := range m.attrs {
		if a.typ == typ {
			return a.body, true
		}
	}
	return nil, false
}

// ----------------------------------------------------------------------------
// MESSAGE-INTEGRITY key derivation
// ----------------------------------------------------------------------------

// longTermKey derives the HMAC key per RFC 8489 §14.5:
//
//	key = MD5(username ":" realm ":" password)
//
// For OAUTH-shaped creds (coturn use-auth-secret / Twilio NTS) the
// "password" handed to this is itself
//
//	base64(HMAC-SHA1(static_secret, username))
//
// produced by the credential issuer.
func longTermKey(username, realm, password string) []byte {
	h := md5.Sum([]byte(username + ":" + realm + ":" + password))
	return h[:]
}

// oauthCreds generates a (username, password) pair valid for ttl
// using coturn's use-auth-secret pattern.
func oauthCreds(staticSecret string, ttl time.Duration) (username, password string) {
	exp := time.Now().Add(ttl).Unix()
	username = fmt.Sprintf("%d:lanturn-phase0", exp)
	mac := hmac.New(sha1.New, []byte(staticSecret))
	mac.Write([]byte(username))
	password = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return
}

// ----------------------------------------------------------------------------
// XOR-MAPPED-ADDRESS (RFC 8489 §14.2) encoding/decoding for TURN
// (XOR-RELAYED-ADDRESS / XOR-PEER-ADDRESS share the same format).
// ----------------------------------------------------------------------------

func decodeXORAddr(body []byte, txid [12]byte) (net.IP, int, error) {
	if len(body) < 8 {
		return nil, 0, fmt.Errorf("short xor-mapped-address: %dB", len(body))
	}
	if body[1] != 0x01 {
		return nil, 0, fmt.Errorf("only IPv4 xor-mapped-address supported in spike, got family %#x", body[1])
	}
	xport := binary.BigEndian.Uint16(body[2:4])
	port := int(xport ^ uint16(stunMagicCookie>>16))
	xip := binary.BigEndian.Uint32(body[4:8])
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, xip^stunMagicCookie)
	return ip, port, nil
}

func encodeXORAddr(ip net.IP, port int) []byte {
	body := make([]byte, 8)
	body[0] = 0
	body[1] = 0x01 // IPv4
	binary.BigEndian.PutUint16(body[2:4], uint16(port)^uint16(stunMagicCookie>>16))
	v4 := ip.To4()
	if v4 == nil {
		panic("only IPv4 supported in spike")
	}
	binary.BigEndian.PutUint32(body[4:8], binary.BigEndian.Uint32(v4)^stunMagicCookie)
	return body
}

// ----------------------------------------------------------------------------
// Client subcommand
// ----------------------------------------------------------------------------

func runClient(server, secret, peerStr string) error {
	peerHost, peerPortStr, err := net.SplitHostPort(peerStr)
	if err != nil {
		return fmt.Errorf("bad --peer %q: %w", peerStr, err)
	}
	peerPort, err := strconv.Atoi(peerPortStr)
	if err != nil {
		return fmt.Errorf("bad --peer port: %w", err)
	}
	peerIP := net.ParseIP(peerHost)
	if peerIP == nil {
		return fmt.Errorf("bad --peer ip %q", peerHost)
	}

	conn, err := net.Dial("udp", server)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	conn.(*net.UDPConn).SetDeadline(time.Now().Add(5 * time.Second))

	logf("dialed %s from %s", conn.RemoteAddr(), conn.LocalAddr())

	// === Step 1: Allocate request, no creds. ===
	req := newRequest(msgAllocateRequest)
	req.addAttr(attrRequestedTransport, []byte{requestedTransportUDP, 0, 0, 0})
	wire := req.Encode(nil, true /* fingerprint */)
	logHex("Allocate-noauth >>>", wire)
	mustWrite(conn, wire)
	resp := mustReadParse(conn)
	logf("got msg type=%#04x", resp.msgType)

	if resp.msgType != msgAllocateError {
		return fmt.Errorf("expected 401-style AllocateError, got msgType=%#04x", resp.msgType)
	}
	errBody, _ := resp.attr(attrErrorCode)
	realm, _ := resp.attr(attrRealm)
	nonce, _ := resp.attr(attrNonce)
	if errBody == nil || realm == nil || nonce == nil {
		return fmt.Errorf("AllocateError missing one of ERROR-CODE / REALM / NONCE")
	}
	errCode := decodeErrorCode(errBody)
	logf("got %d %s; realm=%q nonce=%dB", errCode.class*100+errCode.number, errCode.reason, string(realm), len(nonce))

	// === Step 2: Allocate with creds. ===
	username, password := oauthCreds(secret, 30*time.Second)
	logf("OAUTH creds: USERNAME=%q PASSWORD=base64(%dB)", username, base64Len(password))
	key := longTermKey(username, string(realm), password)

	req = newRequest(msgAllocateRequest)
	req.addAttr(attrRequestedTransport, []byte{requestedTransportUDP, 0, 0, 0})
	req.addAttr(attrUsername, []byte(username))
	req.addAttr(attrRealm, realm)
	req.addAttr(attrNonce, nonce)
	lifetime := make([]byte, 4)
	binary.BigEndian.PutUint32(lifetime, 600) // 10 min
	req.addAttr(attrLifetime, lifetime)
	wire = req.Encode(key, true)
	logHex("Allocate-creds >>>", wire)
	mustWrite(conn, wire)
	resp = mustReadParse(conn)
	logf("got msg type=%#04x", resp.msgType)
	if resp.msgType != msgAllocateResponse {
		errBody, _ := resp.attr(attrErrorCode)
		ec := decodeErrorCode(errBody)
		return fmt.Errorf("Allocate failed: %d %s", ec.class*100+ec.number, ec.reason)
	}

	relayedBody, ok := resp.attr(attrXORRelayedAddress)
	if !ok {
		return fmt.Errorf("Allocate response missing XOR-RELAYED-ADDRESS")
	}
	relayIP, relayPort, err := decodeXORAddr(relayedBody, resp.txid)
	if err != nil {
		return fmt.Errorf("decode xor-relayed-address: %w", err)
	}
	logf("ALLOCATED relay address: %s:%d", relayIP, relayPort)

	// === Step 3: CreatePermission for our peer. ===
	req = newRequest(msgCreatePermRequest)
	req.addAttr(attrXORPeerAddress, encodeXORAddr(peerIP, peerPort))
	req.addAttr(attrUsername, []byte(username))
	req.addAttr(attrRealm, realm)
	req.addAttr(attrNonce, nonce)
	wire = req.Encode(key, true)
	logHex("CreatePerm >>>", wire)
	mustWrite(conn, wire)
	resp = mustReadParse(conn)
	if resp.msgType != msgCreatePermResponse {
		errBody, _ := resp.attr(attrErrorCode)
		ec := decodeErrorCode(errBody)
		return fmt.Errorf("CreatePermission failed: %d %s", ec.class*100+ec.number, ec.reason)
	}
	logf("CreatePermission OK")

	// === Step 4: ChannelBind. ===
	const channelNum uint16 = 0x4001 // first channel in the 0x4000-0x7FFF range
	req = newRequest(msgChannelBindRequest)
	chBody := make([]byte, 4)
	binary.BigEndian.PutUint16(chBody[0:2], channelNum)
	req.addAttr(attrChannelNumber, chBody)
	req.addAttr(attrXORPeerAddress, encodeXORAddr(peerIP, peerPort))
	req.addAttr(attrUsername, []byte(username))
	req.addAttr(attrRealm, realm)
	req.addAttr(attrNonce, nonce)
	wire = req.Encode(key, true)
	logHex("ChannelBind >>>", wire)
	mustWrite(conn, wire)
	resp = mustReadParse(conn)
	if resp.msgType != msgChannelBindResponse {
		errBody, _ := resp.attr(attrErrorCode)
		ec := decodeErrorCode(errBody)
		return fmt.Errorf("ChannelBind failed: %d %s", ec.class*100+ec.number, ec.reason)
	}
	logf("ChannelBind OK (channel=%#04x)", channelNum)

	// === Step 5: Send 5 ChannelData frames with random payload. ===
	for i := 0; i < 5; i++ {
		payload := make([]byte, 100+i*40)
		rand.Read(payload)
		frame := make([]byte, 4+len(payload))
		binary.BigEndian.PutUint16(frame[0:2], channelNum)
		binary.BigEndian.PutUint16(frame[2:4], uint16(len(payload)))
		copy(frame[4:], payload)
		// Pad to 4-byte alignment (RFC 8656 §12.4 over TCP, optional UDP).
		if len(frame)%4 != 0 {
			pad := 4 - len(frame)%4
			frame = append(frame, make([]byte, pad)...)
		}
		logHex(fmt.Sprintf("ChannelData[%d] >>>", i), frame[:8])
		mustWrite(conn, frame)
		time.Sleep(50 * time.Millisecond)
	}
	logf("Sent 5 ChannelData frames; phase 0 client run complete.")
	return nil
}

// ----------------------------------------------------------------------------
// Server subcommand (pion/turn — fine for SERVER-side TURN; the
// design's anti-pion rule is for client-side DTLS handshake)
// ----------------------------------------------------------------------------

func runServer(listen, realm, secret string) error {
	host, portStr, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("bad --listen: %w", err)
	}
	port, _ := strconv.Atoi(portStr)
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

	server, err := turn.NewServer(turn.ServerConfig{
		Realm:         realm,
		AuthHandler:   useAuthSecretHandler(secret),
		LoggerFactory: logging.NewDefaultLoggerFactory(),
		PacketConnConfigs: []turn.PacketConnConfig{
			{
				PacketConn: udpListener,
				RelayAddressGenerator: &turn.RelayAddressGeneratorStatic{
					RelayAddress: pubIP,
					Address:      host,
				},
			},
		},
	})
	if err != nil {
		return fmt.Errorf("create TURN server: %w", err)
	}
	logf("TURN server listening on UDP/%d (realm=%s, public-ip=%s)", port, realm, pubIP)
	logf("static-auth-secret = %s", secret)
	logf("press Ctrl-C to stop")
	defer server.Close()

	// Block forever.
	select {}
}

// useAuthSecretHandler implements coturn's use-auth-secret pattern:
// the password is HMAC-SHA1(static_secret, username) base64'd, and
// the username's "<unix_ts>:<id>" prefix's timestamp must be in the
// future.
func useAuthSecretHandler(secret string) turn.AuthHandler {
	return func(username, realm string, srcAddr net.Addr) ([]byte, bool) {
		// Parse "<unix_ts>:<id>" username.
		parts := strings.SplitN(username, ":", 2)
		if len(parts) != 2 {
			logf("auth: malformed username %q", username)
			return nil, false
		}
		exp, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil || time.Now().Unix() > exp {
			logf("auth: expired or unparseable timestamp in %q", username)
			return nil, false
		}
		mac := hmac.New(sha1.New, []byte(secret))
		mac.Write([]byte(username))
		password := base64.StdEncoding.EncodeToString(mac.Sum(nil))
		// pion expects the MD5(username:realm:password) key, so we
		// derive it here per RFC 8489 §14.5.
		key := longTermKey(username, realm, password)
		logf("auth: %s from %s OK", username, srcAddr)
		return key, true
	}
}

// ----------------------------------------------------------------------------
// Helpers
// ----------------------------------------------------------------------------

type errorCode struct {
	class  int
	number int
	reason string
}

func decodeErrorCode(body []byte) errorCode {
	if len(body) < 4 {
		return errorCode{}
	}
	return errorCode{
		class:  int(body[2] & 0x07),
		number: int(body[3]),
		reason: string(body[4:]),
	}
}

func mustWrite(c net.Conn, b []byte) {
	if _, err := c.Write(b); err != nil {
		log.Fatalf("write: %v", err)
	}
}

func mustReadParse(c net.Conn) *stunMessage {
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil {
		log.Fatalf("read: %v", err)
	}
	logHex("<<< raw", buf[:min(n, 64)])
	m, err := Decode(buf[:n])
	if err != nil {
		log.Fatalf("decode: %v", err)
	}
	return m
}

func base64Len(s string) int { return len(s) }

func logf(format string, a ...any) {
	log.Printf(format, a...)
}

func logHex(label string, b []byte) {
	log.Printf("%s (%dB)\n%s", label, len(b), hex.Dump(b))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ----------------------------------------------------------------------------
// main
// ----------------------------------------------------------------------------

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "server":
		fs := flag.NewFlagSet("server", flag.ExitOnError)
		listen := fs.String("listen", "0.0.0.0:3478", "udp listen addr")
		realm := fs.String("realm", "lanturn.example", "TURN realm")
		secret := fs.String("secret", "lanturn-phase0-shared-secret", "static-auth-secret")
		fs.Parse(os.Args[2:])
		if err := runServer(*listen, *realm, *secret); err != nil {
			log.Fatal(err)
		}
	case "client":
		fs := flag.NewFlagSet("client", flag.ExitOnError)
		server := fs.String("server", "127.0.0.1:3478", "TURN server")
		secret := fs.String("secret", "lanturn-phase0-shared-secret", "static-auth-secret")
		peer := fs.String("peer", "127.0.0.1:9999", "fake peer address to bind a channel for")
		fs.Parse(os.Args[2:])
		if err := runClient(*server, *secret, *peer); err != nil {
			log.Fatal(err)
		}
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `lanturn-phase0 — TURN wire-format validation spike.

Usage:

  lanturn-phase0 server [-listen 0.0.0.0:3478] [-realm STR] [-secret STR]
      Spin up a local TURN test server (pion/turn).
      Set LANTURN_PUBLIC_IP env var to advertise a real address.

  lanturn-phase0 client [-server HOST:PORT] [-secret STR] [-peer HOST:PORT]
      Run the hand-rolled STUN/TURN allocate/channel-bind/channel-data dance.

Capture the wire bytes:

  tshark -i lo0 -d udp.port==3478,stun -V port 3478 > /tmp/lanturn-phase0.tshark

`)
}
