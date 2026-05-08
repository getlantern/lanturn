// Package turn drives the RFC 8656 client side of the lanturn TURN
// flow: Allocate (with the 401-NONCE-then-creds dance), CreatePermission,
// ChannelBind. After ChannelBind succeeds the package exposes a
// RelayConn (a net.Conn) that wraps writes as ChannelData frames and
// unwraps reads of ChannelData frames — this lets the inner DTLS /
// SRTP layer treat the TURN relay as a virtual UDP path to the peer.
package turn

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/getlantern/lanturn/internal/stun"
)

// AllocateConfig drives the TURN Allocate flow.
type AllocateConfig struct {
	Server  string        // host:port of the TURN server
	Secret  string        // static-auth-secret (use-auth-secret pattern)
	CredID  string        // arbitrary id appended to USERNAME after the timestamp
	CredTTL time.Duration // ephemeral-cred lifetime to issue ourselves

	Logf func(format string, args ...any)
}

func (c AllocateConfig) logf(f string, args ...any) {
	if c.Logf != nil {
		c.Logf(f, args...)
	}
}

// Allocation is a successfully-allocated TURN session.
type Allocation struct {
	UDP        *net.UDPConn // the underlying socket to the TURN server
	RelayedIP  net.IP       // address coturn allocated for inbound peer traffic
	RelayedPort int

	Username string
	Realm    string
	Nonce    []byte
	Key      []byte // MD5(username:realm:password) — for further auth'd requests
}

// Allocate runs the 401-NONCE-then-creds Allocate dance and returns
// the resulting Allocation.
func Allocate(cfg AllocateConfig) (*Allocation, error) {
	conn, err := net.Dial("udp", cfg.Server)
	if err != nil {
		return nil, fmt.Errorf("dial turn server: %w", err)
	}
	udp := conn.(*net.UDPConn)
	udp.SetDeadline(time.Now().Add(5 * time.Second))

	// Step 1: Allocate without creds — expect 401 with REALM + NONCE.
	req := stun.NewRequest(stun.MsgAllocateRequest)
	req.AddAttr(stun.AttrRequestedTransport, []byte{stun.RequestedTransportUDP, 0, 0, 0})
	wire := req.Encode(nil, true)
	if _, err := udp.Write(wire); err != nil {
		return nil, fmt.Errorf("write Allocate-noauth: %w", err)
	}

	resp, err := readSTUN(udp)
	if err != nil {
		return nil, fmt.Errorf("read Allocate-noauth response: %w", err)
	}
	if resp.Type != stun.MsgAllocateError {
		return nil, fmt.Errorf("expected AllocateError(0x0113), got %#04x", resp.Type)
	}
	realm, _ := resp.Attr(stun.AttrRealm)
	nonce, _ := resp.Attr(stun.AttrNonce)
	if realm == nil || nonce == nil {
		return nil, fmt.Errorf("AllocateError missing REALM or NONCE")
	}

	// Step 2: Allocate with creds.
	username, password := stun.OAuthCreds(cfg.Secret, cfg.CredID, cfg.CredTTL)
	cfg.logf("OAUTH creds: USERNAME=%q PASSWORD=base64(%dB)", username, len(password))
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
	if _, err := udp.Write(wire); err != nil {
		return nil, fmt.Errorf("write Allocate-creds: %w", err)
	}

	resp, err = readSTUN(udp)
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
	cfg.logf("ALLOCATED relay address: %s:%d", relayIP, relayPort)

	return &Allocation{
		UDP:         udp,
		RelayedIP:   relayIP,
		RelayedPort: relayPort,
		Username:    username,
		Realm:       string(realm),
		Nonce:       nonce,
		Key:         key,
	}, nil
}

// CreatePermission authorizes peer-IP to send to the relayed address.
func (a *Allocation) CreatePermission(peerIP net.IP, peerPort int) error {
	a.UDP.SetDeadline(time.Now().Add(5 * time.Second))

	req := stun.NewRequest(stun.MsgCreatePermRequest)
	req.AddAttr(stun.AttrXORPeerAddress, stun.EncodeXORAddr(peerIP, peerPort))
	req.AddAttr(stun.AttrUsername, []byte(a.Username))
	req.AddAttr(stun.AttrRealm, []byte(a.Realm))
	req.AddAttr(stun.AttrNonce, a.Nonce)
	wire := req.Encode(a.Key, true)
	if _, err := a.UDP.Write(wire); err != nil {
		return fmt.Errorf("write CreatePerm: %w", err)
	}
	resp, err := readSTUN(a.UDP)
	if err != nil {
		return fmt.Errorf("read CreatePerm response: %w", err)
	}
	if resp.Type != stun.MsgCreatePermResponse {
		errBody, _ := resp.Attr(stun.AttrErrorCode)
		ec := stun.DecodeErrorCode(errBody)
		return fmt.Errorf("CreatePerm failed: %d %s", ec.Class*100+ec.Number, ec.Reason)
	}
	return nil
}

// ChannelBind binds channel to (peerIP, peerPort) so traffic from
// that 5-tuple is delivered as ChannelData frames.
func (a *Allocation) ChannelBind(channel uint16, peerIP net.IP, peerPort int) error {
	if channel < 0x4000 || channel > 0x7FFF {
		return fmt.Errorf("channel %#x outside RFC 8656 §12 range 0x4000-0x7FFF", channel)
	}
	a.UDP.SetDeadline(time.Now().Add(5 * time.Second))

	req := stun.NewRequest(stun.MsgChannelBindRequest)
	chBody := make([]byte, 4)
	binary.BigEndian.PutUint16(chBody[0:2], channel)
	req.AddAttr(stun.AttrChannelNumber, chBody)
	req.AddAttr(stun.AttrXORPeerAddress, stun.EncodeXORAddr(peerIP, peerPort))
	req.AddAttr(stun.AttrUsername, []byte(a.Username))
	req.AddAttr(stun.AttrRealm, []byte(a.Realm))
	req.AddAttr(stun.AttrNonce, a.Nonce)
	wire := req.Encode(a.Key, true)
	if _, err := a.UDP.Write(wire); err != nil {
		return fmt.Errorf("write ChannelBind: %w", err)
	}
	resp, err := readSTUN(a.UDP)
	if err != nil {
		return fmt.Errorf("read ChannelBind response: %w", err)
	}
	if resp.Type != stun.MsgChannelBindResponse {
		errBody, _ := resp.Attr(stun.AttrErrorCode)
		ec := stun.DecodeErrorCode(errBody)
		return fmt.Errorf("ChannelBind failed: %d %s", ec.Class*100+ec.Number, ec.Reason)
	}
	return nil
}

// RelayConn wraps an Allocation as a net.Conn, encoding writes as
// ChannelData frames bound to channel and decoding reads of
// ChannelData frames for that channel. STUN messages received on
// the same socket (e.g. responses to subsequent Refresh) are dropped.
type RelayConn struct {
	alloc   *Allocation
	channel uint16
	rdBuf   []byte
}

// NewRelayConn wraps the allocation. Caller must have already
// CreatePermission + ChannelBind for the channel/peer.
func (a *Allocation) NewRelayConn(channel uint16) *RelayConn {
	a.UDP.SetDeadline(time.Time{}) // clear allocate-flow deadline
	return &RelayConn{
		alloc:   a,
		channel: channel,
		rdBuf:   make([]byte, 65536),
	}
}

// Write wraps p in a ChannelData frame and sends to the TURN server.
func (c *RelayConn) Write(p []byte) (int, error) {
	if len(p) > 65535-4 {
		return 0, fmt.Errorf("ChannelData payload %d > max", len(p))
	}
	frame := make([]byte, 4+len(p))
	binary.BigEndian.PutUint16(frame[0:2], c.channel)
	binary.BigEndian.PutUint16(frame[2:4], uint16(len(p)))
	copy(frame[4:], p)
	// 4-byte padding required on TCP transport, optional UDP. We
	// pad anyway for symmetry.
	if pad := (4 - len(frame)%4) % 4; pad > 0 {
		frame = append(frame, make([]byte, pad)...)
	}
	if _, err := c.alloc.UDP.Write(frame); err != nil {
		return 0, err
	}
	return len(p), nil
}

// Read receives one ChannelData payload destined for this channel.
// STUN messages and ChannelData frames for other channels are dropped.
func (c *RelayConn) Read(p []byte) (int, error) {
	for {
		n, err := c.alloc.UDP.Read(c.rdBuf)
		if err != nil {
			return 0, err
		}
		if n < 4 {
			continue
		}
		// Distinguish: STUN starts 0b00xxxxxx (high bits of msg-type
		// always 0 in STUN). ChannelData starts in 0x4000-0x7FFF
		// (high 2 bits = 0b01).
		first := c.rdBuf[0]
		if first&0xC0 == 0 {
			continue // STUN message; ignore
		}
		ch := binary.BigEndian.Uint16(c.rdBuf[0:2])
		if ch != c.channel {
			continue
		}
		bodyLen := int(binary.BigEndian.Uint16(c.rdBuf[2:4]))
		if 4+bodyLen > n {
			continue
		}
		return copy(p, c.rdBuf[4:4+bodyLen]), nil
	}
}

func (c *RelayConn) Close() error                       { return c.alloc.UDP.Close() }
func (c *RelayConn) LocalAddr() net.Addr                { return c.alloc.UDP.LocalAddr() }
func (c *RelayConn) RemoteAddr() net.Addr               { return c.alloc.UDP.RemoteAddr() }
func (c *RelayConn) SetDeadline(t time.Time) error      { return c.alloc.UDP.SetDeadline(t) }
func (c *RelayConn) SetReadDeadline(t time.Time) error  { return c.alloc.UDP.SetReadDeadline(t) }
func (c *RelayConn) SetWriteDeadline(t time.Time) error { return c.alloc.UDP.SetWriteDeadline(t) }

// readSTUN reads one packet, parses as STUN, returns the message.
func readSTUN(udp *net.UDPConn) (*stun.Message, error) {
	buf := make([]byte, 4096)
	n, err := udp.Read(buf)
	if err != nil {
		return nil, err
	}
	return stun.Decode(buf[:n])
}
