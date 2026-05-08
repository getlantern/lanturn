// Package stun implements a hand-rolled subset of RFC 8489 STUN +
// RFC 8656 TURN message encoding/decoding sufficient for lanturn's
// Allocate / CreatePermission / ChannelBind / ChannelData flow.
//
// The hand-rolled discipline is deliberate: lanturn's design depends on
// specific wire-format claims (magic cookie at offset 4, ChannelData
// channel range 0x4000-0x7FFF, FINGERPRINT XOR const 0x5354554e), and
// the validation spike wants to know the bytes match byte-for-byte. We
// do NOT depend on pion/stun on the client side.
package stun

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"net"
	"time"
)

// Wire-format constants from RFC 8489 + RFC 8656.
const (
	MagicCookie    uint32 = 0x2112A442
	FingerprintXOR uint32 = 0x5354554e // "STUN" in ASCII; RFC 8489 §14.7
)

// STUN message types (class+method packed into 14 bits).
const (
	MsgAllocateRequest     = 0x0003
	MsgAllocateResponse    = 0x0103
	MsgAllocateError       = 0x0113
	MsgRefreshRequest      = 0x0004
	MsgRefreshResponse     = 0x0104
	MsgCreatePermRequest   = 0x0008
	MsgCreatePermResponse  = 0x0108
	MsgCreatePermError     = 0x0118
	MsgChannelBindRequest  = 0x0009
	MsgChannelBindResponse = 0x0109
	MsgChannelBindError    = 0x0119
)

// STUN attribute types.
const (
	AttrMappedAddress      = 0x0001
	AttrUsername           = 0x0006
	AttrMessageIntegrity   = 0x0008
	AttrErrorCode          = 0x0009
	AttrUnknownAttributes  = 0x000a
	AttrRealm              = 0x0014
	AttrNonce              = 0x0015
	AttrXORMappedAddress   = 0x0020
	AttrChannelNumber      = 0x000c
	AttrLifetime           = 0x000d
	AttrXORPeerAddress     = 0x0012
	AttrData               = 0x0013
	AttrXORRelayedAddress  = 0x0016
	AttrRequestedTransport = 0x0019
	AttrSoftware           = 0x8022
	AttrAlternateServer    = 0x8023
	AttrFingerprint        = 0x8028
)

// REQUESTED-TRANSPORT protocol values (RFC 8656 §14.7).
const (
	RequestedTransportUDP = 17
	RequestedTransportTCP = 6
)

// Message is a STUN message under construction or after parsing.
type Message struct {
	Type  uint16
	TxID  [12]byte
	Attrs []Attribute
}

// Attribute is one STUN TLV.
type Attribute struct {
	Type uint16
	Body []byte
}

// NewRequest creates a new STUN request message with a random
// transaction ID.
func NewRequest(msgType uint16) *Message {
	m := &Message{Type: msgType}
	if _, err := rand.Read(m.TxID[:]); err != nil {
		panic(err)
	}
	return m
}

// AddAttr appends a STUN attribute.
func (m *Message) AddAttr(typ uint16, body []byte) {
	m.Attrs = append(m.Attrs, Attribute{Type: typ, Body: body})
}

// Attr returns the body of the first attribute matching typ.
func (m *Message) Attr(typ uint16) ([]byte, bool) {
	for _, a := range m.Attrs {
		if a.Type == typ {
			return a.Body, true
		}
	}
	return nil, false
}

// Encode produces the wire bytes. If integrityKey is non-nil, a
// MESSAGE-INTEGRITY attribute is appended (HMAC-SHA1 of the message
// up to and including the integrity-attribute length-fixed-up header,
// per RFC 8489 §14.5). If withFingerprint, FINGERPRINT is appended
// last (CRC32 of the message XOR'd with FingerprintXOR).
func (m *Message) Encode(integrityKey []byte, withFingerprint bool) []byte {
	attrBuf := encodeAttrs(m.Attrs)

	addedLen := 0
	if integrityKey != nil {
		addedLen += 4 + 20
	}
	if withFingerprint {
		addedLen += 4 + 4
	}

	header := make([]byte, 20)
	binary.BigEndian.PutUint16(header[0:2], m.Type)
	binary.BigEndian.PutUint16(header[2:4], uint16(len(attrBuf)+addedLen))
	binary.BigEndian.PutUint32(header[4:8], MagicCookie)
	copy(header[8:20], m.TxID[:])

	if integrityKey != nil {
		// length-for-integrity = current length up through MESSAGE-INTEGRITY,
		// not including any subsequent FINGERPRINT.
		intLen := len(attrBuf) + 4 + 20
		binary.BigEndian.PutUint16(header[2:4], uint16(intLen))

		mac := hmac.New(sha1.New, integrityKey)
		mac.Write(header)
		mac.Write(attrBuf)
		integrity := mac.Sum(nil)

		attrBuf = append(attrBuf, encodeAttr(AttrMessageIntegrity, integrity)...)

		// Restore final length for the finished message.
		binary.BigEndian.PutUint16(header[2:4], uint16(len(attrBuf)+(addedLen-4-20)))
	}

	if withFingerprint {
		buf := append([]byte{}, header...)
		buf = append(buf, attrBuf...)
		crc := crc32.ChecksumIEEE(buf) ^ FingerprintXOR
		fpBody := make([]byte, 4)
		binary.BigEndian.PutUint32(fpBody, crc)
		attrBuf = append(attrBuf, encodeAttr(AttrFingerprint, fpBody)...)
	}

	return append(header, attrBuf...)
}

// Decode parses the wire bytes into a Message. Verifies the magic
// cookie. Does NOT verify MESSAGE-INTEGRITY or FINGERPRINT; callers
// can do that themselves on the parsed attributes.
func Decode(buf []byte) (*Message, error) {
	if len(buf) < 20 {
		return nil, fmt.Errorf("stun: short message: %dB", len(buf))
	}
	if binary.BigEndian.Uint32(buf[4:8]) != MagicCookie {
		return nil, fmt.Errorf("stun: bad magic cookie %#x", binary.BigEndian.Uint32(buf[4:8]))
	}
	m := &Message{Type: binary.BigEndian.Uint16(buf[0:2])}
	copy(m.TxID[:], buf[8:20])

	declaredLen := int(binary.BigEndian.Uint16(buf[2:4]))
	if 20+declaredLen > len(buf) {
		return nil, fmt.Errorf("stun: declared length %d exceeds buffer %d", declaredLen, len(buf)-20)
	}

	pos := 20
	for pos < 20+declaredLen {
		if pos+4 > len(buf) {
			return nil, fmt.Errorf("stun: truncated attribute at %d", pos)
		}
		atyp := binary.BigEndian.Uint16(buf[pos : pos+2])
		alen := int(binary.BigEndian.Uint16(buf[pos+2 : pos+4]))
		if pos+4+alen > len(buf) {
			return nil, fmt.Errorf("stun: attribute body extends past message")
		}
		body := make([]byte, alen)
		copy(body, buf[pos+4:pos+4+alen])
		m.Attrs = append(m.Attrs, Attribute{Type: atyp, Body: body})
		pad := (4 - alen%4) % 4
		pos += 4 + alen + pad
	}
	return m, nil
}

func encodeAttrs(attrs []Attribute) []byte {
	var out []byte
	for _, a := range attrs {
		out = append(out, encodeAttr(a.Type, a.Body)...)
	}
	return out
}

func encodeAttr(typ uint16, body []byte) []byte {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint16(hdr[0:2], typ)
	binary.BigEndian.PutUint16(hdr[2:4], uint16(len(body)))
	out := append(hdr, body...)
	pad := (4 - len(body)%4) % 4
	if pad > 0 {
		out = append(out, make([]byte, pad)...)
	}
	return out
}

// LongTermKey derives the HMAC key per RFC 8489 §14.5:
//
//	key = MD5(username ":" realm ":" password)
func LongTermKey(username, realm, password string) []byte {
	h := md5.Sum([]byte(username + ":" + realm + ":" + password))
	return h[:]
}

// OAuthCreds generates a (username, password) pair valid for ttl using
// coturn's use-auth-secret pattern (Twilio NTS-shaped):
//
//	USERNAME = "<unix_expiry>:<id>"
//	PASSWORD = base64(HMAC-SHA1(static_secret, username))
func OAuthCreds(staticSecret, id string, ttl time.Duration) (username, password string) {
	exp := time.Now().Add(ttl).Unix()
	username = fmt.Sprintf("%d:%s", exp, id)
	mac := hmac.New(sha1.New, []byte(staticSecret))
	mac.Write([]byte(username))
	password = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return
}

// EncodeXORAddr produces an XOR-MAPPED-ADDRESS-style 8-byte body.
// Only IPv4 is supported in the spike.
func EncodeXORAddr(ip net.IP, port int) []byte {
	body := make([]byte, 8)
	body[0] = 0
	body[1] = 0x01 // IPv4 family
	binary.BigEndian.PutUint16(body[2:4], uint16(port)^uint16(MagicCookie>>16))
	v4 := ip.To4()
	if v4 == nil {
		panic("stun: only IPv4 supported in spike")
	}
	binary.BigEndian.PutUint32(body[4:8], binary.BigEndian.Uint32(v4)^MagicCookie)
	return body
}

// DecodeXORAddr unpacks an XOR-MAPPED-ADDRESS-style body.
func DecodeXORAddr(body []byte) (net.IP, int, error) {
	if len(body) < 8 {
		return nil, 0, fmt.Errorf("stun: short xor-mapped-address: %dB", len(body))
	}
	if body[1] != 0x01 {
		return nil, 0, fmt.Errorf("stun: only IPv4 xor-mapped-address supported, got family %#x", body[1])
	}
	xport := binary.BigEndian.Uint16(body[2:4])
	port := int(xport ^ uint16(MagicCookie>>16))
	xip := binary.BigEndian.Uint32(body[4:8])
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, xip^MagicCookie)
	return ip, port, nil
}

// ErrorCode unpacks an ERROR-CODE attribute.
type ErrorCode struct {
	Class  int
	Number int
	Reason string
}

func DecodeErrorCode(body []byte) ErrorCode {
	if len(body) < 4 {
		return ErrorCode{}
	}
	return ErrorCode{
		Class:  int(body[2] & 0x07),
		Number: int(body[3]),
		Reason: string(body[4:]),
	}
}
