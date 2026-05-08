// lanturn-phase0 — Phase 0 validation spike.
//
// Hand-rolled RFC 8489 STUN + RFC 8656 TURN client running the full
// Allocate / 401-NONCE-then-creds / Allocate-with-creds /
// CreatePermission / ChannelBind / ChannelData dance against a TURN
// server. Validates the wire-format claims of the lanturn design
// (circumvention-corpus-private text/2026-05-lanturn-design.md).
//
// See README.md for what exactly Phase 0 validates and how to run it.
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/getlantern/lanturn/internal/stun"
	"github.com/getlantern/lanturn/internal/turn"

	"github.com/pion/logging"
	pionturn "github.com/pion/turn/v3"
)

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

func runClient(server, secret, peerStr string) error {
	peerIP, peerPort, err := parseHostPort(peerStr)
	if err != nil {
		return err
	}

	alloc, err := turn.Allocate(turn.AllocateConfig{
		Server:  server,
		Secret:  secret,
		CredID:  "lanturn-phase0",
		CredTTL: 30 * time.Second,
		Logf:    log.Printf,
	})
	if err != nil {
		return err
	}
	defer alloc.UDP.Close()

	if err := alloc.CreatePermission(peerIP, peerPort); err != nil {
		return err
	}
	log.Printf("CreatePermission OK")

	const channelNum uint16 = 0x4001
	if err := alloc.ChannelBind(channelNum, peerIP, peerPort); err != nil {
		return err
	}
	log.Printf("ChannelBind OK (channel=%#04x)", channelNum)

	relay := alloc.NewRelayConn(channelNum)
	for i := 0; i < 5; i++ {
		payload := make([]byte, 100+i*40)
		rand.Read(payload)
		if _, err := relay.Write(payload); err != nil {
			return fmt.Errorf("ChannelData[%d] write: %w", i, err)
		}
		log.Printf("ChannelData[%d] >>> (%dB) channel=%#04x", i, len(payload), channelNum)
		time.Sleep(50 * time.Millisecond)
	}
	log.Printf("Sent 5 ChannelData frames; phase 0 client run complete.")

	// Briefly demonstrate magic-cookie + FINGERPRINT presence in a
	// fresh request that we encode but don't send.
	demoRequest := stun.NewRequest(stun.MsgAllocateRequest)
	demoRequest.AddAttr(stun.AttrRequestedTransport, []byte{stun.RequestedTransportUDP, 0, 0, 0})
	demoBytes := demoRequest.Encode(nil, true)
	log.Printf("wire-format demo (Allocate request, no creds, with FINGERPRINT):\n%s", hex.Dump(demoBytes))
	return nil
}

func runServer(listen, realm, secret string) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("bad --listen: %w", err)
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
		return fmt.Errorf("create TURN server: %w", err)
	}
	log.Printf("TURN server listening on %s (realm=%s, public-ip=%s)", listen, realm, pubIP)
	log.Printf("static-auth-secret = %s", secret)
	defer server.Close()
	select {}
}

// useAuthSecretHandler implements the Twilio NTS / coturn use-auth-secret
// pattern: USERNAME = "<unix_ts>:<id>",
// PASSWORD = base64(HMAC-SHA1(static_secret, username)). The pion API
// expects the long-term-credential MD5(username:realm:password) key.
func useAuthSecretHandler(secret string) pionturn.AuthHandler {
	return func(username, realm string, srcAddr net.Addr) ([]byte, bool) {
		parts := strings.SplitN(username, ":", 2)
		if len(parts) != 2 {
			log.Printf("auth: malformed username %q", username)
			return nil, false
		}
		exp, err := strconv.ParseInt(parts[0], 10, 64)
		if err != nil || time.Now().Unix() > exp {
			log.Printf("auth: expired or unparseable timestamp in %q", username)
			return nil, false
		}
		mac := hmac.New(sha1.New, []byte(secret))
		mac.Write([]byte(username))
		password := base64.StdEncoding.EncodeToString(mac.Sum(nil))
		log.Printf("auth: %s from %s OK", username, srcAddr)
		return stun.LongTermKey(username, realm, password), true
	}
}

func parseHostPort(s string) (net.IP, int, error) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return nil, 0, fmt.Errorf("bad host:port %q: %w", s, err)
	}
	port, err := strconv.Atoi(p)
	if err != nil {
		return nil, 0, fmt.Errorf("bad port in %q: %w", s, err)
	}
	ip := net.ParseIP(h)
	if ip == nil {
		return nil, 0, fmt.Errorf("bad ip in %q", s)
	}
	return ip, port, nil
}

func usage() {
	fmt.Fprintf(os.Stderr, `lanturn-phase0 — TURN wire-format validation spike.

Subcommands:

  lanturn-phase0 server [-listen 0.0.0.0:3478] [-realm STR] [-secret STR]
      Spin up a local TURN test server (pion/turn).
      Set LANTURN_PUBLIC_IP env var to advertise a real address.

  lanturn-phase0 client [-server HOST:PORT] [-secret STR] [-peer HOST:PORT]
      Run the hand-rolled STUN/TURN allocate/channel-bind/channel-data dance.

Capture wire bytes:

  sudo tshark -i lo0 -d udp.port==3478,stun -V port 3478

`)
	_ = binary.BigEndian // silence "imported and not used" if encodings move
}
