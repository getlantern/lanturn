# lanturn

A Lantern circumvention transport that mimics WebRTC TURN-relayed media flow on
plain UDP/3478 with self-hosted coturn on Lantern's international VPS fleet.

**Status: Phase 1 (DTLS-through-relay + SRTP shaping)**. See
[design draft v0.2](https://github.com/getlantern/circumvention-corpus-private/blob/main/text/2026-05-lanturn-design.md)
in `circumvention-corpus-private` for the full design (private repo).

## Phase 0 — what's here

`cmd/lanturn-phase0/` is a hand-rolled RFC 8489 STUN + RFC 8656 TURN
encoder/decoder that runs the full Allocate / CreatePermission / ChannelBind /
ChannelData dance against a TURN server. It exists to validate the wire-format
claims the lanturn design depends on:

1. STUN magic cookie `0x2112A442` at offset 4 of every STUN message (RFC 8489 §6).
2. ChannelData channel-number range `0x4000-0x7FFF` (RFC 8656 §12).
3. FINGERPRINT attribute (RFC 8489 §14.7) with XOR const `0x5354554e`.
4. 401-NONCE-then-credentials Allocate dance with MESSAGE-INTEGRITY HMAC-SHA1
   over the long-term-credential key `MD5(username:realm:password)` (RFC 8489 §14.5).
5. OAUTH-shaped (coturn `use-auth-secret` / Twilio NTS) ephemeral creds:
   `USERNAME = "<unix_ts>:<random_id>"`, `PASSWORD = base64(HMAC-SHA1(secret, username))`.

The client side is **hand-rolled, no third-party STUN/TURN library** — we want
to know the bytes that hit the wire match the catalog claims byte-for-byte.
The server side uses pion/turn for convenience (the design's anti-pion rule
applies specifically to the *client-side DTLS handshake* in later phases, not
to the TURN protocol itself).

## Quick start

```sh
# Build
go build -o /tmp/lanturn-phase0 ./cmd/lanturn-phase0

# Terminal 1: spin up the local TURN test server
/tmp/lanturn-phase0 server -listen 127.0.0.1:3478 -realm lanturn.test -secret phase0secret

# Terminal 2: run the hand-rolled client
/tmp/lanturn-phase0 client -server 127.0.0.1:3478 -secret phase0secret -peer 127.0.0.1:9999
```

Expected output (client side, abridged):

```
Allocate-noauth >>> ...
got msg type=0x0113
got 401 Unauthorized; realm="lanturn.test" nonce=...
OAUTH creds: USERNAME="1778260358:lanturn-phase0" PASSWORD=base64(28B)
Allocate-creds >>> ...
got msg type=0x0103
ALLOCATED relay address: 127.0.0.1:62655
CreatePermission OK
ChannelBind OK (channel=0x4001)
Sent 5 ChannelData frames; phase 0 client run complete.
```

Server side will log `auth: <username> from <addr> OK` for each authenticated
request.

## Validation against the catalog claims

Every request the client sends is dumped as hex. Inspect:

- The first 8 bytes of any client→server packet should start
  `<msg-type 2B> <length 2B> 21 12 a4 42` — the magic cookie.
- The last 8 bytes of every request should be FINGERPRINT:
  `80 28 00 04 <CRC32 4B>` (type 0x8028, length 4, CRC body).
- ChannelData frames start with the channel number in the
  range `0x4000-0x7FFF`. The spike binds channel `0x4001`,
  so frames begin `40 01 <length 2B>`.

For deeper inspection use Wireshark / tshark:

```sh
sudo tshark -i lo0 -d udp.port==3478,stun -V port 3478
```

Wireshark recognizes STUN/TURN natively when you tell it the port; the
"FINGERPRINT" / "MESSAGE-INTEGRITY" / "REALM" / "NONCE" / "XOR-RELAYED-ADDRESS"
attributes will all be parsed and labeled.

## What's NOT in Phase 0

- No DTLS handshake inside the ChannelData frames yet — those are random bytes
  for now. **Phase 1** will add the client-and-egress DTLS handshake using
  covert-dtls from Lantern Unbounded.
- No SRTP shaping. **Phase 1** also.
- No behavioral mimicry (session rotation, jitter envelope, RTCP, DTX).
  **Phase 2**.
- No coturn-fleet / Lantern-config integration. **Phase 2**.
- No TURNS-on-5349 fallback. **Phase 4**.
- Not wired into lantern-box. **Phase 5**.

## Phase 1 — DTLS-through-relay + SRTP shaping

`cmd/lanturn-phase1/` adds the inner-layer dance:

- Self-signed-cert DTLS handshake between client and egress, **with the
  bytes traversing inside ChannelData payloads** (coturn forwards them
  opaquely).
- SRTP key extraction via RFC 5705 `EXTRACTOR-dtls_srtp` (RFC 5764 §4.2),
  60 bytes of keying material split into per-direction key+salt pairs.
- Steady-state SRTP-shaped packets: PT=111 (Opus), v=2 (leading byte
  `0x80`), incrementing sequence + timestamp at Opus frame cadence
  (960 samples per 20ms, 50pps).
- Demux layer (`packetMux`) routes packets between DTLS records (leading
  bytes 20-25) and SRTP/SRTCP (leading bytes 128-191) — the layer real
  WebRTC stacks have baked in (pion/transport/v3/mux); minimal hand-rolled
  version for the spike.

Quick start:

```sh
go build -o /tmp/lanturn-phase1 ./cmd/lanturn-phase1

# Terminal 1: TURN server (same as Phase 0)
/tmp/lanturn-phase1 server -listen 127.0.0.1:3478 -secret p1secret

# Terminal 2: egress (raw UDP listener → DTLS server → SRTP receiver)
/tmp/lanturn-phase1 egress -listen 127.0.0.1:9999

# Terminal 3: client (TURN allocate → DTLS handshake through relay → send N SRTP)
/tmp/lanturn-phase1 client -server 127.0.0.1:3478 -secret p1secret -peer 127.0.0.1:9999
```

Expected output (excerpts, abridged):

Client side:
```
client: TURN allocate + ChannelBind OK (channel=0x4001 peer=127.0.0.1:9999)
client: starting DTLS handshake through TURN relay...
client: DTLS handshake OK in 2.27ms
client: negotiated SRTP profile: 0x1 (AES-128-CM-HMAC-SHA1-80)
client: extracted 60 bytes of SRTP keying material
client: SRTP[0] >>> seq=34922 ts=3521794419 ssrc=0x932573e3 129B (encrypted=151B) leading=0x80
client: SRTP[1] >>> seq=34923 ts=3521795379 ssrc=0x932573e3 101B (encrypted=123B) leading=0x80
... 10 packets total ...
```

Egress side:
```
egress: first packet from 127.0.0.1:58303 (135B, leading=0x16)
egress: DTLS handshake OK in 1.01ms
egress: extracted 60 bytes of SRTP keying material
egress: SRTP[0] <<< seq=34922 ts=3521794419 ssrc=0x932573e3 PT=111 payload=129B (encrypted=151B)
... 10 packets received ...
```

Wire-level byte-budget check: encrypted = 12 (RTP header) + payload + 10
(SHA1-80 auth tag). Holds for every packet.

## Layout

```
cmd/lanturn-phase0/main.go    Phase 0 — hand-rolled STUN/TURN dance
cmd/lanturn-phase1/main.go    Phase 1 — DTLS handshake through relay + SRTP
internal/stun/                Hand-rolled STUN message encode/decode
internal/turn/                TURN allocate flow + RelayConn (net.Conn wrapper)
testdata/validate.sh          tshark-based wire-format validation
go.mod / go.sum / README.md / .gitignore
```

## Phases (from the design doc)

- **Phase 0**: validate ✅
- **Phase 1**: SRTP shaping ✅ (this spike — but **without** covert-dtls
  fingerprint randomization; see Hard rules below)
- **Phase 2**: behavioral mimicry + coturn-fleet rotation + Lantern
  config integration + **covert-dtls fingerprint hook** (required for
  Russia/China rollout)
- **Phase 3**: video-shape profiles
- **Phase 4**: TURNS-on-5349 fallback
- **Phase 5**: lantern-box integration + field test

## Hard rules

- **Phase 1 uses stock pion/dtls without fingerprint randomization** —
  fine for validation spike, **NOT** acceptable for Russia / China
  deployment. The pion-default DTLS ClientHello fingerprint is matched
  by TSPU since March 2026 (net4people/bbs#603). Phase 2 will integrate
  `common/covertdtls/` from Lantern Unbounded (which wraps pion/dtls
  with the upstream `theodorsm/covert-dtls` randomize / mimic hooks)
  and the design doc §4.4 forbids deployment without it. See cover-dtls
  catalog §Censor Practice for the attack details.
- pion/turn for the **server-side** TURN protocol is fine in any phase
  — the TSPU matcher is on DTLS ClientHello, not on TURN bytes.
- pion/dtls for the **server-side** of the inner DTLS (the egress) is
  fine in any phase — the same reasoning. DTLS-server-fingerprinting in
  deployed censors is less mature than client-fingerprinting.
