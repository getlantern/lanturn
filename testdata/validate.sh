#!/bin/bash
# Phase 0 wire-format validation script.
#
# Captures the lanturn-phase0 client+server dance with tshark and
# verifies the wire-format claims from §4 of the lanturn design doc.
#
# Usage: ./validate.sh
#
# Requires:
#   - tshark (brew install wireshark or apt install tshark)
#   - sudo (for packet capture on lo0)
#   - the binary built at /tmp/lanturn-phase0
set -euo pipefail

BIN=/tmp/lanturn-phase0
PCAP=/tmp/lanturn-phase0.pcap
PORT=3478
SECRET=phase0secret

if [ ! -x "$BIN" ]; then
  echo "build first: go build -o $BIN ./cmd/lanturn-phase0"
  exit 2
fi

echo "==> starting server..."
"$BIN" server -listen 127.0.0.1:$PORT -realm lanturn.test -secret "$SECRET" \
  > /tmp/lanturn-server.log 2>&1 &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT
sleep 0.5

echo "==> starting tshark capture (sudo prompt may appear)..."
LOOPBACK_IF=$(tshark -D 2>/dev/null | grep -i loopback | head -1 | sed 's/\..*//' || echo "lo0")
sudo tshark -i "$LOOPBACK_IF" -w "$PCAP" "udp port $PORT" \
  > /tmp/lanturn-tshark.log 2>&1 &
TSHARK_PID=$!
trap "kill $SERVER_PID $TSHARK_PID 2>/dev/null || true" EXIT
sleep 1

echo "==> running client..."
"$BIN" client -server 127.0.0.1:$PORT -secret "$SECRET" -peer 127.0.0.1:9999 \
  > /tmp/lanturn-client.log 2>&1

sleep 1
echo "==> stopping capture..."
sudo kill $TSHARK_PID 2>/dev/null || true
wait $TSHARK_PID 2>/dev/null || true

echo
echo "==> capture: $PCAP"
echo "==> client log: /tmp/lanturn-client.log"
echo "==> server log: /tmp/lanturn-server.log"
echo
echo "==> wire-format checks:"

# Decode the capture as STUN on UDP/3478.
DECODE_OPTS="-d udp.port==$PORT,stun"

echo
echo "--- magic cookie 0x2112a442 at offset 4 ---"
tshark -r "$PCAP" $DECODE_OPTS -Y "stun" -T fields -e stun.cookie 2>/dev/null \
  | sort -u | head -5

echo
echo "--- attribute types observed ---"
tshark -r "$PCAP" $DECODE_OPTS -Y "stun" -T fields -e stun.attribute 2>/dev/null \
  | tr ',' '\n' | sort -u | head -20

echo
echo "--- ChannelData frames (channel range 0x4000-0x7fff) ---"
tshark -r "$PCAP" $DECODE_OPTS -Y "stun.channel" -T fields \
  -e stun.channel -e stun.length 2>/dev/null | head -10

echo
echo "==> validation complete."
