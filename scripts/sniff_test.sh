#!/usr/bin/env bash
# Phase 6 sniff test: capture real loopback traffic and prove nothing leaks.
#
# This is the check from CLAUDE.md §8 Phase 6, packaged so it can be re-run.
# tcpdump needs root to capture, so this script must be run with sudo:
#
#     sudo ./scripts/sniff_test.sh
#
# For an equivalent proof that needs no privileges, use scripts/wire_proof.py.
set -euo pipefail

CANARY="CANARY-9F2A-DO-NOT-LEAK"
CANARY_NAME="ZeldaCanary7Q"
PORT="${PYCHAT_SNIFF_PORT:-8820}"
PASSWORD="sniff-test-throwaway-password"
WORK="${PYCHAT_SNIFF_DIR:-build/sniff-test}"
PCAP="$WORK/pychat.pcap"

# Run the Python parts as the invoking user, not as root, so nothing in the repo or in
# ~/.pychat ends up owned by root.
RUN_AS="${SUDO_USER:-$(id -un)}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYCHAT_PYTHON:-$REPO_ROOT/.venv/bin/python}"

if [[ $EUID -ne 0 ]]; then
  echo "This script needs root for tcpdump. Re-run it as: sudo $0" >&2
  exit 1
fi
if [[ ! -x "$PYTHON" ]]; then
  echo "Python interpreter not found at $PYTHON. Set PYCHAT_PYTHON to override." >&2
  exit 1
fi

rm -rf "$WORK"
mkdir -p "$WORK/server-data"
chown -R "$RUN_AS" "$WORK"

cleanup() {
  [[ -n "${TCPDUMP_PID:-}" ]] && kill "$TCPDUMP_PID" 2>/dev/null || true
  [[ -n "${SERVER_PID:-}" ]] && kill "$SERVER_PID" 2>/dev/null || true
  wait 2>/dev/null || true
}
trap cleanup EXIT

echo "== starting the server on port $PORT =="
sudo -u "$RUN_AS" env \
  PYCHAT_ROOM_PASSWORD="$PASSWORD" \
  PYCHAT_PORT="$PORT" \
  PYCHAT_DATA_DIR="$WORK/server-data" \
  PYCHAT_LOG_LEVEL=INFO \
  "$PYTHON" -m pychat.server >"$WORK/server.log" 2>&1 &
SERVER_PID=$!
for _ in $(seq 1 60); do
  grep -q listening "$WORK/server.log" 2>/dev/null && break
  sleep 0.25
done
grep -q listening "$WORK/server.log" || { echo "server failed to start:"; cat "$WORK/server.log"; exit 1; }

echo "== capturing loopback traffic on port $PORT =="
tcpdump -i lo -s 0 -w "$PCAP" "tcp port $PORT" >"$WORK/tcpdump.log" 2>&1 &
TCPDUMP_PID=$!
sleep 2

echo "== sending the canary from a real client =="
sudo -u "$RUN_AS" env \
  PYCHAT_ROOM_PASSWORD="$PASSWORD" \
  PYCHAT_SNIFF_PORT="$PORT" \
  PYCHAT_SNIFF_NAME="$CANARY_NAME" \
  PYCHAT_SNIFF_TEXT="$CANARY" \
  PYCHAT_SNIFF_KNOWN_HOSTS="$WORK/known_hosts" \
  "$PYTHON" "$REPO_ROOT/scripts/sniff_client.py"

sleep 2
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true
chown "$RUN_AS" "$PCAP" 2>/dev/null || true

echo
echo "== results =="
echo "capture: $PCAP ($(stat -c%s "$PCAP") bytes)"
TEXT_HITS=$(strings "$PCAP" | grep -c "$CANARY" || true)
NAME_HITS=$(strings "$PCAP" | grep -ci "$CANARY_NAME" || true)
PASS_HITS=$(strings "$PCAP" | grep -c "$PASSWORD" || true)
echo "message text  '$CANARY': $TEXT_HITS   (must be 0)"
echo "display name  '$CANARY_NAME': $NAME_HITS   (must be 0)"
echo "room password: $PASS_HITS   (must be 0)"

if [[ "$TEXT_HITS" -eq 0 && "$NAME_HITS" -eq 0 && "$PASS_HITS" -eq 0 ]]; then
  echo
  echo "PASS - no plaintext content, display name or password in the capture"
  exit 0
fi
echo
echo "FAIL - something leaked; do not ship this"
exit 1
