#!/bin/sh
# Smoke and regression coverage for radsrs's native wire-record path.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
. "$REPO_ROOT/security-review/regression-tests/lib.sh"

RADSRS_BIN="$REPO_ROOT/bin/radsrs"
FIXTURE="$REPO_ROOT/security-review/regression-tests/fixtures/valid_v5_record.argus"
REGRESSION_FAIL_MARKER="$(mktemp -t argus_radsrs_fail.XXXXXX)"
TMPDIR_TEST="$(mktemp -d -t argus_radsrs.XXXXXX)"
SERVER_PID=""
CLIENT_PID=""

cleanup() {
   if [ -n "$CLIENT_PID" ]; then
      kill "$CLIENT_PID" 2>/dev/null
      wait "$CLIENT_PID" 2>/dev/null
   fi
   if [ -n "$SERVER_PID" ]; then
      kill "$SERVER_PID" 2>/dev/null
      wait "$SERVER_PID" 2>/dev/null
   fi
   rm -rf "$TMPDIR_TEST"
   rm -f "$REGRESSION_FAIL_MARKER"
}
trap cleanup EXIT HUP INT TERM

if [ ! -x "$RADSRS_BIN" ]; then
   echo "error: $RADSRS_BIN not found or not executable -- build it first (make -j4)" >&2
   exit 2
fi
if [ ! -f "$FIXTURE" ]; then
   echo "error: $FIXTURE not found" >&2
   exit 2
fi

HOME_TEST="$TMPDIR_TEST/home"
mkdir -p "$HOME_TEST"

validate_output() {
   output="$1"
   label="$2"

   if python3 - "$FIXTURE" "$output" <<'PY'
import base64
import json
import struct
import sys

fixture_path, output_path = sys.argv[1:]
fixture = open(fixture_path, "rb").read()
output = open(output_path, "rb").read()
texts = [text.strip() for text in output.split(b"\x1e") if text.strip()]

if len(texts) != 2:
    raise SystemExit("expected two JSON text-sequence values, got %d" % len(texts))

offset = 0
for ordinal, text in enumerate(texts):
    record = json.loads(text.decode("utf-8"))
    words = struct.unpack_from("!H", fixture, offset + 2)[0]
    expected = fixture[offset:offset + words * 4]
    actual = base64.b64decode(record["record"]["raw_base64"])

    if actual != expected:
        raise SystemExit("record %d raw bytes do not round-trip" % ordinal)
    if record["record"]["length_words"] != words:
        raise SystemExit("record %d has the wrong wire length" % ordinal)
    if record["fidelity"] != "exact_native_v3_v5":
        raise SystemExit("record %d did not claim native V3/V5 fidelity" % ordinal)

    if ordinal == 0:
        if record["record"]["type"] != "management":
            raise SystemExit("first record is not a management record")
        if record["canonical"]["management"]["major_version"] != 5:
            raise SystemExit("management record did not decode its major version")
    else:
        if record["record"]["type"] != "flow":
            raise SystemExit("second record is not a flow record")
        dsrs = record["dsrs"]
        rebuilt = b"".join(base64.b64decode(dsr["raw_base64"]) for dsr in dsrs)
        if rebuilt != expected[4:]:
            raise SystemExit("flow DSR order or bytes do not round-trip")
        expected_types = [1, 2, 3, 16, 48, 72, 18, 80, 66, 32, 7]
        if [dsr["ordinal"] for dsr in dsrs] != list(range(len(dsrs))):
            raise SystemExit("flow DSR ordinals are not contiguous")
        if [dsr["type_raw"] for dsr in dsrs] != expected_types:
            raise SystemExit("flow DSR types are not in native wire order")
        if record["canonical"]["flow"]["struct"] != "ArgusFlow":
            raise SystemExit("flow DSR was not decoded as ArgusFlow")

    offset += words * 4

if offset != len(fixture):
    raise SystemExit("fixture contains trailing bytes")
PY
   then
      pass "$label output is valid JSON-seq and round-trips native records"
   else
      fail "$label output did not preserve the native record stream"
   fi
}

FILE_OUTPUT="$TMPDIR_TEST/file.jsonseq"
FILE_LOG="$TMPDIR_TEST/file.log"
if HOME="$HOME_TEST" "$RADSRS_BIN" -X -r "$FIXTURE" >"$FILE_OUTPUT" 2>"$FILE_LOG"; then
   pass "radsrs processed a native file"
   validate_output "$FILE_OUTPUT" "file"
else
   fail "radsrs failed to process a native file (see $FILE_LOG)"
fi

FULL_OUTPUT="$TMPDIR_TEST/full.jsonseq"
FULL_LOG="$TMPDIR_TEST/full.log"
if (
   ulimit -f 1
   trap '' XFSZ
   HOME="$HOME_TEST" "$RADSRS_BIN" -X -r "$FIXTURE" >"$FULL_OUTPUT" 2>"$FULL_LOG"
); then
   fail "radsrs succeeded after its JSON output stream failed"
elif grep -q "unable to write JSON sequence" "$FULL_LOG"; then
   pass "radsrs reports a failed JSON output stream"
else
   fail "radsrs did not report its JSON output-stream failure (see $FULL_LOG)"
fi

READY_FILE="$TMPDIR_TEST/port"
SERVER_LOG="$TMPDIR_TEST/server.log"
REMOTE_OUTPUT="$TMPDIR_TEST/remote.jsonseq"
REMOTE_LOG="$TMPDIR_TEST/remote.log"

python3 - "$FIXTURE" "$READY_FILE" >"$SERVER_LOG" 2>&1 <<'PY' &
import socket
import sys

fixture_path, ready_path = sys.argv[1:]
payload = open(fixture_path, "rb").read()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(10)
    with open(ready_path, "w", encoding="ascii") as ready:
        ready.write("%d\n" % listener.getsockname()[1])

    conn, _ = listener.accept()
    with conn:
        conn.settimeout(10)
        conn.sendall(payload)
        conn.shutdown(socket.SHUT_WR)
        try:
            while conn.recv(4096):
                pass
        except (ConnectionResetError, socket.timeout):
            pass
PY
SERVER_PID=$!

i=0
while [ "$i" -lt 50 ] && [ ! -s "$READY_FILE" ]; do
   sleep 0.1
   i=$((i + 1))
done

if [ ! -s "$READY_FILE" ]; then
   fail "loopback server did not publish a port (see $SERVER_LOG)"
else
   read PORT < "$READY_FILE"
   HOME="$HOME_TEST" "$RADSRS_BIN" -X -S "argus-tcp://127.0.0.1:$PORT" >"$REMOTE_OUTPUT" 2>"$REMOTE_LOG" &
   CLIENT_PID=$!

   if wait_for_exit "$CLIENT_PID" 100; then
      wait "$CLIENT_PID"
      RC=$?
      CLIENT_PID=""
      if [ "$RC" -eq 0 ]; then
         pass "radsrs processed a loopback native server"
         validate_output "$REMOTE_OUTPUT" "remote"
      else
         fail "radsrs exited $RC for the loopback native server (see $REMOTE_LOG)"
      fi
   else
      kill -9 "$CLIENT_PID" 2>/dev/null
      wait "$CLIENT_PID" 2>/dev/null
      CLIENT_PID=""
      fail "radsrs did not exit within 10 seconds for the loopback native server"
   fi
fi

if [ -n "$SERVER_PID" ]; then
   if wait_for_exit "$SERVER_PID" 100; then
      wait "$SERVER_PID" 2>/dev/null
      SERVER_PID=""
   else
      kill -9 "$SERVER_PID" 2>/dev/null
      wait "$SERVER_PID" 2>/dev/null
      SERVER_PID=""
      fail "loopback server did not exit after the client disconnected"
   fi
fi

if [ -s "$REGRESSION_FAIL_MARKER" ]; then
   exit 1
fi
exit 0
