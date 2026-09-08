#!/bin/sh
# Regression test for F-CL-51: infinite loop on EOF/short-read in the
# MAR-record reader -- common/argus_util.c (ArgusReadConnection(),
# ARGUS_FILE case's local-file MAR-header read loop).
#
# After validating the 16-byte cookie header, ArgusReadConnection() reads the
# rest of the fixed-size MAR record in a "while (cnt != size)" loop that
# accumulates bytes from successive fread() calls. The loop's only exit path
# on fread() returning <= 0 (EOF or a persistent read error) was wrapped
# entirely in a /* ... */ comment, so once fread() started returning 0 the
# loop had no way to detect it and called fread() again unconditionally,
# forever: cnt could never reach size without forward progress, and nothing
# else in the loop body could break out. A truncated native or compressed
# input file -- or a decompression subprocess (see F-CL-50's popen() path)
# that exits early or produces less output than expected -- hung the client
# indefinitely, spinning a full CPU core, with no way to make progress or
# exit.
#
# This test proves that a file truncated right after the 16-byte cookie
# header (before the remainder of the fixed-size MAR record has arrived) is
# rejected promptly (process exits on its own, non-zero, well within a
# generous timeout) rather than hanging.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RA_BIN="$REPO_ROOT/bin/ra"
FIXTURE="$SCRIPT_DIR/fixtures/valid_v5_record.argus"

REGRESSION_FAIL_MARKER="$(mktemp -t argus_regress_fcl51.XXXXXX)"
TRUNCATED="$(mktemp -t argus_regress_fcl51_trunc.XXXXXX)"
LOGFILE="$(mktemp -t argus_regress_fcl51_log.XXXXXX)"
trap 'rm -f "$REGRESSION_FAIL_MARKER" "$TRUNCATED" "$LOGFILE"' EXIT

if [ ! -x "$RA_BIN" ]; then
   echo "error: $RA_BIN not found or not executable -- build it first (make -j4)" >&2
   exit 2
fi
if [ ! -f "$FIXTURE" ]; then
   echo "error: $FIXTURE not found" >&2
   exit 2
fi

# Truncate the fixture to 24 bytes: the 16-byte cookie header plus 8 bytes of
# the MAR record body (out of the full ~64+ byte MAR record), so
# ArgusReadConnection() passes the cookie check and enters the accumulation
# loop, then genuinely hits EOF partway through -- the exact condition the
# original bug never handled.
dd if="$FIXTURE" of="$TRUNCATED" bs=1 count=24 2>/dev/null

if [ ! -s "$TRUNCATED" ]; then
   echo "error: failed to create truncated fixture at $TRUNCATED" >&2
   exit 2
fi

# Run in the background under our own timeout so a still-buggy binary that
# hangs forever doesn't hang this test script itself; force-kill and fail if
# it doesn't exit on its own well within a generous window.
HOME=/tmp "$RA_BIN" -r "$TRUNCATED" -c ',' >"$LOGFILE" 2>&1 &
PID=$!

if wait_for_exit "$PID" 50; then
   wait "$PID" 2>/dev/null
   RC=$?
   pass "ra exited on its own after ${ELAPSED_TENTHS} tenths of a second (well within timeout) on a truncated MAR-record file"
   if [ "$RC" -eq 0 ]; then
      fail "ra exited 0 (success) on a genuinely truncated MAR-record file -- expected a non-zero exit"
   else
      pass "ra exited non-zero ($RC) on the truncated MAR-record file as expected"
   fi
else
   kill -9 "$PID" 2>/dev/null
   wait "$PID" 2>/dev/null
   fail "ra did not exit within 5 seconds on a truncated MAR-record file -- F-CL-51 infinite-loop regression (had to force-kill PID $PID; see $LOGFILE)"
fi

if [ -s "$REGRESSION_FAIL_MARKER" ]; then
   exit 1
fi
exit 0
