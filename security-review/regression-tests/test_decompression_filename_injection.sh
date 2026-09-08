#!/bin/sh
# Regression test for F-CL-50: popen() shell injection via a double-quoted
# filename in the decompression path -- common/argus_util.c
# (ArgusReadConnection(), ARGUS_FILE case).
#
# ArgusReadConnection() detects a gzip/bzip2/xz/compress magic-number prefix
# on an input file and shells out to the matching decompressor via popen(),
# building the command with the caller-supplied filename interpolated inside
# double quotes: snprintf(cmd, ..., "%s \"%s\" 2>/dev/null", decomp, filename).
# Shell double-quoting does NOT neutralize $(...), backticks, or variable
# expansion -- only single-quoting does. A crafted filename such as
# 'pwned$(some-command).argus.gz' therefore ran arbitrary shell commands as
# the argus-reading process's user, with no attacker-controlled network
# access needed: a malicious/booby-trapped filename anywhere the tool might
# be pointed at "-r <file>" (a shared drop directory, a downloaded archive,
# etc.) is enough.
#
# The fix (see the comment directly above the fixed snprintf() call in
# common/argus_util.c) switched to single-quoting, and added an explicit
# rejection of any filename containing an embedded single quote (since a
# single-quoted shell string cannot itself contain an unescaped single quote)
# rather than trying to escape it.
#
# This test proves both properties end-to-end against the real, built `ra`
# binary, not by inspecting source:
#   1. A gzip-compressed fixture whose filename contains a shell command
#      substitution ("$(touch <marker file>)") does NOT create the marker
#      file when read -- i.e. the substitution is never executed by a shell.
#   2. The record is still read successfully in the ordinary case (valid
#      filename, no metacharacters) -- decompression itself isn't broken.
#   3. A filename containing an embedded single quote is rejected (non-zero
#      exit, no crash) rather than silently mishandled.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RA_BIN="$REPO_ROOT/bin/ra"
FIXTURE="$SCRIPT_DIR/fixtures/valid_v5_record.argus"

REGRESSION_FAIL_MARKER="$(mktemp -t argus_regress_fcl50.XXXXXX)"
trap 'rm -f "$REGRESSION_FAIL_MARKER"' EXIT

if [ ! -x "$RA_BIN" ]; then
   echo "error: $RA_BIN not found or not executable -- build it first (make -j4)" >&2
   exit 2
fi
if [ ! -f "$FIXTURE" ]; then
   echo "error: $FIXTURE not found" >&2
   exit 2
fi

TMPDIR_TEST="$(mktemp -d -t argus_regress_fcl50_dir.XXXXXX)"
trap 'rm -rf "$TMPDIR_TEST"; rm -f "$REGRESSION_FAIL_MARKER"' EXIT

# --- Check 1: command-substitution filename must not execute anything ---------------------
#
# Run with cwd inside TMPDIR_TEST so a relative marker path lands in a known,
# disposable location regardless of what the injected command does with its
# own cwd.

MARKER="pwned_marker"
INJECT_NAME="pwned\$(touch $MARKER).argus.gz"

( cd "$TMPDIR_TEST" && gzip -c "$FIXTURE" > "$INJECT_NAME" )

rm -f "$TMPDIR_TEST/$MARKER"
HOME=/tmp "$RA_BIN" -r "$TMPDIR_TEST/$INJECT_NAME" -c ',' >"$TMPDIR_TEST/inject.out" 2>&1
RC=$?

if [ -f "$TMPDIR_TEST/$MARKER" ]; then
   fail "shell command substitution in filename executed and created $TMPDIR_TEST/$MARKER -- F-CL-50 shell-injection regression"
else
   pass "shell command substitution in filename did not execute (no marker file created)"
fi

if [ "$RC" -eq 0 ] && grep -q "30.0.0.2" "$TMPDIR_TEST/inject.out"; then
   pass "record from the command-substitution-named file was still read correctly (exit 0, expected record present)"
else
   fail "reading the command-substitution-named file did not succeed as expected (exit $RC, see $TMPDIR_TEST/inject.out)"
fi

# --- Check 2: ordinary filename (no metacharacters) still decompresses correctly ------------

PLAIN_NAME="plain_test_file.argus.gz"
( cd "$TMPDIR_TEST" && gzip -c "$FIXTURE" > "$PLAIN_NAME" )

HOME=/tmp "$RA_BIN" -r "$TMPDIR_TEST/$PLAIN_NAME" -c ',' >"$TMPDIR_TEST/plain.out" 2>&1
RC=$?

if [ "$RC" -eq 0 ] && grep -q "30.0.0.2" "$TMPDIR_TEST/plain.out"; then
   pass "ordinary gzip-compressed filename decompresses and reads correctly"
else
   fail "ordinary gzip-compressed filename failed to read correctly (exit $RC, see $TMPDIR_TEST/plain.out)"
fi

# --- Check 3: filename with an embedded single quote is rejected, not crashed --------------

QUOTE_NAME="file's_quote_test.argus.gz"
( cd "$TMPDIR_TEST" && gzip -c "$FIXTURE" > "$QUOTE_NAME" )

HOME=/tmp "$RA_BIN" -r "$TMPDIR_TEST/$QUOTE_NAME" -c ',' >"$TMPDIR_TEST/quote.out" 2>&1
RC=$?

if [ "$RC" -eq 139 ] || [ "$RC" -gt 128 ]; then
   fail "filename with embedded single quote crashed ra (exit $RC, see $TMPDIR_TEST/quote.out)"
elif [ "$RC" -eq 0 ]; then
   fail "filename with embedded single quote was accepted (exit 0) -- expected rejection"
else
   pass "filename with embedded single quote was rejected cleanly (exit $RC)"
fi

if [ -s "$REGRESSION_FAIL_MARKER" ]; then
   exit 1
fi
exit 0
