#!/bin/sh
# Regression test for F-CL-49: unauthenticated remote arbitrary local-file-read
# via the "FILE:" client command -- common/argus_output.c
# (ArgusClientCommands[], ArgusCheckClientMessage()'s RADIUM_FILE case,
# ArgusSendFile()).
#
# This is a STATIC source-code check, not a dynamic network-level test, unlike
# every other script in this directory. Rationale: the fix disables the "FILE:"
# command outright (ArgusClientCommands[RADIUM_FILE] set to NULL, plus the
# handler body commented out) rather than adding validation to a still-live
# code path. Reliably driving this through a live radium/argus-B listener from
# a repo-only harness requires standing up a real client-server session over
# the wire protocol (argus -P <port> as server, a raw socket as client) --
# doable interactively (verified manually during this test's development: a
# raw "FILE:/etc/hosts" request against a live "argus -P" listener returns no
# file content, consistent with this fix), but not something this script
# reproduces end-to-end, since radium's own command-line/config plumbing for
# starting a listener from this repo alone needs further investigation, and a
# static check is precise, fast (no live process/sockets/timing), and exactly
# matches what actually changed. If ArgusClientCommands[RADIUM_FILE] or the
# RADIUM_FILE case body is ever restored, this test will fail immediately.
#
# Checks, all against common/argus_output.c:
#   1. The FILE: string literal is not present anywhere as an *active* (not
#      commented-out) entry in the ArgusClientCommands[] table.
#   2. ArgusClientCommands[RADIUM_FILE] is followed by NULL, not a string.
#   3. The only call to ArgusSendFile() in the RADIUM_FILE case block is
#      inside a /* ... */ comment (i.e. dead code), not live code.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
SRC="$REPO_ROOT/common/argus_output.c"

REGRESSION_FAIL_MARKER="$(mktemp -t argus_regress_fcl49.XXXXXX)"
trap 'rm -f "$REGRESSION_FAIL_MARKER"' EXIT

if [ ! -f "$SRC" ]; then
   echo "error: $SRC not found" >&2
   exit 2
fi

# --- Check 1: ArgusClientCommands[] table entry for RADIUM_FILE is NULL --------------------
#
# The table is a fixed initializer list; the RADIUM_FILE (index 5, the last
# entry before the closing brace) slot must be exactly "NULL," on its own
# line (allowing surrounding whitespace), not a quoted "FILE:" string.

TABLE_BLOCK="$(awk '/^char \*ArgusClientCommands\[ARGUSMAXCLIENTCOMMANDS\]/,/^};/' "$SRC")"

if [ -z "$TABLE_BLOCK" ]; then
   fail "could not locate the ArgusClientCommands[] table in $SRC -- has this been renamed/restructured?"
else
   if printf '%s\n' "$TABLE_BLOCK" | grep -qE '^\s*"FILE:"\s*,?\s*$'; then
      fail "ArgusClientCommands[] table contains an active \"FILE:\" entry -- F-CL-49 regression: the FILE: command has been re-enabled"
   else
      pass "ArgusClientCommands[] table has no active \"FILE:\" string entry"
   fi

   if printf '%s\n' "$TABLE_BLOCK" | grep -qE '^\s*NULL\s*,?\s*$'; then
      pass "ArgusClientCommands[] table's last entry is NULL as expected"
   else
      fail "ArgusClientCommands[] table's last entry is not NULL -- F-CL-49 regression: the RADIUM_FILE slot may have been restored to a non-NULL value"
   fi
fi

# --- Check 2: the RADIUM_FILE case's ArgusSendFile() call is inside a comment --------------
#
# Extract the case RADIUM_FILE: { ... } block (up to the next "case " or the
# closing of the switch) and confirm that the only occurrence of
# "ArgusSendFile (output, client, file, 0)" within it is preceded by a "/*"
# with no intervening "*/" (i.e. it is commented out).

CASE_BLOCK="$(awk '/case RADIUM_FILE: \{/{flag=1} flag{print} flag && /^ *\}$/{if (++n==1) exit}' "$SRC")"

if [ -z "$CASE_BLOCK" ]; then
   fail "could not locate the 'case RADIUM_FILE:' block in $SRC -- has this been renamed/restructured?"
else
   if printf '%s\n' "$CASE_BLOCK" | grep -q 'ArgusSendFile (output, client, file, 0);'; then
      # The call text is present (expected -- it's still there as commented-out
      # dead code). Confirm it appears strictly between a "/*" and the block's
      # matching "*/", i.e. the call line itself is not live, compiled code.
      if printf '%s\n' "$CASE_BLOCK" | awk '
         /\/\*/ { incomment=1 }
         /ArgusSendFile \(output, client, file, 0\);/ { if (incomment) found_in_comment=1; else found_live=1 }
         /\*\// { incomment=0 }
         END { exit !(found_in_comment && !found_live) }
      '; then
         pass "ArgusSendFile() call in the RADIUM_FILE case is inside a comment (dead code), not live"
      else
         fail "ArgusSendFile() call in the RADIUM_FILE case does not appear to be safely commented out -- F-CL-49 regression risk"
      fi
   else
      fail "ArgusSendFile() call text not found at all in the RADIUM_FILE case block -- unexpected structural change, please verify manually"
   fi
fi

if [ -s "$REGRESSION_FAIL_MARKER" ]; then
   exit 1
fi
exit 0
