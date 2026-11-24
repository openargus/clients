#!/bin/sh
# Regression test for scale-aware client Jitter DSR handling.
#
# Synthetic V5 FAR records carry millisecond/second Jitter DSRs.  racluster
# must normalize them to microseconds before merging, preserve both direction
# bits, and avoid narrow intermediate arithmetic for very large counts.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RA_BIN="$REPO_ROOT/bin/ra"
RACLUSTER_BIN="$REPO_ROOT/bin/racluster"
FIXTURE="$SCRIPT_DIR/fixtures/valid_v5_record.argus"

REGRESSION_FAIL_MARKER="$(mktemp -t argus_regress_jitter_scale.XXXXXX)"
TMPDIR_TEST="$(mktemp -d -t argus_regress_jitter_scale_dir.XXXXXX)"
trap 'rm -rf "$TMPDIR_TEST"; rm -f "$REGRESSION_FAIL_MARKER"' EXIT HUP INT TERM

if [ ! -x "$RA_BIN" ] || [ ! -x "$RACLUSTER_BIN" ]; then
   echo "error: bin/ra and bin/racluster must be built first (make -j4)" >&2
   exit 2
fi
if [ ! -f "$FIXTURE" ]; then
   echo "error: $FIXTURE not found" >&2
   exit 2
fi

SCALED_INPUT="$TMPDIR_TEST/scaled.argus"
LARGE_INPUT="$TMPDIR_TEST/large.argus"
DIRECTION_INPUT="$TMPDIR_TEST/direction.argus"

if ! python3 - "$FIXTURE" "$SCALED_INPUT" "$LARGE_INPUT" "$DIRECTION_INPUT" <<'PY'
import struct
import sys

source, scaled_path, large_path, direction_path = sys.argv[1:]
blob = open(source, "rb").read()

mar_words = struct.unpack_from("!H", blob, 2)[0]
mar_end = mar_words * 4
assert blob[0] == 0x85 and mar_end == 128
assert struct.unpack_from("!I", blob, 8)[0] == 0xE57150CB

far_words = struct.unpack_from("!H", blob, mar_end + 2)[0]
far_end = mar_end + far_words * 4
assert blob[mar_end] == 0x15 and far_end == len(blob)
base_far = blob[mar_end:far_end]

def far_with_jitter(qualifier, n, minimum, mean, stdev, maximum):
    record = bytearray(base_far)
    words = struct.unpack_from("!H", record, 2)[0]
    stats = struct.pack("!iffff", n, minimum, mean, stdev, maximum) + b"\0" * 8
    jitter = bytes((0x46, 0x00, qualifier, 0x08)) + stats
    assert len(jitter) == 32
    struct.pack_into("!H", record, 2, words + 8)
    return bytes(record + jitter)

mar = blob[:mar_end]
open(scaled_path, "wb").write(mar +
    far_with_jitter(0x11, 2, 1.0, 2.0, 0.5, 3.0) +
    far_with_jitter(0x21, 3, 0.004, 0.005, 0.001, 0.006))
open(large_path, "wb").write(mar +
    far_with_jitter(0x01, 1500000000, 1000.0, 1000.0, 0.0, 1000.0) +
    far_with_jitter(0x01, 1000000000, 3000.0, 3000.0, 0.0, 3000.0))
open(direction_path, "wb").write(mar +
    far_with_jitter(0x01, 2, 1500.0, 2000.0, 500.0, 2500.0) +
    far_with_jitter(0x04, 3, 4000.0, 5000.0, 1000.0, 6000.0))
PY
then
   echo "error: failed to create synthetic Jitter DSR fixtures" >&2
   exit 2
fi

merge_records() {
   input="$1"
   output="$2"
   label="$3"

   if HOME=/tmp "$RACLUSTER_BIN" -M nocorrect -M norep -r "$input" -w "$output" >"$TMPDIR_TEST/$label.log" 2>&1; then
      pass "$label records merged cleanly"
   else
      fail "$label records did not merge cleanly (see $TMPDIR_TEST/$label.log)"
   fi
}

check_row() {
   file="$1"
   fields="$2"
   expected="$3"
   label="$4"

   HOME=/tmp "$RA_BIN" -r "$file" -n -c ',' -p 6 -s "$fields" >"$TMPDIR_TEST/$label.report" 2>&1
   if [ "$?" -eq 0 ] && grep -Fx "$expected" "$TMPDIR_TEST/$label.report" >/dev/null; then
      pass "$label statistics match the expected merge"
   else
      fail "$label statistics did not match the expected merge (see $TMPDIR_TEST/$label.report)"
   fi
}

check_qualifier() {
   file="$1"
   expected="$2"
   label="$3"

   if python3 - "$file" "$expected" <<'PY'
import struct
import sys

path, expected = sys.argv[1:]
expected = int(expected, 0)
data = open(path, "rb").read()
offset = 0

while offset < len(data):
    if offset + 4 > len(data):
        raise SystemExit("truncated record header")
    record_type, _, words = struct.unpack_from("!BBH", data, offset)
    end = offset + words * 4
    if words == 0 or end > len(data):
        raise SystemExit("invalid record length")
    if (record_type & 0xF0) == 0x10:
        dsr_offset = offset + 4
        while dsr_offset + 4 <= end:
            dsr_type, _, qualifier, dsr_words = struct.unpack_from("!BBBB", data, dsr_offset)
            dsr_end = dsr_offset + dsr_words * 4
            if dsr_words == 0 or dsr_end > end:
                raise SystemExit("invalid DSR length")
            if dsr_type == 0x46:
                if qualifier != expected:
                    raise SystemExit("unexpected jitter qualifier 0x%02x" % qualifier)
                raise SystemExit(0)
            dsr_offset = dsr_end
    offset = end

raise SystemExit("Jitter DSR not found")
PY
   then
      pass "$label Jitter DSR qualifier is preserved"
   else
      fail "$label Jitter DSR qualifier was not preserved"
   fi
}

SCALED_OUTPUT="$TMPDIR_TEST/scaled-merged.argus"
merge_records "$SCALED_INPUT" "$SCALED_OUTPUT" "scaled"
check_row "$SCALED_OUTPUT" "sintpktactmin,sintpktact,sintpktactmax,sjitact" \
   "1.000000,3.800000,6.000000,1.691153" "scaled"
check_qualifier "$SCALED_OUTPUT" 0x01 "scaled"

LARGE_OUTPUT="$TMPDIR_TEST/large-merged.argus"
merge_records "$LARGE_INPUT" "$LARGE_OUTPUT" "large-count"
check_row "$LARGE_OUTPUT" "sintpktact,sjitact" "1.800000,0.979796" "large-count"

DIRECTION_OUTPUT="$TMPDIR_TEST/direction-merged.argus"
merge_records "$DIRECTION_INPUT" "$DIRECTION_OUTPUT" "direction"
check_row "$DIRECTION_OUTPUT" "sintpktact,sjitact,dintpktact,djitact" \
   "2.000000,0.500000,5.000000,1.000000" "direction"
check_qualifier "$DIRECTION_OUTPUT" 0x05 "direction"

if [ -s "$REGRESSION_FAIL_MARKER" ]; then
   exit 1
fi
exit 0
