#!/bin/sh
# Regression test for TCP retransmission output fields.
#
# TCP retransmission counters are carried by the TCP performance DSR.  The
# loss output fields read those counters, but retrans/sretrans/dretrans used
# to only inspect UDT DSRs and consequently printed zero for TCP flows.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib.sh"

REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
RA_BIN="$REPO_ROOT/bin/ra"
FIXTURE="$SCRIPT_DIR/fixtures/valid_v5_record.argus"

REGRESSION_FAIL_MARKER="$(mktemp -t argus_regress_tcp_retrans.XXXXXX)"
TMPDIR_TEST="$(mktemp -d -t argus_regress_tcp_retrans_dir.XXXXXX)"
trap 'rm -rf "$TMPDIR_TEST"; rm -f "$REGRESSION_FAIL_MARKER"' EXIT HUP INT TERM

if [ ! -x "$RA_BIN" ]; then
   echo "error: $RA_BIN not found or not executable -- build it first (make -j4)" >&2
   exit 2
fi
if [ ! -f "$FIXTURE" ]; then
   echo "error: $FIXTURE not found" >&2
   exit 2
fi

INPUT="$TMPDIR_TEST/tcp-retrans.argus"
REPORT="$TMPDIR_TEST/report.csv"

if ! python3 - "$FIXTURE" "$INPUT" <<'PY'
import struct
import sys

source, destination = sys.argv[1:]
blob = bytearray(open(source, "rb").read())

mar_words = struct.unpack_from("!H", blob, 2)[0]
mar_end = mar_words * 4
far = bytearray(blob[mar_end:])
record_type, _, far_words = struct.unpack_from("!BBH", far, 0)
assert record_type == 0x15 and far_words * 4 == len(far)

# Use the existing valid FAR record as a container, replacing its UDP flow,
# source-only metric DSR, and empty network DSR with a bidirectional TCP flow
# and a full TCP performance DSR.  This avoids requiring a sensor binary or a
# packet capture to test the client formatter.
tcp_perf = bytearray(128)
tcp_perf[:4] = bytes((0x30, 0x05, 0x02, 0x20))
struct.pack_into("!IIIII", tcp_perf, 4, 0, 4, 0, 0, 0)
# TCP object: src metrics begin at DSR offset 24, dst metrics at offset 76;
# retrans is 32 bytes into each metrics structure.
struct.pack_into("!I", tcp_perf, 56, 46)
struct.pack_into("!I", tcp_perf, 108, 39)

rebuilt = bytearray(far[:4])
offset = 4
found_flow = found_metric = found_network = False

while offset < len(far):
    dsr_type, _, _, dsr_words = struct.unpack_from("!BBBB", far, offset)
    dsr_end = offset + dsr_words * 4
    assert dsr_words and dsr_end <= len(far)
    dsr = bytearray(far[offset:dsr_end])

    if dsr_type == 0x02:  # ARGUS_FLOW_DSR: IPv4 classic 5-tuple
        assert dsr[2] == 0x01
        dsr[12] = 0x06  # IPPROTO_TCP
        found_flow = True
    elif dsr_type == 0x10:  # ARGUS_METER_DSR
        # ARGUS_METER_PKTS_BYTES_APP + ARGUS_SRCDST_SHORT.
        dsr = bytearray((0x10, 0x04, 0x02, 0x04))
        dsr += struct.pack("!HHHHHH", 60, 6000, 5500, 60, 6000, 5500)
        found_metric = True
    elif dsr_type == 0x30:  # ARGUS_NETWORK_DSR
        dsr = tcp_perf
        found_network = True

    rebuilt += dsr
    offset = dsr_end

assert found_flow and found_metric and found_network
assert len(rebuilt) % 4 == 0
struct.pack_into("!H", rebuilt, 2, len(rebuilt) // 4)
open(destination, "wb").write(blob[:mar_end] + rebuilt)
PY
then
   echo "error: failed to create TCP retransmission fixture" >&2
   exit 2
fi

if HOME=/tmp "$RA_BIN" -n -c ',' \
   -s proto,retrans,sretrans,dretrans,loss,sloss,dloss -r "$INPUT" >"$REPORT" 2>&1 && \
   grep -Fx 'tcp,85,46,39,85,46,39' "$REPORT" >/dev/null; then
   pass "TCP retransmission fields match the TCP performance DSR"
else
   fail "TCP retransmission fields were not read from the TCP performance DSR (see $REPORT)"
fi

if [ -s "$REGRESSION_FAIL_MARKER" ]; then
   exit 1
fi
exit 0
