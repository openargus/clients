#!/bin/sh
# Regression coverage for client-side PRP-1 MAC-DSR v2 support.
#
# The retained fixture was emitted by the sensor from deterministic PRP frames.
# Check all three client paths that must understand its 67-word MAC DSR:
#
#   * radsrs's canonical JSON view, including the host-order PRP values;
#   * normal ra read/write, which must preserve the complete v2 wire DSR; and
#   * rmon reversal, which must exchange the v2 directions and their qualifier
#     bits before serializing the result.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
. "$SCRIPT_DIR/lib.sh"

RADSRS_BIN="${RADSRS_BIN:-$REPO_ROOT/bin/radsrs}"
RA_BIN="${RA_BIN:-$REPO_ROOT/bin/ra}"
FIXTURE="$SCRIPT_DIR/fixtures/prp_mac_v2.argus"
TMPDIR_TEST="$(mktemp -d "${TMPDIR:-/tmp}/argus_radsrs_prp_v2.XXXXXX")"
REGRESSION_FAIL_MARKER="$TMPDIR_TEST/fail"
JSON_OUTPUT="$TMPDIR_TEST/prp.jsonseq"
ROUNDTRIP_OUTPUT="$TMPDIR_TEST/roundtrip.argus"
REVERSE_OUTPUT="$TMPDIR_TEST/reverse.argus"
ONE_WAY_FIXTURE="$TMPDIR_TEST/one-way-prp.argus"
ONE_WAY_REVERSE_OUTPUT="$TMPDIR_TEST/one-way-reverse.argus"

cleanup() {
   rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT HUP INT TERM

if [ ! -x "$RADSRS_BIN" ]; then
   echo "error: $RADSRS_BIN not found or not executable -- build it first (make -j4)" >&2
   exit 2
fi
if [ ! -x "$RA_BIN" ]; then
   echo "error: $RA_BIN not found or not executable -- build it first (make -j4)" >&2
   exit 2
fi
if [ ! -f "$FIXTURE" ]; then
   echo "error: $FIXTURE not found" >&2
   exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
   echo "error: python3 is required for the PRP MAC-v2 regression test" >&2
   exit 2
fi

mkdir -p "$TMPDIR_TEST/home"

if HOME="$TMPDIR_TEST/home" "$RADSRS_BIN" -X -r "$FIXTURE" >"$JSON_OUTPUT" 2>"$TMPDIR_TEST/radsrs.log"; then
   pass "radsrs processed the sensor-produced PRP MAC-v2 fixture"
else
   fail "radsrs could not process the PRP MAC-v2 fixture (see $TMPDIR_TEST/radsrs.log)"
fi

if HOME="$TMPDIR_TEST/home" "$RA_BIN" -X -r "$FIXTURE" -w "$ROUNDTRIP_OUTPUT" >"$TMPDIR_TEST/roundtrip.log" 2>&1; then
   pass "ra read and rewrote the PRP MAC-v2 fixture"
else
   fail "ra could not rewrite the PRP MAC-v2 fixture (see $TMPDIR_TEST/roundtrip.log)"
fi

if HOME="$TMPDIR_TEST/home" "$RA_BIN" -X -M rmon -r "$FIXTURE" -w "$REVERSE_OUTPUT" >"$TMPDIR_TEST/reverse.log" 2>&1; then
   pass "ra produced the rmon-reversed PRP MAC-v2 record"
else
   fail "ra could not reverse the PRP MAC-v2 record (see $TMPDIR_TEST/reverse.log)"
fi

# The fixture carries both direction qualifier bits.  Derive a source-only
# variant so the reversal check also detects a regression that swaps the
# observations but leaves a one-sided qualifier unchanged.
if python3 - "$FIXTURE" "$ONE_WAY_FIXTURE" <<'PY'
import struct
import sys

source_path, output_path = sys.argv[1:]
data = bytearray(open(source_path, "rb").read())
offset = 0

while offset < len(data):
    if len(data) - offset < 4:
        raise SystemExit("truncated record header")
    record_type, _, words = struct.unpack_from("!BBH", data, offset)
    end = offset + words * 4
    if words == 0 or end > len(data):
        raise SystemExit("invalid record length")

    if (record_type & 0xf0) == 0x10:
        cursor = offset + 4
        while cursor < end:
            if end - cursor < 4:
                raise SystemExit("truncated DSR header")
            dsr_type, subtype, _, dsr_words = struct.unpack_from("!BBBB", data, cursor)
            if dsr_words == 0 or cursor + dsr_words * 4 > end:
                raise SystemExit("invalid DSR length")
            if (dsr_type & 0x7f, subtype, dsr_words) == (0x42, 2, 67):
                # Preserve legacy qualifier bits and retain only source PRP.
                data[cursor + 2] = (data[cursor + 2] & ~0x0c) | 0x04
                open(output_path, "wb").write(data)
                raise SystemExit(0)
            cursor += dsr_words * 4

    offset = end

raise SystemExit("MAC-v2 DSR not found")
PY
then
   pass "derived a source-only PRP qualifier fixture"
else
   fail "could not derive a source-only PRP qualifier fixture"
fi

if [ -f "$ONE_WAY_FIXTURE" ] &&
   HOME="$TMPDIR_TEST/home" "$RA_BIN" -X -M rmon -r "$ONE_WAY_FIXTURE" -w "$ONE_WAY_REVERSE_OUTPUT" >"$TMPDIR_TEST/one-way-reverse.log" 2>&1; then
   pass "ra reversed the source-only PRP qualifier fixture"
else
   fail "ra could not reverse the source-only PRP qualifier fixture (see $TMPDIR_TEST/one-way-reverse.log)"
fi

if python3 - "$FIXTURE" "$JSON_OUTPUT" "$ROUNDTRIP_OUTPUT" "$REVERSE_OUTPUT" \
              "$ONE_WAY_FIXTURE" "$ONE_WAY_REVERSE_OUTPUT" <<'PY'
import base64
import json
import struct
import sys

(
    fixture_path,
    json_path,
    roundtrip_path,
    reverse_path,
    one_way_path,
    one_way_reverse_path,
) = sys.argv[1:]


def records(path):
    """Return raw records and their DSRs without interpreting their payloads."""
    data = open(path, "rb").read()
    offset = 0
    result = []

    while offset < len(data):
        if len(data) - offset < 4:
            raise AssertionError("%s has a truncated record header" % path)
        record_type, cause, words = struct.unpack_from("!BBH", data, offset)
        end = offset + words * 4
        if words == 0 or end > len(data):
            raise AssertionError("%s has an invalid record length" % path)

        dsrs = []
        if (record_type & 0xf0) == 0x10:
            cursor = offset + 4
            while cursor < end:
                if end - cursor < 4:
                    raise AssertionError("%s has a truncated DSR header" % path)
                dsr_type, subtype, qualifier, short_words = struct.unpack_from("!BBBB", data, cursor)
                if dsr_type & 0x80:
                    dsr_words = 1
                elif subtype & 0x80:
                    dsr_words = struct.unpack_from("!H", data, cursor + 2)[0]
                else:
                    dsr_words = short_words
                if dsr_words == 0 or cursor + dsr_words * 4 > end:
                    raise AssertionError("%s has an invalid DSR length" % path)
                dsrs.append({
                    "type": dsr_type,
                    "subtype": subtype,
                    "qualifier": qualifier,
                    "words": dsr_words,
                    "offset": cursor,
                    "raw": data[cursor:cursor + dsr_words * 4],
                })
                cursor += dsr_words * 4
            if cursor != end:
                raise AssertionError("%s DSR chain does not end on the record boundary" % path)

        result.append({
            "type": record_type,
            "cause": cause,
            "words": words,
            "offset": offset,
            "raw": data[offset:end],
            "dsrs": dsrs,
        })
        offset = end

    return result


def flow_records(items):
    return [item for item in items if (item["type"] & 0xf0) == 0x10]


def mac_dsr(record):
    values = [item for item in record["dsrs"] if (item["type"] & 0x7f) == 0x42]
    if len(values) != 1:
        raise AssertionError("expected one MAC DSR, got %d" % len(values))
    value = values[0]
    if (value["subtype"], value["words"]) != (2, 67):
        raise AssertionError("MAC DSR is not a 67-word v2 DSR: %r" %
                             ((value["subtype"], value["words"]),))
    return value


def reverse_mac_wire(raw):
    """Expected network-order MAC-v2 bytes after ArgusReverseRecord()."""
    if len(raw) != 67 * 4:
        raise AssertionError("unexpected MAC-v2 size")

    result = bytearray(raw)
    qualifier = raw[2]

    # Legacy Ethernet MAC view: destination, source, ether type, dsap, ssap.
    result[4:10] = raw[10:16]
    result[10:16] = raw[4:10]
    result[18] = raw[19]
    result[19] = raw[18]

    # MAC-v2 source/destination qualifier bits and the complete PRP snapshots.
    result[2] = qualifier & ~0x0c
    if qualifier & 0x04:
        result[2] |= 0x08
    if qualifier & 0x08:
        result[2] |= 0x04
    result[20:144] = raw[144:268]
    result[144:268] = raw[20:144]
    return bytes(result)


def check_rct(actual, sequence, lan_size, sec, usec):
    expected = {
        "sequence": sequence,
        "lan_id_and_lsdu_size": lan_size,
        "lan_id": lan_size >> 12,
        "lsdu_size": lan_size & 0x0fff,
        "time": {"tv_sec": sec, "tv_usec": usec},
    }
    if actual != expected:
        raise AssertionError("wrong RCT snapshot: %r != %r" % (actual, expected))


def check_lan(actual, counters, first, last):
    expected_counters = {
        "packets": str(counters[0]),
        "gaps": str(counters[1]),
        "out_of_order": str(counters[2]),
        "duplicates": str(counters[3]),
    }
    for name, expected in expected_counters.items():
        if actual.get(name) != expected:
            raise AssertionError("wrong %s counter: %r != %r" %
                                 (name, actual.get(name), expected))
    check_rct(actual.get("first"), *first)
    check_rct(actual.get("last"), *last)


fixture_records = records(fixture_path)
if len(fixture_records) != 2 or fixture_records[0]["type"] != 0x85:
    raise AssertionError("fixture must contain its MAR followed by one FAR")
fixture_flows = flow_records(fixture_records)
if len(fixture_flows) != 1:
    raise AssertionError("fixture must contain exactly one flow record")
fixture_flow = fixture_flows[0]
fixture_mac = mac_dsr(fixture_flow)
if (fixture_mac["type"], fixture_mac["qualifier"]) != (0x42, 0x0d):
    raise AssertionError("unexpected MAC-v2 fixture header")

# radsrs must retain every source record byte-for-byte while exposing the
# already-NtoH-converted PRP fields in canonical.mac.prp.
json_values = [json.loads(value) for value in open(json_path, "rb").read().split(b"\x1e") if value.strip()]
if len(json_values) != len(fixture_records):
    raise AssertionError("expected %d JSON sequence values, got %d" %
                         (len(fixture_records), len(json_values)))
for source, value in zip(fixture_records, json_values):
    raw = base64.b64decode(value["record"]["raw_base64"], validate=True)
    if raw != source["raw"]:
        raise AssertionError("radsrs raw record did not preserve source bytes")
    if value["record"]["length_words"] != source["words"]:
        raise AssertionError("radsrs reported the wrong raw record length")
    if value["fidelity"] != "exact_native_v3_v5":
        raise AssertionError("radsrs did not report native-record fidelity")
    if source["dsrs"]:
        dsr_bytes = b"".join(base64.b64decode(dsr["raw_base64"], validate=True)
                             for dsr in value["dsrs"])
        if dsr_bytes != source["raw"][4:]:
            raise AssertionError("radsrs DSR bytes did not preserve wire order")

flow_json = [value for value in json_values if value["record"]["type"] == "flow"]
if len(flow_json) != 1:
    raise AssertionError("expected one flow JSON object")
mac = flow_json[0]["canonical"].get("mac")
if not mac or mac.get("struct") != "ArgusMacStruct":
    raise AssertionError("radsrs did not canonically decode the MAC DSR")
if mac.get("header") != {
    "type": 66,
    "name": "mac",
    "subtype": 2,
    "qualifier": 13,
    "length_words": 67,
}:
    raise AssertionError("wrong canonical MAC-v2 header: %r" % mac.get("header"))
if (mac.get("ether_shost"), mac.get("ether_dhost"), mac.get("ether_type"),
        mac.get("dsap"), mac.get("ssap")) != (
            "02:00:00:00:00:01", "02:00:00:00:00:02", 2048, 0, 0):
    raise AssertionError("wrong canonical legacy MAC fields")

prp = mac.get("prp")
if not prp or set(prp) != {"src", "dst"}:
    raise AssertionError("radsrs did not expose both PRP directions")
src = prp["src"]
dst = prp["dst"]
if (src.get("flags"), src.get("malformed_rcts")) != (15, "1"):
    raise AssertionError("wrong source PRP flags or malformed total")
if (dst.get("flags"), dst.get("malformed_rcts")) != (13, "1"):
    raise AssertionError("wrong destination PRP flags or malformed total")
check_lan(src["lan_a"], (4, 1, 1, 1),
          (100, 0xa000 | 35, 1, 100000000),
          (101, 0xa000 | 35, 1, 140000000))
check_lan(src["lan_b"], (3, 1, 0, 0),
          (100, 0xb000 | 35, 1, 110000000),
          (103, 0xb000 | 35, 1, 200000000))
check_lan(dst["lan_a"], (2, 0, 1, 0),
          (500, 0xa000 | 35, 1, 160000000),
          (499, 0xa000 | 35, 1, 170000000))
check_lan(dst["lan_b"], (0, 0, 0, 0),
          (0, 0, 0, 0), (0, 0, 0, 0))

# ra's normal output reaches ArgusHtoN() after canonicalization.  Its FAR,
# including the MAC-v2 DSR, must exactly reproduce the sensor's wire bytes.
roundtrip_flows = flow_records(records(roundtrip_path))
if len(roundtrip_flows) != 1 or roundtrip_flows[0]["raw"] != fixture_flow["raw"]:
    raise AssertionError("normal ra output did not round-trip the PRP FAR")
if mac_dsr(roundtrip_flows[0])["raw"] != fixture_mac["raw"]:
    raise AssertionError("normal ra output did not round-trip the MAC-v2 DSR")

# rmon emits the original and a reversed copy.  Compare complete wire DSRs so
# every counter/RCT field, not only the displayed counters, is covered.
reverse_macs = [mac_dsr(record)["raw"] for record in flow_records(records(reverse_path))]
expected_reverse = reverse_mac_wire(fixture_mac["raw"])
if len(reverse_macs) != 2 or fixture_mac["raw"] not in reverse_macs or \
        expected_reverse not in reverse_macs:
    raise AssertionError("rmon did not preserve and reverse the full MAC-v2 DSR")

# Source-only PRP must become destination-only in the rmon copy.  This catches
# a qualifier-bit regression that the fixture's both-directions header cannot.
one_way_flow = flow_records(records(one_way_path))
if len(one_way_flow) != 1:
    raise AssertionError("source-only fixture does not contain one flow")
one_way_mac = mac_dsr(one_way_flow[0])["raw"]
if one_way_mac[2] != 0x05:
    raise AssertionError("source-only fixture has the wrong MAC qualifier")
one_way_reverse_macs = [mac_dsr(record)["raw"]
                        for record in flow_records(records(one_way_reverse_path))]
expected_one_way_reverse = reverse_mac_wire(one_way_mac)
if expected_one_way_reverse[2] != 0x09:
    raise AssertionError("test did not derive the expected destination-only qualifier")
if len(one_way_reverse_macs) != 2 or one_way_mac not in one_way_reverse_macs or \
        expected_one_way_reverse not in one_way_reverse_macs:
    raise AssertionError("rmon did not reverse the one-sided PRP qualifier")
PY
then
   pass "radsrs PRP JSON, wire round-trip, and direction reversal are correct"
else
   fail "PRP MAC-v2 JSON, wire round-trip, or direction reversal validation failed"
fi

if [ -s "$REGRESSION_FAIL_MARKER" ]; then
   exit 1
fi
exit 0
