#!/bin/sh
# Regression coverage for compact sensor-side PRP-1 MAC-DSR v2 support.
#
# Sensors write an 11-word MAC-v2 DSR with unsigned 32-bit LAN totals.
# Clients promote it to their 15-word canonical form with long long totals.
# Check decoding, output conversion, aggregation, and source/destination
# reversal without reintroducing sequence or RCT snapshot state.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
. "$SCRIPT_DIR/lib.sh"

RADSRS_BIN="${RADSRS_BIN:-$REPO_ROOT/bin/radsrs}"
RA_BIN="${RA_BIN:-$REPO_ROOT/bin/ra}"
RACLUSTER_BIN="${RACLUSTER_BIN:-$REPO_ROOT/bin/racluster}"
FIXTURE="$SCRIPT_DIR/fixtures/prp_mac_v2.argus"
TMPDIR_TEST="$(mktemp -d "${TMPDIR:-/tmp}/argus_radsrs_prp_v2.XXXXXX")"
REGRESSION_FAIL_MARKER="$TMPDIR_TEST/fail"
JSON_OUTPUT="$TMPDIR_TEST/prp.jsonseq"
ROUNDTRIP_OUTPUT="$TMPDIR_TEST/roundtrip.argus"
REVERSE_OUTPUT="$TMPDIR_TEST/reverse.argus"
ONE_WAY_FIXTURE="$TMPDIR_TEST/one-way-prp.argus"
ONE_WAY_REVERSE_OUTPUT="$TMPDIR_TEST/one-way-reverse.argus"
AGGREGATE_INPUT="$TMPDIR_TEST/aggregate-input.argus"
AGGREGATE_OUTPUT="$TMPDIR_TEST/aggregate-output.argus"
AGGREGATE_JSON_OUTPUT="$TMPDIR_TEST/aggregate.jsonseq"

cleanup() {
   rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT HUP INT TERM

if [ ! -x "$RADSRS_BIN" ] || [ ! -x "$RA_BIN" ] || [ ! -x "$RACLUSTER_BIN" ]; then
   echo "error: bin/radsrs, bin/ra, and bin/racluster must be built first (make -j4)" >&2
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
   pass "radsrs processed the compact sensor PRP MAC-v2 fixture"
else
   fail "radsrs could not process the PRP MAC-v2 fixture (see $TMPDIR_TEST/radsrs.log)"
fi

if HOME="$TMPDIR_TEST/home" "$RA_BIN" -X -r "$FIXTURE" -w "$ROUNDTRIP_OUTPUT" >"$TMPDIR_TEST/roundtrip.log" 2>&1; then
   pass "ra preserved the compact PRP MAC-v2 fixture"
else
   fail "ra could not preserve the PRP MAC-v2 fixture (see $TMPDIR_TEST/roundtrip.log)"
fi

if HOME="$TMPDIR_TEST/home" "$RA_BIN" -X -M rmon -r "$FIXTURE" -w "$REVERSE_OUTPUT" >"$TMPDIR_TEST/reverse.log" 2>&1; then
   pass "ra produced the rmon-reversed PRP MAC-v2 record"
else
   fail "ra could not reverse the PRP MAC-v2 record (see $TMPDIR_TEST/reverse.log)"
fi

# The fixture carries both direction qualifier bits. Derive a source-only
# variant so reversal also proves that one-sided PRP status follows direction.
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
            if (dsr_type & 0x7f, subtype, dsr_words) == (0x42, 2, 11):
                data[cursor + 2] = (data[cursor + 2] & ~0x0c) | 0x04
                open(output_path, "wb").write(data)
                raise SystemExit(0)
            cursor += dsr_words * 4

    offset = end

raise SystemExit("compact MAC-v2 DSR not found")
PY
then
   pass "derived a source-only compact PRP qualifier fixture"
else
   fail "could not derive a source-only PRP qualifier fixture"
fi

if [ -f "$ONE_WAY_FIXTURE" ] &&
   HOME="$TMPDIR_TEST/home" "$RA_BIN" -X -M rmon -r "$ONE_WAY_FIXTURE" -w "$ONE_WAY_REVERSE_OUTPUT" >"$TMPDIR_TEST/one-way-reverse.log" 2>&1; then
   pass "ra reversed the source-only PRP qualifier fixture"
else
   fail "ra could not reverse the source-only PRP qualifier fixture (see $TMPDIR_TEST/one-way-reverse.log)"
fi

# Give two otherwise-identical sensor records different 32-bit totals. Their
# source LAN-A sum exceeds UINT_MAX, proving client aggregation uses and emits
# the 64-bit canonical counters rather than sensor-width arithmetic.
if python3 - "$FIXTURE" "$AGGREGATE_INPUT" <<'PY'
import struct
import sys

source_path, output_path = sys.argv[1:]
data = open(source_path, "rb").read()
offset = 0
mar = None
far = None

while offset < len(data):
    if len(data) - offset < 4:
        raise SystemExit("truncated record header")
    record_type, _, words = struct.unpack_from("!BBH", data, offset)
    end = offset + words * 4
    if words == 0 or end > len(data):
        raise SystemExit("invalid record length")
    if record_type == 0x85:
        mar = data[offset:end]
    elif (record_type & 0xf0) == 0x10:
        far = data[offset:end]
    offset = end

if mar is None or far is None:
    raise SystemExit("fixture must contain a MAR and FAR")


def set_prp_totals(record, qualifier, src, dst):
    cursor = 4
    while cursor < len(record):
        if len(record) - cursor < 4:
            raise SystemExit("truncated DSR header")
        dsr_type, subtype, _, dsr_words = struct.unpack_from("!BBBB", record, cursor)
        if dsr_words == 0 or cursor + dsr_words * 4 > len(record):
            raise SystemExit("invalid DSR length")
        if (dsr_type & 0x7f, subtype, dsr_words) == (0x42, 2, 11):
            record[cursor + 2] = (record[cursor + 2] & ~0x0c) | qualifier
            struct.pack_into("!III", record, cursor + 20, *src)
            struct.pack_into("!III", record, cursor + 32, *dst)
            return
        cursor += dsr_words * 4
    raise SystemExit("compact MAC-v2 DSR not found")


first = bytearray(far)
second = bytearray(far)
set_prp_totals(first, 0x04, (0x03, 4000000000, 10), (0x00, 0, 0))
set_prp_totals(second, 0x08, (0x04, 500000000, 30), (0x05, 40, 50))
open(output_path, "wb").write(mar + first + second)
PY
then
   pass "built compact PRP records for 64-bit aggregation"
else
   fail "could not build compact PRP aggregation input"
fi

if [ -f "$AGGREGATE_INPUT" ] &&
   HOME="$TMPDIR_TEST/home" "$RACLUSTER_BIN" -M nocorrect -M norep -r "$AGGREGATE_INPUT" -w "$AGGREGATE_OUTPUT" >"$TMPDIR_TEST/aggregate.log" 2>&1; then
   pass "racluster merged compact PRP records"
else
   fail "racluster could not merge compact PRP records (see $TMPDIR_TEST/aggregate.log)"
fi

if [ -f "$AGGREGATE_OUTPUT" ] &&
   HOME="$TMPDIR_TEST/home" "$RADSRS_BIN" -X -r "$AGGREGATE_OUTPUT" >"$AGGREGATE_JSON_OUTPUT" 2>"$TMPDIR_TEST/aggregate-radsrs.log"; then
   pass "radsrs decoded the canonical aggregated PRP record"
else
   fail "radsrs could not decode the canonical aggregated PRP record (see $TMPDIR_TEST/aggregate-radsrs.log)"
fi

if python3 - "$FIXTURE" "$JSON_OUTPUT" "$ROUNDTRIP_OUTPUT" "$REVERSE_OUTPUT" \
               "$ONE_WAY_FIXTURE" "$ONE_WAY_REVERSE_OUTPUT" "$AGGREGATE_OUTPUT" \
               "$AGGREGATE_JSON_OUTPUT" <<'PY'
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
    aggregate_path,
    aggregate_json_path,
) = sys.argv[1:]

SENSOR_MAC_WORDS = 11
CLIENT_MAC_WORDS = 15


def records(path):
    """Return raw records and their DSRs without interpreting payloads."""
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


def mac_dsr(record, words):
    values = [item for item in record["dsrs"] if (item["type"] & 0x7f) == 0x42]
    if len(values) != 1:
        raise AssertionError("expected one MAC DSR, got %d" % len(values))
    value = values[0]
    if (value["subtype"], value["words"]) != (2, words):
        raise AssertionError("MAC DSR has unexpected subtype/length: %r" %
                             ((value["subtype"], value["words"]),))
    return value


def sensor_directions(raw):
    if len(raw) != SENSOR_MAC_WORDS * 4:
        raise AssertionError("unexpected compact sensor MAC-v2 size")
    return (struct.unpack_from("!III", raw, 20),
            struct.unpack_from("!III", raw, 32))


def canonical_directions(raw):
    if len(raw) != CLIENT_MAC_WORDS * 4:
        raise AssertionError("unexpected canonical client MAC-v2 size")
    return (struct.unpack_from("!Iqq", raw, 20),
            struct.unpack_from("!Iqq", raw, 40))


def promoted_mac_wire(raw):
    """Expected client canonical MAC-v2 bytes from an 11-word sensor DSR."""
    result = bytearray(raw[:20])
    for direction in sensor_directions(raw):
        result.extend(struct.pack("!Iqq", *direction))
    result[3] = CLIENT_MAC_WORDS
    return bytes(result)


def reverse_mac_wire(raw):
    """Expected network-order canonical MAC-v2 bytes after reversal."""
    if len(raw) != CLIENT_MAC_WORDS * 4:
        raise AssertionError("unexpected canonical MAC-v2 size")

    result = bytearray(raw)
    qualifier = raw[2]

    # Legacy Ethernet MAC view: destination, source, ether type, dsap, ssap.
    result[4:10] = raw[10:16]
    result[10:16] = raw[4:10]
    result[18] = raw[19]
    result[19] = raw[18]

    result[2] = qualifier & ~0x0c
    if qualifier & 0x04:
        result[2] |= 0x08
    if qualifier & 0x08:
        result[2] |= 0x04
    result[20:40] = raw[40:60]
    result[40:60] = raw[20:40]
    return bytes(result)


fixture_records = records(fixture_path)
if len(fixture_records) != 2 or fixture_records[0]["type"] != 0x85:
    raise AssertionError("fixture must contain its MAR followed by one FAR")
fixture_flows = flow_records(fixture_records)
if len(fixture_flows) != 1:
    raise AssertionError("fixture must contain exactly one flow record")
fixture_flow = fixture_flows[0]
fixture_mac = mac_dsr(fixture_flow, SENSOR_MAC_WORDS)
if (fixture_mac["type"], fixture_mac["qualifier"]) != (0x42, 0x0c):
    raise AssertionError("unexpected compact MAC-v2 fixture header")
sensor_src, sensor_dst = sensor_directions(fixture_mac["raw"])
if (sensor_src, sensor_dst) != ((0x07, 2, 1), (0x05, 1, 0)):
    raise AssertionError("fixture does not contain the expected compact PRP totals")
canonical_mac = promoted_mac_wire(fixture_mac["raw"])

# radsrs preserves original sensor bytes but exposes the promoted 64-bit
# client canonical values in its readable view.
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
    "qualifier": 12,
    "length_words": CLIENT_MAC_WORDS,
}:
    raise AssertionError("wrong canonical MAC-v2 header: %r" % mac.get("header"))
if (mac.get("ether_shost"), mac.get("ether_dhost"), mac.get("ether_type"),
        mac.get("dsap"), mac.get("ssap")) != (
            "02:00:00:00:00:01", "02:00:00:00:00:02", 2048, 0, 0):
    raise AssertionError("wrong canonical legacy MAC fields")
expected_prp = {
    "src": {"flags": 0x07, "lan_a": {"packets": "2"}, "lan_b": {"packets": "1"}},
    "dst": {"flags": 0x05, "lan_a": {"packets": "1"}, "lan_b": {"packets": "0"}},
}
if mac.get("prp") != expected_prp:
    raise AssertionError("wrong canonical compact PRP view: %r" % mac.get("prp"))

# An unmodified `ra -w` record preserves the original sensor wire bytes. The
# canonical form is used when a client generates a modified/derived record.
roundtrip_flows = flow_records(records(roundtrip_path))
if len(roundtrip_flows) != 1:
    raise AssertionError("normal ra output did not contain one PRP FAR")
roundtrip_flow = roundtrip_flows[0]
roundtrip_mac = mac_dsr(roundtrip_flow, SENSOR_MAC_WORDS)
if roundtrip_flow["raw"] != fixture_flow["raw"] or roundtrip_mac["raw"] != fixture_mac["raw"]:
    raise AssertionError("normal ra output did not preserve the sensor MAC-v2 DSR")

# rmon preserves the original sensor record and emits a generated canonical
# reversed copy. Compare complete MAC DSRs so long-long totals and qualifier
# bits are both used by the generated output.
reverse_macs = []
for record in flow_records(records(reverse_path)):
    values = [item for item in record["dsrs"] if (item["type"] & 0x7f) == 0x42]
    if len(values) != 1:
        raise AssertionError("rmon output does not contain one MAC DSR")
    reverse_macs.append(values[0]["raw"])
expected_reverse = reverse_mac_wire(canonical_mac)
if len(reverse_macs) != 2 or fixture_mac["raw"] not in reverse_macs or \
        expected_reverse not in reverse_macs:
    raise AssertionError("rmon did not preserve and reverse canonical MAC-v2 totals")

# Source-only PRP must become destination-only in the rmon copy.
one_way_flow = flow_records(records(one_way_path))
if len(one_way_flow) != 1:
    raise AssertionError("source-only fixture does not contain one flow")
one_way_sensor_mac = mac_dsr(one_way_flow[0], SENSOR_MAC_WORDS)["raw"]
if one_way_sensor_mac[2] != 0x04:
    raise AssertionError("source-only fixture has the wrong MAC qualifier")
one_way_canonical_mac = promoted_mac_wire(one_way_sensor_mac)
one_way_reverse_macs = []
for record in flow_records(records(one_way_reverse_path)):
    values = [item for item in record["dsrs"] if (item["type"] & 0x7f) == 0x42]
    if len(values) != 1:
        raise AssertionError("one-way rmon output does not contain one MAC DSR")
    one_way_reverse_macs.append(values[0]["raw"])
expected_one_way_reverse = reverse_mac_wire(one_way_canonical_mac)
if expected_one_way_reverse[2] != 0x08:
    raise AssertionError("test did not derive the expected destination-only qualifier")
if len(one_way_reverse_macs) != 2 or one_way_sensor_mac not in one_way_reverse_macs or \
        expected_one_way_reverse not in one_way_reverse_macs:
    raise AssertionError("rmon did not reverse the one-sided PRP qualifier")

# Aggregation ORs directional status and adds LAN totals in the client-width
# representation. The LAN-A sum is intentionally larger than UINT_MAX.
aggregate_flows = flow_records(records(aggregate_path))
if len(aggregate_flows) != 1:
    raise AssertionError("racluster did not emit one aggregated PRP FAR")
aggregate_mac = mac_dsr(aggregate_flows[0], CLIENT_MAC_WORDS)
if (aggregate_mac["qualifier"] & 0x0c) != 0x0c:
    raise AssertionError("racluster did not merge PRP direction qualifiers")
if canonical_directions(aggregate_mac["raw"]) != (
        (0x07, 4500000000, 40), (0x05, 40, 50)):
    raise AssertionError("racluster did not retain 64-bit compact PRP totals")

# Reading the generated record back must use the canonical 15-word decoder,
# including byte-order conversion of counters above the sensor-width range.
aggregate_json = [json.loads(value) for value in open(aggregate_json_path, "rb").read().split(b"\x1e") if value.strip()]
aggregate_flow_json = [value for value in aggregate_json if value["record"]["type"] == "flow"]
if len(aggregate_flow_json) != 1:
    raise AssertionError("radsrs did not emit one aggregated PRP JSON record")
aggregate_prp = aggregate_flow_json[0]["canonical"].get("mac", {}).get("prp")
if aggregate_prp != {
    "src": {"flags": 0x07, "lan_a": {"packets": "4500000000"}, "lan_b": {"packets": "40"}},
    "dst": {"flags": 0x05, "lan_a": {"packets": "40"}, "lan_b": {"packets": "50"}},
}:
    raise AssertionError("canonical PRP decoder did not retain 64-bit totals: %r" % aggregate_prp)
PY
then
   pass "PRP JSON, promotion, aggregation, serialization, and reversal are correct"
else
   fail "PRP JSON, promotion, aggregation, serialization, or reversal validation failed"
fi

if [ -s "$REGRESSION_FAIL_MARKER" ]; then
   exit 1
fi
exit 0
