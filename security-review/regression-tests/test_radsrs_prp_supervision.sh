#!/bin/sh
# Regression coverage for the fixed-size PRP supervision Network DSR.
#
# Verify client byte-order conversion and JSON, raw pass-through, exact-length
# canonicalization, role-preserving inventory aggregation, conflict handling,
# and reversal behavior without treating observations as directional fields.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
. "$SCRIPT_DIR/lib.sh"

RADSRS_BIN="${RADSRS_BIN:-$REPO_ROOT/bin/radsrs}"
RA_BIN="${RA_BIN:-$REPO_ROOT/bin/ra}"
RACLUSTER_BIN="${RACLUSTER_BIN:-$REPO_ROOT/bin/racluster}"
BASE_FIXTURE="$SCRIPT_DIR/fixtures/prp_mac_v2.argus"
TMPDIR_TEST="$(mktemp -d "${TMPDIR:-/tmp}/argus_radsrs_prp_supervision.XXXXXX")"
REGRESSION_FAIL_MARKER="$TMPDIR_TEST/fail"
MERGE_INPUT="$TMPDIR_TEST/merge-input.argus"
INVALID_INPUT="$TMPDIR_TEST/invalid-length.argus"
INPUT_JSON="$TMPDIR_TEST/input.jsonseq"
INVALID_JSON="$TMPDIR_TEST/invalid.jsonseq"
ROUNDTRIP_OUTPUT="$TMPDIR_TEST/roundtrip.argus"
REVERSE_OUTPUT="$TMPDIR_TEST/reverse.argus"
MERGE_OUTPUT="$TMPDIR_TEST/merge-output.argus"
MERGE_JSON="$TMPDIR_TEST/merge.jsonseq"
EXPECTED_JSON="$TMPDIR_TEST/expected.json"

cleanup() {
   rm -rf "$TMPDIR_TEST"
}
trap cleanup EXIT HUP INT TERM

if [ ! -x "$RADSRS_BIN" ] || [ ! -x "$RA_BIN" ] || [ ! -x "$RACLUSTER_BIN" ]; then
   echo "error: bin/radsrs, bin/ra, and bin/racluster must be built first (make -j4)" >&2
   exit 2
fi
if [ ! -f "$BASE_FIXTURE" ]; then
   echo "error: $BASE_FIXTURE not found" >&2
   exit 2
fi
if ! command -v python3 >/dev/null 2>&1; then
   echo "error: python3 is required for the PRP supervision regression test" >&2
   exit 2
fi

mkdir -p "$TMPDIR_TEST/home"

if python3 - "$BASE_FIXTURE" "$MERGE_INPUT" "$INVALID_INPUT" "$EXPECTED_JSON" <<'PY'
import json
import struct
import sys

base_path, merge_path, invalid_path, expected_path = sys.argv[1:]

PRESENT = 0x00000001
VALID = 0x00000002
HAS_SEQUENCE = 0x00000010
REPORTER = 0x00000020
NODE_A = 0x00000040
NODE_B = 0x00000080
REDBOX = 0x00000100
VDAN = 0x00000200
EOT = 0x00000400
PADDING = 0x00000800
CLAIM_CONFLICT = 0x00001000


def records(data):
    offset = 0
    values = []
    while offset < len(data):
        if len(data) - offset < 4:
            raise SystemExit("truncated record header")
        kind, _, words = struct.unpack_from("!BBH", data, offset)
        end = offset + words * 4
        if words == 0 or end > len(data):
            raise SystemExit("invalid record length")
        values.append((kind, data[offset:end]))
        offset = end
    return values


def supervision(flags, version, sequence, path, node_mode, reporter,
                node_a, node_b, redbox, vdan):
    value = struct.pack("!IHHBB", flags, version, sequence, path, node_mode)
    value += reporter + node_a + node_b + redbox + vdan
    assert len(value) == 40
    return bytes((0x30, 0x46, 0, 11)) + value


def append_dsr(record, dsr):
    result = bytearray(record)
    old_words = struct.unpack_from("!H", result, 2)[0]
    if old_words * 4 != len(result) or len(dsr) % 4:
        raise SystemExit("invalid base FAR")
    struct.pack_into("!H", result, 2, old_words + len(dsr) // 4)
    result.extend(dsr)
    return bytes(result)


base_records = records(open(base_path, "rb").read())
mar = next((value for kind, value in base_records if kind == 0x85), None)
far = next((value for kind, value in base_records if (kind & 0xf0) == 0x10), None)
if mar is None or far is None:
    raise SystemExit("base fixture must contain a MAR and FAR")

first = {
    "flags": PRESENT | VALID | HAS_SEQUENCE | REPORTER | NODE_A | NODE_B |
             REDBOX | VDAN | EOT,
    "version": 1,
    "sequence": 0x1234,
    "path": 1,
    "node_mode": 20,
    "reporter": bytes.fromhex("020000000001"),
    "node_a": bytes.fromhex("0200000000aa"),
    "node_b": bytes.fromhex("0200000000bb"),
    "redbox": bytes.fromhex("0200000000cc"),
    "vdan": bytes.fromhex("0200000000dd"),
}
second = {
    "flags": PRESENT | VALID | HAS_SEQUENCE | REPORTER | NODE_A | NODE_B |
             REDBOX | VDAN | PADDING,
    "version": 1,
    "sequence": 0x4321,
    "path": 1,
    "node_mode": 20,
    "reporter": bytes.fromhex("020000000002"),
    "node_a": bytes.fromhex("0200000000ab"),
    "node_b": bytes.fromhex("0200000000bc"),
    "redbox": bytes.fromhex("0200000000cd"),
    "vdan": bytes.fromhex("0200000000de"),
}

first_dsr = supervision(**first)
second_dsr = supervision(**second)
first_far = append_dsr(far, first_dsr)
second_far = append_dsr(far, second_dsr)

# Structurally valid record/DSR framing but the wrong PRP DSR size.  Clients
# must preserve raw input while refusing to project undersized union bytes.
bad_dsr = bytes((0x30, 0x46, 0, 10)) + (b"\x00" * 36)
bad_far = append_dsr(far, bad_dsr)

open(merge_path, "wb").write(mar + first_far + second_far)
open(invalid_path, "wb").write(mar + bad_far)
with open(expected_path, "w", encoding="utf-8") as output:
    json.dump({
        "first_dsr": first_dsr.hex(),
        "second_dsr": second_dsr.hex(),
        "first_far": first_far.hex(),
        "second_far": second_far.hex(),
        "first": {key: (value.hex() if isinstance(value, bytes) else value)
                  for key, value in first.items()},
        "second": {key: (value.hex() if isinstance(value, bytes) else value)
                   for key, value in second.items()},
        "merged_flags": first["flags"] | second["flags"] | CLAIM_CONFLICT,
    }, output, sort_keys=True)
PY
then
   pass "built PRP supervision client fixtures"
else
   fail "could not build PRP supervision client fixtures"
fi

if HOME="$TMPDIR_TEST/home" "$RADSRS_BIN" -X -r "$MERGE_INPUT" >"$INPUT_JSON" 2>"$TMPDIR_TEST/input-radsrs.log"; then
   pass "radsrs decoded PRP supervision fixtures"
else
   fail "radsrs could not decode PRP supervision fixtures (see $TMPDIR_TEST/input-radsrs.log)"
fi

if HOME="$TMPDIR_TEST/home" "$RA_BIN" -X -r "$MERGE_INPUT" -w "$ROUNDTRIP_OUTPUT" >"$TMPDIR_TEST/roundtrip.log" 2>&1; then
   pass "ra preserved PRP supervision fixtures"
else
   fail "ra could not preserve PRP supervision fixtures (see $TMPDIR_TEST/roundtrip.log)"
fi

if HOME="$TMPDIR_TEST/home" "$RA_BIN" -X -M rmon -r "$MERGE_INPUT" -w "$REVERSE_OUTPUT" >"$TMPDIR_TEST/reverse.log" 2>&1; then
   pass "ra produced rmon-reversed PRP supervision records"
else
   fail "ra could not reverse PRP supervision fixtures (see $TMPDIR_TEST/reverse.log)"
fi

if HOME="$TMPDIR_TEST/home" "$RACLUSTER_BIN" -M nocorrect -M norep -r "$MERGE_INPUT" -w "$MERGE_OUTPUT" >"$TMPDIR_TEST/merge.log" 2>&1; then
   pass "racluster merged PRP supervision observations"
else
   fail "racluster could not merge PRP supervision observations (see $TMPDIR_TEST/merge.log)"
fi

if HOME="$TMPDIR_TEST/home" "$RADSRS_BIN" -X -r "$MERGE_OUTPUT" >"$MERGE_JSON" 2>"$TMPDIR_TEST/merge-radsrs.log"; then
   pass "radsrs decoded merged PRP supervision observations"
else
   fail "radsrs could not decode merged PRP supervision observations (see $TMPDIR_TEST/merge-radsrs.log)"
fi

if HOME="$TMPDIR_TEST/home" "$RADSRS_BIN" -X -r "$INVALID_INPUT" >"$INVALID_JSON" 2>"$TMPDIR_TEST/invalid-radsrs.log"; then
   pass "radsrs handled an invalid-length PRP Network DSR"
else
   fail "radsrs could not handle the invalid-length PRP Network DSR (see $TMPDIR_TEST/invalid-radsrs.log)"
fi

if python3 - "$EXPECTED_JSON" "$INPUT_JSON" "$ROUNDTRIP_OUTPUT" \
                "$REVERSE_OUTPUT" "$MERGE_OUTPUT" "$MERGE_JSON" "$INVALID_JSON" <<'PY'
from collections import Counter
import json
import struct
import sys

(
    expected_path,
    input_json_path,
    roundtrip_path,
    reverse_path,
    merge_path,
    merge_json_path,
    invalid_json_path,
) = sys.argv[1:]
expected = json.load(open(expected_path, encoding="utf-8"))

NETWORK_TYPE = 0x30
NETWORK_SUBTYPE_PRP = 0x46
NETWORK_WORDS_PRP = 11


def records(path):
    data = open(path, "rb").read()
    offset = 0
    values = []
    while offset < len(data):
        if len(data) - offset < 4:
            raise AssertionError("truncated record header in " + path)
        kind, cause, words = struct.unpack_from("!BBH", data, offset)
        end = offset + words * 4
        if words == 0 or end > len(data):
            raise AssertionError("invalid record length in " + path)
        dsrs = []
        if (kind & 0xf0) == 0x10:
            cursor = offset + 4
            while cursor < end:
                if end - cursor < 4:
                    raise AssertionError("truncated DSR header in " + path)
                dtype, subtype, _, short_words = struct.unpack_from("!BBBB", data, cursor)
                if dtype & 0x80:
                    dwords = 1
                elif subtype & 0x80:
                    dwords = struct.unpack_from("!H", data, cursor + 2)[0]
                else:
                    dwords = short_words
                if dwords == 0 or cursor + dwords * 4 > end:
                    raise AssertionError("invalid DSR length in " + path)
                dsrs.append((dtype, subtype, cursor, dwords, data[cursor:cursor + dwords * 4]))
                cursor += dwords * 4
            if cursor != end:
                raise AssertionError("DSR chain did not end on record boundary in " + path)
        values.append({"type": kind, "cause": cause, "raw": data[offset:end], "dsrs": dsrs})
        offset = end
    return values


def flow_records(path):
    return [record for record in records(path) if (record["type"] & 0xf0) == 0x10]


def prp_dsr(record):
    matches = [raw for dtype, subtype, _, words, raw in record["dsrs"]
               if (dtype & 0x7f) == NETWORK_TYPE and subtype == NETWORK_SUBTYPE_PRP]
    if len(matches) != 1:
        raise AssertionError("expected exactly one PRP Network DSR")
    raw = matches[0]
    if len(raw) != NETWORK_WORDS_PRP * 4:
        raise AssertionError("PRP Network DSR did not use its fixed length")
    return raw


def mac_text(value):
    return ":".join(value[index:index + 2] for index in range(0, 12, 2))


def fields_from_expected(value):
    return {
        "flags": value["flags"],
        "version": value["version"],
        "path": value["path"],
        "sequence": value["sequence"],
        "node_mode": value["node_mode"],
        "reporter": mac_text(value["reporter"]),
        "claimed_node_a": mac_text(value["node_a"]),
        "claimed_node_b": mac_text(value["node_b"]),
        "redbox": mac_text(value["redbox"]),
        "vdan": mac_text(value["vdan"]),
        "identities_authenticated": False,
    }


def json_values(path):
    return [json.loads(value) for value in open(path, "rb").read().split(b"\x1e") if value.strip()]


# NtoH conversion feeds the canonical JSON view while radsrs retains raw
# records separately.  Verify all values, including fields intentionally kept
# distinct even when they are merely MAC-address claims.
input_flows = [value for value in json_values(input_json_path)
               if value["record"]["type"] == "flow"]
if len(input_flows) != 2:
    raise AssertionError("expected two PRP supervision input flows")
for value, want in zip(input_flows, (expected["first"], expected["second"])):
    net = value["canonical"].get("net")
    if not net or net.get("header") != {
        "type": NETWORK_TYPE,
        "name": "network",
        "subtype": NETWORK_SUBTYPE_PRP,
        "qualifier": 0,
        "length_words": NETWORK_WORDS_PRP,
    }:
        raise AssertionError("PRP Network DSR was not canonically decoded")
    if net.get("fields") != fields_from_expected(want):
        raise AssertionError("wrong PRP supervision canonical fields: %r" % net.get("fields"))

# Unmodified output preserves sensor/client input bytes exactly.
roundtrip_flows = flow_records(roundtrip_path)
if [record["raw"].hex() for record in roundtrip_flows] != [expected["first_far"], expected["second_far"]]:
    raise AssertionError("ra did not preserve unmodified PRP supervision records")

# Supervision identities are observations, not src/dst fields. rmon may emit
# reversed flow copies, but each Network DSR must remain byte-for-byte intact.
reverse_dsrs = Counter(prp_dsr(record).hex() for record in flow_records(reverse_path))
if reverse_dsrs != Counter({expected["first_dsr"]: 2, expected["second_dsr"]: 2}):
    raise AssertionError("rmon changed PRP supervision identities or sequences")

# Inventory-oriented merge retains the first claim for every role, marks the
# incompatible later claims, and retains the latest supervision sequence.
merged_flows = flow_records(merge_path)
if len(merged_flows) != 1:
    raise AssertionError("racluster did not emit one merged supervision flow")
merged = bytearray(prp_dsr(merged_flows[0]))
flags, version, sequence = struct.unpack_from("!IHH", merged, 4)
if (flags, version, sequence, merged[12], merged[13]) != (
        expected["merged_flags"], 1, expected["second"]["sequence"], 1, 20):
    raise AssertionError("merged supervision header/flags are incorrect")
for offset, field in ((14, "reporter"), (20, "node_a"), (26, "node_b"),
                      (32, "redbox"), (38, "vdan")):
    if merged[offset:offset + 6].hex() != expected["first"][field]:
        raise AssertionError("merged %s was not the first observed claim" % field)

merged_json_flows = [value for value in json_values(merge_json_path)
                     if value["record"]["type"] == "flow"]
if len(merged_json_flows) != 1:
    raise AssertionError("radsrs did not emit one merged supervision JSON record")
merged_want = dict(expected["first"])
merged_want["flags"] = expected["merged_flags"]
merged_want["sequence"] = expected["second"]["sequence"]
if merged_json_flows[0]["canonical"].get("net", {}).get("fields") != fields_from_expected(merged_want):
    raise AssertionError("merged PRP supervision JSON did not retain role-specific claims")

# Exact-length canonicalization rejects an undersized PRP Network DSR rather
# than reading its incomplete union payload. Its raw DSR remains available in
# the authoritative raw representation, but no canonical net object appears.
invalid_flows = [value for value in json_values(invalid_json_path)
                 if value["record"]["type"] == "flow"]
if len(invalid_flows) != 1:
    raise AssertionError("invalid-length fixture did not contain one flow")
if "net" in invalid_flows[0].get("canonical", {}):
    raise AssertionError("undersized PRP Network DSR was canonically decoded")
PY
then
   pass "PRP supervision byte order, JSON, inventory merge, reversal, and length validation are correct"
else
   fail "PRP supervision client validation failed"
fi

if [ -s "$REGRESSION_FAIL_MARKER" ]; then
   exit 1
fi
exit 0
