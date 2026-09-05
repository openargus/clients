# security-review/fuzz

Fuzzing harness and regression corpus for the Argus client library's record-ingestion
entry point, added following the 2026-09-03 clients security review (see
`argus-clients-security-review.2026.09.03-phase2/` in the review's own working docs, kept
separately from this repo, for the full writeup of findings F-CL-1 through F-CL-37).

## Contents

- `fuzz_handle_record.c` — a standalone harness that calls `ArgusHandleRecord()` directly on
  a raw, network-byte-order `struct ArgusRecord` buffer, without needing a live connection or
  a real input file. Compiled with `-fsanitize=address,undefined` so it aborts on any
  memory-safety or undefined-behavior violation, not just on outright segfaults.
- `build.sh` — builds the harness against the real client-library object files. Requires
  `./configure` to have already been run (needs `include/argus_config.h`). Two modes:
  - `build.sh` (default) — AFL++-instrumented build, for running new fuzzing campaigns
    (`afl-fuzz`) if you have `afl-clang-fast` installed.
  - `build.sh plain` — plain clang build, no AFL instrumentation. This is what CI uses to
    replay saved inputs quickly.
- `corpus/` — a seed corpus of real, valid Argus v3 records extracted directly from two
  capture files used elsewhere in this review (a MAR record plus a variety of FAR records
  spanning different DSR combinations/lengths). Used both as an initial AFL seed corpus and
  as a basic smoke-test set.
- `crashes/` — hand-saved reproducers for findings caught by this harness, kept for
  readability/documentation purposes. Currently: 3 reproducers for the double-to-int overflow
  in `ArgusFetchSrcLoss()`/`ArgusFetchDstLoss()` (fixed in `common/argus_client.c` in the same
  change that added this harness — see `ArgusClampDoubleToInt()`).
- `regression-corpus/` — reserved for the deduplicated, accumulated set of crashing inputs
  found across future AFL campaigns against this harness, mirroring the sensor repo's
  `security-review/fuzz/regression-corpus/` convention. Empty for now; `crashes/` covers the
  first findings.

## Why `ArgusHandleRecord()`

`ArgusHandleRecord()` (`common/argus_util.c`) is the function every client-side reader calls
immediately after enough bytes for one Argus record have been assembled from a stream or
file — see `common/argus_client.c`'s `ArgusReadStreamSocket()` and `common/argus_main.c`'s
file-reading loop, both of which call it directly on a raw, still-network-byte-order
`struct ArgusRecord *`. It is the single choke point through which every on-the-wire or
on-disk Argus record enters the client library, and its call graph
(`ArgusGenerateRecordStruct()` -> per-DSR-type parsing/canonicalization -> filtering ->
scheduling) covers essentially the entire client-side attack surface for a malicious or
corrupted Argus data stream, without needing anything client-specific (printing, output
formatting, MySQL, etc.).

## Running locally

```sh
./configure
sh security-review/fuzz/build.sh plain
for f in security-review/fuzz/corpus/* \
         security-review/fuzz/crashes/*; do
  ./security-review/fuzz/fuzz_handle_record "$f" || echo "CRASH: $f"
done
```

## Running a new AFL campaign

```sh
./configure
sh security-review/fuzz/build.sh          # afl-clang-fast build
afl-fuzz -i security-review/fuzz/corpus -o /tmp/afl-out \
  -- security-review/fuzz/fuzz_handle_record @@
```

Any new crashes found should be minimized (`afl-tmin`), triaged, fixed upstream in the client
library code, and — once confirmed to reproduce the bug pre-fix and not reproduce post-fix —
added to `regression-corpus/` (or `crashes/` for a small, well-documented set) so CI guards
against a regression going forward.
