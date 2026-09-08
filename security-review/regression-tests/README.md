# Security-review regression tests (clients repo)

This directory holds small, targeted regression tests for specific fixes made during the
2026-09 clients-repo security review follow-on (see `../findings-log.md`,
`../SECURITY-REVIEW-REPORT.md` Section 11, and `../STATUS.md`). It follows the same pattern as
the sensor repo's own `security-review/regression-tests/` directory (`lib.sh` copied verbatim),
kept separate from `../fuzz/`, which fuzzes/replays a corpus against the single
`ArgusHandleRecord()` choke point and does not exercise these code paths (client-connection
command dispatch, decompression subprocess invocation, MAR-record EOF handling).

## What is (and isn't) covered here

- **F-CL-49** (unauthenticated remote file-read via the `FILE:` client command): covered by a
  **static source-code check** (`test_file_command_disabled.sh`), not a dynamic network-level
  test, unlike the other two. The fix disables the command outright (dispatch-table entry set
  to `NULL`, handler body commented out) rather than adding validation to a still-live code
  path, so the strongest test of a live radium/argus-B session is a manual one (see that
  script's header comment for the interactive verification actually performed during this
  fix's review, and why a full end-to-end network harness isn't reproduced here). If the
  dispatch-table entry or handler body is ever restored, this test fails immediately.
- **F-CL-50** (popen shell injection via a double-quoted filename during decompression) and
  **F-CL-51** (infinite loop on EOF/short-read in the MAR-record reader): both deterministic,
  functional bugs with real end-to-end pass/fail regression tests (`test_decompression_filename_injection.sh`,
  `test_mar_reader_eof_handling.sh`) that reproduce the original bug's exact conditions against
  the real, built `bin/ra` and check for the fixed behavior.

**F-CL-52** (Makefile install: missing `set -e`) is not covered by a test in this directory,
consistent with the sensor repo's own precedent for its equivalent finding (F-49): it was
verified via `make`-level fault injection, not a program input, and doesn't fit this directory's
per-fix-test pattern.

## Running locally

```sh
./configure
make -j4
sh security-review/regression-tests/run_all.sh
```

`run_all.sh` runs every `test_*.sh` script in this directory against the already-built `bin/ra`
and reports a final pass/fail summary. Each script can also be run standalone; see the comment
header in each file for what it checks and why.

## Fixtures

`fixtures/valid_v5_record.argus` is a small (316-byte), synthetic Argus v5 data file generated
locally by running the sensor's own `bin/argus -r <tiny public pcap> -w <out>` against one of
the sensor repo's own public, BSD-licensed pcap fixtures (`lsp-ping-timestamp.pcap`, from
tcpdump's public test corpus) -- it contains no real, captured, or otherwise sensitive network
data, only a single synthetic UDP flow record. Test scripts derive gzip/bzip2-compressed and
truncated copies of it at runtime (into a scratch temp directory, never committed) as needed;
only this one base file is committed here.
