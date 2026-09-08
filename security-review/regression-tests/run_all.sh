#!/bin/sh
# Runs every regression test in this directory and prints a final pass/fail
# summary. Intended for both local use and CI
# (.github/workflows/ci.yml's "security-regression-tests" job).
#
# Usage:
#   sh security-review/regression-tests/run_all.sh
#
# Requires bin/ra to already be built (./configure && make -j4) before
# running.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

cd "$REPO_ROOT"

if [ ! -x "bin/ra" ]; then
   echo "error: bin/ra not found -- run './configure && make -j4' first" >&2
   exit 2
fi

overall_rc=0
ran=0
failed=0

echo "=== Regression tests ==="
for t in "$SCRIPT_DIR"/test_*.sh; do
   [ -f "$t" ] || continue
   ran=$((ran + 1))
   echo ""
   echo "--- $(basename "$t") ---"
   if sh "$t"; then
      :
   else
      failed=$((failed + 1))
      overall_rc=1
   fi
done

echo ""
echo "=== Summary: $((ran - failed))/$ran test scripts passed ==="
exit "$overall_rc"
