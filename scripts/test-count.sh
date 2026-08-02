#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Emit a test count as EXECUTED / SKIPPED / reported — never as a bare total.
#
# WHY THIS EXISTS (DEFECT_CLASSES 10)
# -----------------------------------
# This project's gated tests return early after an `eprintln!("SKIP …")`, and libtest scores
# an early return as a PASS. `cargo test` therefore prints `test result: ok. 121 passed` when
# 19 of those skipped, and the reason is invisible without `--nocapture` because stderr is
# captured for passing tests. That is a false positive in the strict sense: the harness
# asserts success about work it did not do.
#
# A rule ("remember to pass --nocapture and look") is the same shape as every rule-based fix
# that failed this session. So the extraction is mechanical: this script always runs with
# --nocapture, always subtracts the skips, and has no mode that prints the total alone.
#
# Usage:  scripts/test-count.sh -p delphi-runtime
#         scripts/test-count.sh --manifest-path runtime/shell-host/Cargo.toml
# Exits non-zero if the tests failed, so it can gate.

set -uo pipefail

log=$(mktemp -t delphi-testcount-XXXXXX)
trap 'rm -f "$log"' EXIT

# --nocapture is NOT optional: it is the only way the SKIP lines reach the output at all.
cargo test "$@" -- --nocapture &> "$log"
rc=$?

reported=$(grep -E '^test result:' "$log" \
  | grep -oE '[0-9]+ passed' | grep -oE '[0-9]+' | awk '{s+=$1} END {print s+0}')
# The project's two early-return markers. Anchored at column 0 so a SKIP *described* inside a
# doc comment or an assertion message cannot inflate the count.
skipped=$(grep -cE '^(SKIP|DEFER) ' "$log")
executed=$(( reported - skipped ))

if [ "$rc" -ne 0 ]; then
    echo "TESTS FAILED (cargo exit $rc) — count below is not a coverage claim:"
    grep -E '^test result:|^error|panicked at' "$log" | head -20
fi

printf 'EXECUTED %d / SKIPPED %d / reported %d\n' "$executed" "$skipped" "$reported"

if [ "$skipped" -gt 0 ]; then
    echo "--- the $skipped skipped test(s) returned early and were scored as passes ---"
    grep -E '^(SKIP|DEFER) ' "$log" | cut -c1-110 | sed 's/^/  /'
fi

exit "$rc"
