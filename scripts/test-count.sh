#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Emit a test count as EXECUTED / SKIPPED / reported — never as a bare total.
#
# WHY THIS EXISTS (DEFECT_CLASSES 10)
# -----------------------------------
# Gated tests here return early after an `eprintln!("SKIP …")`, and libtest scores an early
# return as a PASS. `cargo test` prints `ok. 121 passed` when 19 of those skipped, and the
# reason is invisible without `--nocapture` because stderr is captured for passing tests.
# That is a false positive in the strict sense: the harness asserting success about work it
# did not do. A rule ("remember --nocapture and look") is the shape that lost every time a
# mechanism was available, so the extraction is mechanical.
#
# IT MUST FAIL LOUDLY RATHER THAN FALL BACK TO A TOTAL (DEFECT_CLASSES 22)
# ------------------------------------------------------------------------
# A future cargo/libtest format change would break the parse. If that degraded to "just print
# the reported number", this tool would reintroduce, through itself, the exact defect it was
# built to prevent. So every parse step is checked and every failure REFUSES. There is no
# fallback path and no mode that prints the total alone.
#
# Usage:  scripts/test-count.sh -p delphi-runtime
#         DELPHI_TESTCOUNT_LOG=<file> scripts/test-count.sh   # parse a captured log (tests)
# Exits non-zero if the tests failed OR if the output could not be parsed.

set -uo pipefail

REFUSE() { echo "REFUSING to report a count: $*" >&2; exit 2; }

if [ -n "${DELPHI_TESTCOUNT_LOG:-}" ]; then
    # Parse-only: exercises this script's parsing against a captured log, so the parser is
    # checkable by something other than itself.
    log="$DELPHI_TESTCOUNT_LOG"
    [ -r "$log" ] || REFUSE "DELPHI_TESTCOUNT_LOG=$log is not readable"
    rc=0
else
    log=$(mktemp -t delphi-testcount-XXXXXX) || REFUSE "mktemp failed"
    trap 'rm -f "$log"' EXIT
    # --nocapture is NOT optional: it is the only way SKIP lines reach the output at all.
    # --test-threads=1 is NOT optional either: with parallel threads, a test's SKIP (stderr)
    # interleaves with libtest's `test NAME ... ok` (stdout), so the marker lands at column 0
    # on some runs and mid-line on others. That made the count DRIFT run to run (measured:
    # 17/18/19 for the same tree). Serial output is deterministic. This is a counting run, not
    # a stability run — parallel stability is measured separately.
    cargo test "$@" -- --nocapture --test-threads=1 &> "$log"
    rc=$?
fi

# ── PARSE, with every step checked ──────────────────────────────────────────────────────
result_lines=$(grep -cE '^test result:' "$log")
if [ "$result_lines" -eq 0 ]; then
    if [ "$rc" -ne 0 ]; then
        echo "TESTS FAILED (cargo exit $rc) before any test ran:" >&2
        grep -E '^error|panicked at' "$log" | head -10 >&2
        exit "$rc"
    fi
    REFUSE "no 'test result:' lines in the output — the format may have changed. \
This script does NOT fall back to a total (DEFECT_CLASSES 22)."
fi

reported=$(grep -E '^test result:' "$log" \
  | grep -oE '[0-9]+ passed' | grep -oE '^[0-9]+' | awk '{s+=$1} END {print s+0}')
[[ "$reported" =~ ^[0-9]+$ ]] || REFUSE "could not extract a passed-count ('$reported')"

# Anchored to libtest's OWN line format — `test <name> ... SKIP…` — not to column 0. The
# column-0 anchor was wrong twice over: it missed every marker in serial output (where libtest
# prefixes the line) and it made the parallel count depend on interleaving. Matching the
# harness's format also keeps a SKIP *described* in prose from inflating the count.
skipped=$(grep -cE '^test .+ \.\.\. (SKIP|DEFER)' "$log")
[[ "$skipped" =~ ^[0-9]+$ ]] || REFUSE "could not extract a skip-count ('$skipped')"

if [ "$skipped" -gt "$reported" ]; then
    REFUSE "more skips ($skipped) than reported passes ($reported) — the parse is wrong, \
and a wrong count is worse than none"
fi

executed=$(( reported - skipped ))

if [ "$rc" -ne 0 ]; then
    echo "TESTS FAILED (cargo exit $rc) — the count below is NOT a coverage claim:" >&2
    grep -E '^test result:|^error|panicked at' "$log" | head -20 >&2
fi

printf 'EXECUTED %d / SKIPPED %d / reported %d\n' "$executed" "$skipped" "$reported"

if [ "$skipped" -gt 0 ]; then
    echo "--- the $skipped skipped test(s) returned early and were scored as passes ---"
    grep -E '^(SKIP|DEFER) ' "$log" | cut -c1-110 | sed 's/^/  /'
fi

exit "$rc"
