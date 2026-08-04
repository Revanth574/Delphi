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
# A PHYSICAL FLOOR CATCHES THE SKIP-SHAPED FALSE GREEN INDEPENDENTLY OF THE SKIP PARSE
# ------------------------------------------------------------------------------------
# `cargo test --release` once reported "7 passed" for real_webkit_load in 0.02s. Seven real
# WebKit launches cannot complete in 20ms — they had all SKIPPED. The count said ok; the
# TIMING said impossible. That is a second, independent signal, and it matters because the
# SKIP parse has already been wrong once (it was anchored to column 0 and matched nothing).
#
# So the rate is ALWAYS reported, and `DELPHI_MIN_MS_PER_TEST` turns it into an assertion for
# suites with a known floor. When a measurement has a physical floor, assert the floor.
#
# Usage:  scripts/test-count.sh -p delphi-runtime
#         DELPHI_MIN_MS_PER_TEST=100 scripts/test-count.sh --release   # WebKit-launching suite
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

# Every summary line must yield a passed-count. A malformed one silently contributed 0
# before (D0-R6-05), which reads as a smaller suite rather than as a parse failure.
malformed=$(grep -E '^test result:' "$log" | grep -cvE '[0-9]+ passed')
[ "$malformed" -eq 0 ] || REFUSE "$malformed 'test result:' line(s) carry no passed-count — \
the format may have changed; this script does not guess."
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

# Test-execution time only (libtest's own per-binary figure), not build time.
# Only from `test result:` SUMMARY lines (D0-R6-06). Matching `finished in` anywhere let
# nested or quoted output inflate the elapsed time, which RAISES the rate and so WEAKENS the
# floor — a guard that fails open under noise.
elapsed_ms=$(grep -E '^test result:' "$log" | grep -oE 'finished in [0-9]+\.[0-9]+s' \
  | grep -oE '[0-9]+\.[0-9]+' | awk '{s+=$1} END {printf "%d", s*1000}')
[[ "$elapsed_ms" =~ ^[0-9]+$ ]] || REFUSE "could not extract an elapsed time ('$elapsed_ms')"

if [ "$rc" -ne 0 ]; then
    echo "TESTS FAILED (cargo exit $rc) — the count below is NOT a coverage claim:" >&2
    grep -E '^test result:|^error|panicked at' "$log" | head -20 >&2
fi

if [ "$executed" -gt 0 ]; then
    rate=$(( elapsed_ms / executed ))
    printf 'EXECUTED %d / SKIPPED %d / reported %d   (%dms total, %dms per executed test)\n' \
        "$executed" "$skipped" "$reported" "$elapsed_ms" "$rate"
else
    rate=0
    printf 'EXECUTED %d / SKIPPED %d / reported %d   (%dms total)\n' \
        "$executed" "$skipped" "$reported" "$elapsed_ms"
fi

# THE PHYSICAL FLOOR. Independent of the SKIP parse by construction: it asks whether the work
# could have happened in the time taken, not whether a marker was printed.
if [ -n "${DELPHI_MIN_MS_PER_TEST:-}" ]; then
    # A mistyped, zero or negative floor previously disabled the check while still exiting 0
    # (D0-R6-07) — the caller believes a floor is enforced and none is.
    # D0-R7-06: `^[0-9]+$` accepts a 30-digit value, and the `-le` comparison then fails with
    # "integer expected" — a shell error, not a refusal, so the script CONTINUED and exited 0
    # with the floor silently disabled. Bound the length before comparing.
    if ! [[ "$DELPHI_MIN_MS_PER_TEST" =~ ^[0-9]{1,9}$ ]] || [ "$DELPHI_MIN_MS_PER_TEST" -le 0 ]; then
        REFUSE "DELPHI_MIN_MS_PER_TEST='$DELPHI_MIN_MS_PER_TEST' is not a positive integer. \
A floor that silently does not apply is worse than none, because the caller believes it does."
    fi
    if [ "$executed" -eq 0 ]; then
        REFUSE "a floor of ${DELPHI_MIN_MS_PER_TEST}ms/test was declared but NOTHING executed"
    fi
    if [ "$rate" -lt "$DELPHI_MIN_MS_PER_TEST" ]; then
        REFUSE "$executed test(s) completed in ${elapsed_ms}ms (${rate}ms each), below the \
declared floor of ${DELPHI_MIN_MS_PER_TEST}ms. The work this suite names cannot happen that \
fast, so it reported on something else — skipped tests are the usual cause, and they score \
as passes."
    fi
fi

if [ "$skipped" -gt 0 ]; then
    echo "--- the $skipped skipped test(s) returned early and were scored as passes ---"
    # SAME anchor as the counting path above (D0-R6-09). It was fixed there and left here,
    # so counts were right while this list was silently EMPTY under real serial output —
    # one defect, two consumers, one of them fixed.
    grep -E '^test .+ \.\.\. (SKIP|DEFER)' "$log" | cut -c1-110 | sed 's/^/  /'
fi

exit "$rc"
