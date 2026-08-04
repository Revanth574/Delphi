#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Require the EXECUTED and SKIPPED test counts to EQUAL the recorded ones.
#
#   scripts/ci-test-count-gate.sh --workspace     # args are passed to test-count.sh
#
# WHY EQUALITY AND NOT A FLOOR (D0-R7-01)
# ---------------------------------------
# This guard existed as a floor whose own protocol said "count goes UP freely", recorded as a
# number that predated an entire crate. The actual sat scores of tests above it, so a test
# that started SKIPPING kept the floor satisfied — the disappearance the guard exists to
# catch. D0-R6 had already fixed the MEASUREMENT (executed, not reported: a skip scores as a
# pass) and the blindness simply moved into the THRESHOLD. Equality has no margin to hide in.
#
# WHY BOTH NUMBERS, NOT JUST EXECUTED
# -----------------------------------
# A single total is satisfiable two ways, which is the shape of every bug this file has had.
# EXECUTED alone is blind to a compensating pair — one test deleted while another stops
# skipping. Recording both makes that visible as a SKIPPED change.
#
# WHY THIS IS A SCRIPT AND NOT INLINE IN ci.yml
# ---------------------------------------------
# Inline shell cannot be RED-proven: the test would exercise a copy, and a copy that has
# drifted is DEFECT_CLASSES 25. `scripts/ci-test-count-gate.test.sh` runs THIS file.
#
# FAILS CLOSED. Every parse failure, missing key, or extractor refusal is a non-zero exit.

set -uo pipefail

BASELINE="${DELPHI_TEST_COUNT_BASELINE:-.github/rust-test-count-baseline}"
# Overridable so the RED suite can feed captured extractor output without a cargo run. The
# end-to-end leg leaves it unset and really skips a test.
EXTRACTOR="${DELPHI_TEST_COUNT_CMD:-scripts/test-count.sh}"

FAIL() { echo "::error::$*" >&2; echo "GATE FAILED: $*" >&2; exit 1; }

out=$("$EXTRACTOR" "$@" 2>&1)
rc=$?
# The extractor REFUSEs rather than guessing; that refusal must not be read as a count of 0.
[ "$rc" -eq 0 ] || FAIL "test-count.sh exited $rc — the count is UNKNOWN, not zero. Output: $out"

read_one() {
    # Exactly one match, or refuse: two `EXECUTED` lines mean the output shape changed and
    # picking either one is a guess.
    local n
    n=$(printf '%s\n' "$out" | grep -cE "^$1 [0-9]+")
    [ "$n" -eq 1 ] || return 1
    printf '%s\n' "$out" | grep -oE "^$1 [0-9]+" | grep -oE '[0-9]+'
}

actual_exec=$(read_one EXECUTED) \
    || FAIL "no single 'EXECUTED <n>' line in the extractor output — format changed? Got: $out"
actual_skip=$(printf '%s\n' "$out" | grep -oE 'SKIPPED [0-9]+' | grep -oE '[0-9]+' | head -1)
[ -n "$actual_skip" ] \
    || FAIL "no 'SKIPPED <n>' in the extractor output — format changed? Got: $out"

[ -r "$BASELINE" ] || FAIL "baseline $BASELINE is missing or unreadable. Measured this run: \
EXECUTED=$actual_exec SKIPPED=$actual_skip"

# Bounded digits: an oversized value makes `-ne` a shell error, and a shell error under
# `set -u` without `-e` CONTINUES (D0-R7-06 — the same class, in the same family of script).
read_key() {
    local vals
    vals=$(grep -oE "^$1=[0-9]{1,9}$" "$BASELINE" | cut -d= -f2)
    [ "$(printf '%s' "$vals" | grep -c .)" -eq 1 ] || return 1
    printf '%s\n' "$vals"
}

want_exec=$(read_key EXECUTED) || want_exec=""
want_skip=$(read_key SKIPPED) || want_skip=""
if [ -z "$want_exec" ] || [ -z "$want_skip" ]; then
    echo "$BASELINE does not record exactly one EXECUTED= and one SKIPPED= (1-9 digits each)."
    echo "This run measured:"
    echo
    echo "    EXECUTED=$actual_exec"
    echo "    SKIPPED=$actual_skip"
    echo
    FAIL "baseline not recorded — paste the two lines above into $BASELINE, in the commit that \
changed the counts."
fi

if [ "$actual_exec" -ne "$want_exec" ] || [ "$actual_skip" -ne "$want_skip" ]; then
    echo "measured  EXECUTED=$actual_exec SKIPPED=$actual_skip"
    echo "recorded  EXECUTED=$want_exec SKIPPED=$want_skip"
    echo
    echo "  EXECUTED down  => a test disappeared, or started SKIPPING. Which one, and why?"
    echo "  EXECUTED up    => tests were added; record the new count in the same commit."
    echo "  SKIPPED moved  => a gate's precondition changed. That is a fact worth a sentence."
    FAIL "test counts differ from $BASELINE — deliberate work, not a threshold to drift past."
fi

echo "EXECUTED $actual_exec / SKIPPED $actual_skip — equal to $BASELINE ✓"
