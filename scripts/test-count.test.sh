#!/bin/bash
# SPDX-License-Identifier: MIT
#
# RED-proof for `scripts/test-count.sh` (tier 1 — clause (d): its output IS the project's
# coverage claim, so its green is cited as evidence).
#
# The property: the count is checkable by something OTHER THAN ITSELF. Every count in this
# arc was produced and validated by the same summing method, which is why 19 skips rode
# inside "121 passed" for the whole increment. Here the expected triple is fixed by
# construction — the fixture logs are written by this script — so agreement is evidence.
#
# Deterministic: no cargo, no display, no root, no network.

set -uo pipefail
cd "$(dirname "$0")" || exit 1
EXTRACTOR="./test-count.sh"
fail=0

check() { # name expected-substring actual-output expected-rc actual-rc
    local name="$1" want="$2" got="$3" want_rc="$4" got_rc="$5"
    if [[ "$got" == *"$want"* && "$got_rc" == "$want_rc" ]]; then
        printf '  ok    %s\n' "$name"
    else
        printf '  FAIL  %s\n        want rc=%s containing: %s\n        got  rc=%s: %s\n' \
            "$name" "$want_rc" "$want" "$got_rc" "${got//$'\n'/ | }"
        fail=1
    fi
}

run_on_log() { # <log-content> -> sets OUT / RC
    local f; f=$(mktemp)
    printf '%s' "$1" > "$f"
    OUT=$(DELPHI_TESTCOUNT_LOG="$f" "$EXTRACTOR" 2>&1); RC=$?
    rm -f "$f"
}

echo "test-count.sh RED-proof"

# ── 1. THE KEYSTONE: a known skip count must be subtracted ──────────────────────────────
# 5 reported, 2 skipped => 3 executed. A tool that reports the total says 5.
run_on_log 'running 5 tests
test alpha ... SKIP alpha: requires root
test beta ... SKIP beta: requires a display
test gamma ... ok
test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
'
check "known 5-reported/2-skipped yields EXECUTED 3" "EXECUTED 3 / SKIPPED 2 / reported 5" "$OUT" 0 "$RC"

# ── 2. The positive leg: no skips must not be mangled into one ──────────────────────────
run_on_log 'running 3 tests
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
'
check "no skips yields EXECUTED 3 / SKIPPED 0" "EXECUTED 3 / SKIPPED 0 / reported 3" "$OUT" 0 "$RC"

# ── 3. Multiple result lines (several test binaries) sum ────────────────────────────────
run_on_log 'test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
test gamma ... SKIP gamma: requires root
test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
'
check "sums across binaries" "EXECUTED 9 / SKIPPED 1 / reported 10" "$OUT" 0 "$RC"

# ── 4. CLASS-22 GUARD: an unparseable format REFUSES; it must never fall back ───────────
# This is the one that matters most. A libtest format change must not silently degrade this
# tool into the bare-total reporter it exists to replace.
run_on_log 'running 5 tests
test alpha ... SKIP alpha: requires root
== 5 tests succeeded ==
'
check "unrecognised format REFUSES (no fallback)" "REFUSING" "$OUT" 2 "$RC"
if [[ "$OUT" == *"EXECUTED"* ]]; then
    printf '  FAIL  unrecognised format still emitted a count: %s\n' "${OUT//$'\n'/ | }"; fail=1
fi

# ── 5. An impossible parse (more skips than passes) REFUSES rather than going negative ──
run_on_log 'test a ... SKIP a: x
test b ... SKIP b: x
test c ... SKIP c: x
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
'
check "skips > passes REFUSES" "REFUSING" "$OUT" 2 "$RC"

# ── 6. A SKIP mentioned INSIDE a message must not inflate the count (column-0 anchor) ───
run_on_log 'running 2 tests
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
note: a SKIP here would prove nothing, see the SKIP discussion above
'
check "prose mentioning SKIP is not counted" "EXECUTED 2 / SKIPPED 0 / reported 2" "$OUT" 0 "$RC"

# ── 7. THE PHYSICAL FLOOR: the skip-shaped false green, caught WITHOUT the SKIP parse ───
# The real event: `cargo test --release` reported "7 passed" for real_webkit_load in 0.02s.
# Seven WebKit launches cannot happen in 20ms. These cases carry NO skip markers, so only the
# timing can catch them — which is the point: two independent signals, and the SKIP parse has
# already been wrong once.
run_with_floor() { # <floor-ms> <log-content>
    local f; f=$(mktemp); printf '%s' "$2" > "$f"
    OUT=$(DELPHI_MIN_MS_PER_TEST="$1" DELPHI_TESTCOUNT_LOG="$f" "$EXTRACTOR" 2>&1); RC=$?
    rm -f "$f"
}

run_with_floor 100 'running 7 tests
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
'
check "impossible rate REFUSES even with NO skip markers" "below the" "$OUT" 2 "$RC"

run_with_floor 100 'running 7 tests
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.00s
'
check "plausible rate passes the same floor" "EXECUTED 7 / SKIPPED 0" "$OUT" 0 "$RC"

run_with_floor 100 'running 2 tests
test a ... SKIP a: x
test b ... SKIP b: x
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
'
check "floor declared but nothing executed REFUSES" "NOTHING executed" "$OUT" 2 "$RC"

# ── 7a. D0-R6-05/06/07/09 — the guards added after round 6 ──────────────────────────────
# A summary line with no passed-count silently contributed 0, reading as a smaller suite.
run_on_log 'test result: ok. 3 passed; 0 failed
test result: FAILED. some other shape
'
check "summary without a passed-count REFUSES" "REFUSING" "$OUT" 2 "$RC"

# `finished in` matched ANYWHERE let nested output inflate elapsed — which RAISES the rate and
# so WEAKENS the floor. A guard that fails open under noise is not a guard.
run_with_floor 100 'note: a nested harness said finished in 99.00s somewhere
running 7 tests
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.02s
'
check "elapsed is taken ONLY from summary lines" "below the" "$OUT" 2 "$RC"

# A mistyped/zero/negative floor previously disabled the check while exiting 0.
run_with_floor 10O 'running 7 tests
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.00s
'
check "a non-numeric floor REFUSES (typo must not disable it)" "not a positive integer" "$OUT" 2 "$RC"
run_with_floor 0 'running 7 tests
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.00s
'
check "a zero floor REFUSES" "not a positive integer" "$OUT" 2 "$RC"

# R6-09: the LISTING path had the column-0 anchor the counting path shed two rounds ago, so
# counts were right while the list was silently empty.
run_on_log 'test alpha ... SKIP alpha: requires root
test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
'
check "the skipped-test LIST is populated, not empty" "SKIP alpha" "$OUT" 0 "$RC"

# D0-R7-06: an oversized numeric floor passed the regex, then `-le` errored with "integer
# expected" and the script CONTINUED — exiting 0 with the floor silently disabled.
run_with_floor 999999999999999999999999999999 'running 7 tests
test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.00s
'
check "an oversized floor REFUSES (must not disable itself)" "not a positive integer" "$OUT" 2 "$RC"

# ── 8. THE ANTI-CLASS-25 CASE: parse a REAL captured libtest log ───────────────────────
# The first version of this file invented its fixture format, and the invented format did not
# match libtest's. The parser passed six synthetic cases while missing every marker in real
# serial output, because libtest prefixes the line with `test <name> ... `. A fixture that is
# constructed differently from the thing it stands in for is DEFECT_CLASSES 25 — here inside
# the RED-proof of a tier-1 artifact.
OUT=$(DELPHI_TESTCOUNT_LOG=testdata/real-libtest-serial.log "$EXTRACTOR" 2>&1); RC=$?
check "parses REAL captured libtest output" "EXECUTED 2 / SKIPPED 3 / reported 5" "$OUT" 0 "$RC"

echo
if [ "$fail" -eq 0 ]; then echo "ALL PASS"; else echo "FAILURES ABOVE"; fi
exit "$fail"
