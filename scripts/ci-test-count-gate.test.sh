#!/bin/bash
# SPDX-License-Identifier: MIT
#
# RED proofs for scripts/ci-test-count-gate.sh — the gate that catches a test disappearing.
#
# The gate is TIER 1 under §6's clause (d): its green is the only evidence that no test
# vanished or started skipping. So it owes both weakens, and both are here as cases:
#
#   WEAKEN (a) — restore the floor. A floor passes a run in which a test just started
#                skipping, as long as the total stays above it. That is D0-R7-01 itself.
#   WEAKEN (b) — compare EXECUTED only. Passes a COMPENSATING PAIR (one test deleted, one
#                gated test un-skipped) that leaves the executed total unchanged.
#
# Extractor output fixtures are derived from a CAPTURED run
# (scripts/testdata/real-test-count-output.log), never typed from memory: invented fixtures
# caught 0/7 of the extractor's own defects (DEFECT_CLASSES 25).
#
# The end-to-end leg — really make a test SKIP, real extractor, real crate — is not here
# because it edits a source file; it is run by hand and recorded in the commit body.

set -uo pipefail
cd "$(dirname "$0")/.."

GATE=scripts/ci-test-count-gate.sh
CAPTURED=scripts/testdata/real-test-count-output.log
[ -r "$CAPTURED" ] || { echo "missing captured fixture $CAPTURED"; exit 2; }

work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0; fail=0

# A stub extractor: emits a fixture, exits with a chosen code, ignores its args.
mkstub() {  # mkstub <file> <rc>
    local s="$work/stub-$RANDOM.sh"
    { echo '#!/bin/bash'; echo "cat '$1'"; echo "exit $2"; } > "$s"
    chmod +x "$s"; printf '%s' "$s"
}
# A fixture with the two counts substituted into the captured line.
mkout() {  # mkout <executed> <skipped>
    local f="$work/out-$1-$2.log"
    sed -E "1s/^EXECUTED [0-9]+ \/ SKIPPED [0-9]+/EXECUTED $1 \/ SKIPPED $2/" "$CAPTURED" > "$f"
    printf '%s' "$f"
}
mkbase() {  # mkbase <content>
    local f="$work/base-$RANDOM"; printf '%s\n' "$1" > "$f"; printf '%s' "$f"
}

check() {  # check <name> <want-rc: 0|nonzero> <gate-path> <baseline> <stub>
    local name=$2 want=$3 gate=$4 base=$5 stub=$6
    local out rc
    out=$(DELPHI_TEST_COUNT_BASELINE="$base" DELPHI_TEST_COUNT_CMD="$stub" "$gate" --workspace 2>&1)
    rc=$?
    local ok=no
    if [ "$want" = 0 ] && [ "$rc" -eq 0 ]; then ok=yes; fi
    if [ "$want" != 0 ] && [ "$rc" -ne 0 ]; then ok=yes; fi
    if [ "$ok" = yes ]; then
        pass=$((pass+1)); printf '  %-58s PASS (rc=%s)\n' "$1" "$rc"
    else
        fail=$((fail+1)); printf '  %-58s FAIL (rc=%s, wanted %s)\n' "$1" "$rc" "$want"
        printf '%s\n' "$out" | sed 's/^/      | /'
    fi
    LAST_OUT="$out"
}

echo "=== ci-test-count-gate RED proofs ==="

GOOD_BASE=$(mkbase 'EXECUTED=102
SKIPPED=19')

# ---- the gate as shipped -----------------------------------------------------------------
check "equal counts" ok 0 "$GATE" "$GOOD_BASE" "$(mkstub "$CAPTURED" 0)"
check "a test started SKIPPING (102/19 -> 101/20)" x 1 "$GATE" "$GOOD_BASE" "$(mkstub "$(mkout 101 20)" 0)"
check "a test was ADDED (102/19 -> 103/19)"        x 1 "$GATE" "$GOOD_BASE" "$(mkstub "$(mkout 103 19)" 0)"
check "COMPENSATING PAIR (102/19 -> 102/18)"       x 1 "$GATE" "$GOOD_BASE" "$(mkstub "$(mkout 102 18)" 0)"

# ---- extractor-side failures must not read as a count --------------------------------------
check "extractor REFUSEs (rc=2)" x 1 "$GATE" "$GOOD_BASE" "$(mkstub "$CAPTURED" 2)"
case "$LAST_OUT" in *UNKNOWN*) echo "    ...and says UNKNOWN, not zero ✓";;
  *) echo "    ...but did NOT say UNKNOWN — a refusal read as a count"; fail=$((fail+1));; esac
check "output has no EXECUTED line" x 1 "$GATE" "$GOOD_BASE" \
    "$(mkstub "$(sed 1d "$CAPTURED" > "$work/noexec.log"; printf '%s' "$work/noexec.log")" 0)"
check "output has TWO EXECUTED lines" x 1 "$GATE" "$GOOD_BASE" \
    "$(mkstub "$(cat "$CAPTURED" "$CAPTURED" > "$work/dup.log"; printf '%s' "$work/dup.log")" 0)"

# ---- baseline-side failures ----------------------------------------------------------------
STUB_OK=$(mkstub "$CAPTURED" 0)
check "baseline file absent"        x 1 "$GATE" "$work/nope"                 "$STUB_OK"
check "baseline records no keys"    x 1 "$GATE" "$(mkbase '# nothing here')" "$STUB_OK"
case "$LAST_OUT" in *"EXECUTED=102"*) echo "    ...and prints the measured lines to paste ✓";;
  *) echo "    ...but does not print what to record"; fail=$((fail+1));; esac
check "baseline has TWO EXECUTED= keys" x 1 "$GATE" "$(mkbase 'EXECUTED=102
EXECUTED=7
SKIPPED=19')" "$STUB_OK"
check "baseline value is 30 digits (R7-06 class)" x 1 "$GATE" "$(mkbase 'EXECUTED=102000000000000000000000000000
SKIPPED=19')" "$STUB_OK"
check "baseline key not anchored (' EXECUTED=102')" x 1 "$GATE" "$(mkbase ' EXECUTED=102
SKIPPED=19')" "$STUB_OK"
check "baseline SKIPPED= missing"   x 1 "$GATE" "$(mkbase 'EXECUTED=102')"   "$STUB_OK"

# ---- WEAKEN (a): the floor. The defect R7-01 names, reconstructed. -------------------------
echo
echo "  --- weaken (a): equality -> floor ---"
sed -E 's/if \[ "\$actual_exec" -ne "\$want_exec" \] \|\| \[ "\$actual_skip" -ne "\$want_skip" \]; then/if [ "$actual_exec" -lt "$want_exec" ]; then/' \
    "$GATE" > "$work/gate-floor.sh"; chmod +x "$work/gate-floor.sh"
grep -q 'actual_exec" -lt' "$work/gate-floor.sh" || { echo "  WEAKEN (a) DID NOT APPLY — the"; \
    echo "  substitution matched nothing, so the next result would be about the SHIPPED gate."; exit 2; }
LOW_BASE=$(mkbase 'EXECUTED=50
SKIPPED=19')
check "floor + a test just skipped (101 vs floor 50)" want-0 0 "$work/gate-floor.sh" "$LOW_BASE" "$(mkstub "$(mkout 101 20)" 0)"
echo "    ^ the floor PASSES a disappearance. Shipped gate on the same input:"
check "shipped gate, same input"    x 1 "$GATE" "$LOW_BASE" "$(mkstub "$(mkout 101 20)" 0)"

# ---- WEAKEN (b): EXECUTED only. A different form, invisible to weaken (a). -----------------
echo
echo "  --- weaken (b): drop the SKIPPED comparison ---"
sed -E 's/ \|\| \[ "\$actual_skip" -ne "\$want_skip" \]//' "$GATE" > "$work/gate-execonly.sh"
chmod +x "$work/gate-execonly.sh"
grep -q 'actual_skip" -ne' "$work/gate-execonly.sh" && { echo "  WEAKEN (b) DID NOT APPLY — the"; \
    echo "  SKIPPED comparison is still present, so the next result proves nothing."; exit 2; }
check "EXECUTED-only + compensating pair (102/18)" want-0 0 "$work/gate-execonly.sh" "$GOOD_BASE" "$(mkstub "$(mkout 102 18)" 0)"
echo "    ^ EXECUTED-only PASSES the pair. Shipped gate on the same input: case 4 above, FAIL."

echo
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ] && { echo "ALL PASS"; exit 0; }
echo "SUITE FAILED"; exit 1
