#!/bin/bash
# SPDX-License-Identifier: MIT
#
# D0A-R10-12 — the guard's REDs and its stability run.
#
# ── RUN THIS UNPRIVILEGED. It sudo's for the test BINARY only. ────────────────────────
#
# Two structural rules, each written after this script violated it:
#
#   1. BUILD BEFORE THE SUDO BOUNDARY. sudo's secure_path does not contain ~/.cargo/bin,
#      so a `cargo` call inside a sudo'd script is not found; `$HOME` becomes /root, so
#      CARGO_TARGET_DIR points at another tree. The first version did both, ran nothing,
#      and read the absent failure line as a verdict.
#   2. ABSENCE IS NOT AN OUTCOME, AND `ok` IS NOT EXECUTION. Every run must produce a
#      `test result:` line, and the guard must be shown to have RUN — a skipped libtest
#      test prints `ok` (DEFECT_CLASSES 10), so the stability leg requires the guard's own
#      capability witnesses in the output and rejects a SKIP explicitly (D0A-R16-03).
#
# LEG A is the real RED (D0A-R16-01). LEG B is a secondary RED that only exercises
# emission. LEG C is stability. Any leg failing its expectation exits NON-ZERO (R16-04).

set -u -o pipefail

SRC_SANDBOX="runtime/src/sandbox.rs"
TEST_NAME="the_predrop_payload_cannot_recover_capabilities_across_a_further_exec"
ITERATIONS="${ITERATIONS:-30}"
SHIM_DIR="scratch/nnp-shim"
SHIM="$PWD/$SHIM_DIR/nnp_suppress.so"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/delphi-target}"

FAILURES=0
note_failure() { echo "  >>> LEG FAILED ITS EXPECTATION: $1"; FAILURES=$((FAILURES + 1)); }
hr() { printf '%s\n' "============================================================"; }

if [ "$(id -u)" -eq 0 ]; then
    echo "REFUSING: run this UNPRIVILEGED — it sudo's for the test binary only."
    exit 1
fi
[ -f "$SRC_SANDBOX" ] || { echo "REFUSING: run from the repo root"; exit 1; }
command -v cargo >/dev/null || { echo "REFUSING: cargo not on PATH"; exit 1; }
command -v gcc   >/dev/null || { echo "REFUSING: gcc needed to build the NNP shim"; exit 1; }

echo "Priming sudo (the test binary needs root; the build does not)..."
sudo -v || { echo "REFUSING: sudo unavailable"; exit 1; }

BACKUP="$(mktemp)"
cp "$SRC_SANDBOX" "$BACKUP"
restore() {
    cp "$BACKUP" "$SRC_SANDBOX"
    cmp -s "$BACKUP" "$SRC_SANDBOX" \
        && echo "RESTORED: $SRC_SANDBOX byte-identical to the pre-run backup." \
        || echo "!!! RESTORE FAILED — $SRC_SANDBOX differs. Fix before committing."
}
trap restore EXIT

build_test_bin() { # build_test_bin <context>  -> prints the binary path, or exits 2
    local ctx="$1" json bin
    if ! json="$(cargo test -p delphi-runtime --lib --no-run --message-format=json 2>/dev/null)"; then
        echo "!!! BUILD FAILED ($ctx)" >&2
        cargo test -p delphi-runtime --lib --no-run 2>&1 | tail -20 >&2
        exit 2
    fi
    bin="$(printf '%s' "$json" | python3 -c '
import sys, json
for line in sys.stdin:
    try: m = json.loads(line)
    except Exception: continue
    if m.get("executable") and m.get("profile", {}).get("test"):
        print(m["executable"])
' | tail -1)"
    [ -n "$bin" ] && [ -x "$bin" ] || { echo "!!! NO TEST BINARY ($ctx)" >&2; exit 2; }
    printf '%s\n' "$bin"
}

require_suite_ran() { # <output> <context>
    printf '%s' "$1" | grep -q "test result:" && return 0
    echo; echo "!!! NO SUITE RAN ($2) — no 'test result:' line. Refusing to classify."
    printf '%s\n' "$1" | tail -15 | sed 's/^/    | /'
    exit 2
}

# D0A-R16-03. `ok` is not evidence the guard executed — a SKIP prints `ok` too.
require_guard_executed() { # <output> <context>
    if printf '%s' "$1" | grep -q "SKIP $TEST_NAME"; then
        echo "!!! THE GUARD SKIPPED ($2) — it proved nothing. Check root/bwrap."
        exit 2
    fi
    if ! printf '%s' "$1" | grep -q "restricted (--cap-drop"; then
        echo "!!! NO CAPABILITY WITNESS ($2) — the guard did not print its legs, so an"
        echo "    'ok' here is not evidence it ran. Is --nocapture set?"
        exit 2
    fi
    return 0
}

witnesses() { printf '%s' "$1" | grep -E "restricted \(|control    \(" | sed 's/^/    /'; }

# --- LEG A : the REAL RED — suppress bwrap's no_new_privs (D0A-R16-01) -------
# The round-16 review falsified "not weaken-provable in-tree". bwrap is dynamically linked
# and calls prctl through the PLT (R_X86_64_JUMP_SLOT, prctl@GLIBC_2.2.5), is not setuid and
# holds no file capabilities — so LD_PRELOAD reaches it even as root. Suppressing
# PR_SET_NO_NEW_PRIVS builds exactly the shape the guard exists to catch.
#
# `sudo env LD_PRELOAD=...` because sudo strips LD_PRELOAD from the environment it passes;
# `env` runs as root and sets it for the test binary, whose bwrap children inherit it.
# (Production's run_fd_pinned env_clear()s, so this reaches the TEST's bwrap only — which is
# what is wanted: it simulates a bwrap that stopped setting NNP.)
hr; echo "LEG A — REAL RED: bwrap's no_new_privs suppressed"; hr
gcc -shared -fPIC -o "$SHIM" "$SHIM_DIR/nnp_suppress.c" -ldl || { echo "shim build failed"; exit 2; }
echo "  shim: $SHIM"
if ! sudo env LD_PRELOAD="$SHIM" /usr/sbin/capsh --print 2>/dev/null | grep -q "no-new-privs=0"; then
    echo "  (note: capsh under the shim still reports NNP set for its own process; the"
    echo "   interception that matters is bwrap's, checked by the leg's outcome below)"
fi

A_BIN="$(build_test_bin "unmodified, for leg A")"
a_out="$(sudo env LD_PRELOAD="$SHIM" "$A_BIN" --nocapture "$TEST_NAME" 2>&1)"
require_suite_ran "$a_out" "leg A"
require_guard_executed "$a_out" "leg A"
witnesses "$a_out"
echo
if printf '%s' "$a_out" | grep -q "test result: FAILED"; then
    if printf '%s' "$a_out" | grep -q "the restriction is cosmetic"; then
        echo "  LEG A VERDICT: FAILED ON THE c0 ASSERTION under NNP suppression."
        echo "                 THIS IS THE REAL RED. The guard bites the regression it"
        echo "                 exists for, not merely the absence of the flags."
    else
        echo "  LEG A VERDICT: failed on the WRONG assertion — mis-aimed. Read above."
        note_failure "leg A failed on an unexpected assertion"
    fi
else
    echo "  LEG A VERDICT: *** PASSED UNDER NNP SUPPRESSION *** — the guard does NOT bite"
    echo "                 its own regression. Either the shim did not reach bwrap, or the"
    echo "                 assertion is wrong. Do not bank the grading until this is fixed."
    note_failure "leg A passed under the weaken"
fi

# --- LEG B : secondary RED — the flags removed -------------------------------
hr; echo "LEG B — secondary RED: the flags removed (exercises EMISSION only)"; hr
python3 - "$SRC_SANDBOX" <<'PY' || exit 2
import sys
p = sys.argv[1]
s = open(p).read()
old = '''        self.args.push("--cap-drop".to_string());
        self.args.push("ALL".to_string());
        self.args.push("--cap-add".to_string());
        self.args.push("CAP_SETUID".to_string());
        self.args.push("--cap-add".to_string());
        self.args.push("CAP_SETGID".to_string());
'''
assert s.count(old) == 1, f"expected exactly 1 occurrence, found {s.count(old)}"
open(p, 'w').write(s.replace(old, ''))
print("  weaken applied: with_credential_drop() emits nothing")
PY

B_BIN="$(build_test_bin "weakened")"
b_out="$(sudo "$B_BIN" --nocapture "$TEST_NAME" 2>&1)"
require_suite_ran "$b_out" "leg B"
require_guard_executed "$b_out" "leg B"
witnesses "$b_out"
echo
if printf '%s' "$b_out" | grep -q "the restriction is cosmetic"; then
    echo "  LEG B VERDICT: failed on the c0 assertion — expected."
    echo "                 SECONDARY. This exercises EMISSION, which the unit test already"
    echo "                 covers via assemble_profile. Leg A is the load-bearing RED."
else
    echo "  LEG B VERDICT: did not fail as expected — read above."
    note_failure "leg B did not fail on the c0 assertion"
fi

restore
trap - EXIT
trap restore EXIT

# --- LEG C : stability -------------------------------------------------------
hr; echo "LEG C — STABILITY: $ITERATIONS iterations, FULL lib suite, default parallel"; hr
C_BIN="$(build_test_bin "restored")"
echo "  Full suite each iteration: filtering to one test removes the concurrent load that"
echo "  is the reason §6 requires the default parallel setting."
echo "  --nocapture, and the guard's witnesses required — an 'ok' from a SKIP is not a run."
echo
pass=0; notok=0; suite_fail=0
for i in $(seq "$ITERATIONS"); do
    out="$(sudo "$C_BIN" --nocapture 2>&1)"
    require_suite_ran "$out" "stability iteration $i"
    require_guard_executed "$out" "stability iteration $i"
    if printf '%s' "$out" | grep -qE "^test execute::tests::$TEST_NAME \.\.\. ok$"; then
        pass=$((pass + 1))
    else
        notok=$((notok + 1))
        echo "  iteration $i: the guard did not report ok"
        printf '%s' "$out" | grep -E "$TEST_NAME|panicked at" | sed 's/^/    /'
    fi
    printf '%s' "$out" | grep -q "test result: FAILED" && suite_fail=$((suite_fail + 1))
done
echo
echo "  GUARD:  ok $pass / not-ok $notok  of $ITERATIONS   (each verified to have RUN)"
echo "  SUITE:  $suite_fail of $ITERATIONS iterations had ANY failing test"
if [ "$pass" -eq "$ITERATIONS" ] && [ "$suite_fail" -eq 0 ]; then
    echo "  STABILITY VERDICT: $pass/$ITERATIONS clean under default parallel."
else
    echo "  STABILITY VERDICT: NOT STABLE. A flake is a fact about the test."
    note_failure "stability not clean"
fi

# D0A-R16-04: the script's exit status must carry the outcome.
hr
if [ "$FAILURES" -eq 0 ]; then
    echo "ALL LEGS MET THEIR EXPECTATIONS."
else
    echo "$FAILURES LEG(S) DID NOT MEET THEIR EXPECTATION — exiting non-zero."
fi
hr
exit $(( FAILURES > 0 ? 1 : 0 ))
