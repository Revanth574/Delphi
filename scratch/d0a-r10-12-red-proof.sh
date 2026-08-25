#!/bin/bash
# SPDX-License-Identifier: MIT
#
# D0A-R10-12 — the RED and the >=30 stability run the guard owes, as one invocation.
#
# ── RUN THIS UNPRIVILEGED. It sudo's for the test BINARY only. ────────────────────────
#
# The first version of this script ran the whole thing under sudo and called `cargo`
# inside. It never ran anything: sudo's `secure_path` does not contain ~/.cargo/bin, so
# cargo was not found, and `CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/delphi-target}"`
# expanded $HOME to /root — a different tree. Both legs then read the ABSENCE of a failure
# line as a verdict: the RED reported "PASSED UNDER THE WEAKEN" and the stability leg
# reported `ok 0 / not-ok 30` beside `0 of 30 had ANY failing test`. Those two lines
# contradict each other, and that contradiction is the only reason it was caught.
#
# That is the exact defect this script exists to detect, committed by the script. Hence
# the two structural rules below, which are not stylistic:
#
#   1. BUILD BEFORE THE SUDO BOUNDARY. cargo runs as the user, with the user's PATH and
#      CARGO_TARGET_DIR; only the built test binary is exec'd under sudo. (`bwrap_path()`
#      uses absolute candidates and /usr/bin/bwrap is inside secure_path, so the test
#      itself needs nothing from the user's PATH.)
#   2. ABSENCE IS NOT AN OUTCOME. Every run must produce a `test result:` line. If it does
#      not, the script EXITS NON-ZERO saying the run failed — it does not classify.

set -u -o pipefail

SRC="runtime/src/sandbox.rs"
TEST_NAME="the_predrop_payload_cannot_recover_capabilities_across_a_further_exec"
ITERATIONS="${ITERATIONS:-30}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/delphi-target}"

hr() { printf '%s\n' "============================================================"; }

# RULE 1: refuse to run as root. Under sudo the BUILD would be root's, which is the
# failure this script is a correction for.
if [ "$(id -u)" -eq 0 ]; then
    echo "REFUSING: run this UNPRIVILEGED — it sudo's for the test binary only."
    echo "  As root, cargo builds into root's tree with root's PATH, which is exactly how"
    echo "  the previous version measured nothing. Run:  scratch/d0a-r10-12-red-proof.sh"
    exit 1
fi
[ -f "$SRC" ] || { echo "REFUSING: run from the repo root (no $SRC)"; exit 1; }
command -v cargo >/dev/null || { echo "REFUSING: cargo not on PATH"; exit 1; }

echo "Priming sudo (the test binary needs root; the build does not)..."
sudo -v || { echo "REFUSING: sudo unavailable"; exit 1; }

BACKUP="$(mktemp)"
cp "$SRC" "$BACKUP"
restore() {
    cp "$BACKUP" "$SRC"
    if cmp -s "$BACKUP" "$SRC"; then
        echo "RESTORED: $SRC byte-identical to the pre-run backup."
    else
        echo "!!! RESTORE FAILED — $SRC differs from $BACKUP. Fix before committing."
    fi
}
trap restore EXIT

# Build unprivileged; print the test binary path. Hard-fails rather than returning empty.
build_test_bin() { # build_test_bin <context>
    local ctx="$1" json bin
    if ! json="$(cargo test -p delphi-runtime --lib --no-run --message-format=json 2>/dev/null)"; then
        echo "!!! BUILD FAILED ($ctx) — cannot proceed." >&2
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
    if [ -z "$bin" ] || [ ! -x "$bin" ]; then
        echo "!!! NO TEST BINARY ($ctx) — cargo produced no executable path." >&2
        exit 2
    fi
    printf '%s\n' "$bin"
}

# RULE 2: a run with no `test result:` line is a FAILED RUN, not a verdict.
require_suite_ran() { # require_suite_ran <output> <context>
    if ! printf '%s' "$1" | grep -q "test result:"; then
        echo
        echo "!!! NO SUITE RAN ($2) — the output contains no 'test result:' line."
        echo "    That is a failed run, not an outcome. Refusing to classify it."
        printf '%s\n' "$1" | tail -15 | sed 's/^/    | /'
        exit 2
    fi
}

# --- RED ---------------------------------------------------------------------
hr; echo "RED — the guard against the PRE-FIX profile"; hr
python3 - "$SRC" <<'PY' || exit 2
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
print("  weaken applied: with_credential_drop() now emits nothing")
PY

RED_BIN="$(build_test_bin "weakened")"
echo "  built (weakened): $RED_BIN"
red_out="$(sudo -E "$RED_BIN" --nocapture "$TEST_NAME" 2>&1)"
require_suite_ran "$red_out" "RED leg"

echo "$red_out" | grep -E "restricted \(|control    \(|^test .*$TEST_NAME|panicked at|test result" | sed 's/^/  /'
echo
if echo "$red_out" | grep -q "test result: FAILED"; then
    if echo "$red_out" | grep -q "the restriction is cosmetic"; then
        echo "  RED VERDICT: failed on the c0 assertion."
        echo
        echo "  READ THIS BEFORE BANKING IT. This weaken removes the FLAGS, so it exercises"
        echo "  EMISSION — which the_credential_drop_restriction_is_emitted_only_when_asked"
        echo "  already covers with two weakens of its own. It does NOT establish that the"
        echo "  guard bites the regression it exists for (bwrap dropping no_new_privs), and"
        echo "  that variable is not ours to remove. The guard's discrimination rests on the"
        echo "  probe pair — window-probe legs 4b and 6b/6c — not on this run."
        echo "  Recorded as a limit: CONFORMANCE_REGISTER.md D0A-R10-12."
    elif echo "$red_out" | grep -q "PRECONDITION FAILED"; then
        echo "  RED VERDICT: failed on the CONTROL PRECONDITION — the platform cannot"
        echo "               demonstrate the property either way. Not a statement about the guard."
    else
        echo "  RED VERDICT: failed for an UNCLASSIFIED reason — read the output above."
    fi
elif echo "$red_out" | grep -q "SKIP $TEST_NAME"; then
    echo "  RED VERDICT: THE TEST SKIPPED — it proved nothing. Check root/bwrap."
else
    echo "  RED VERDICT: *** PASSED UNDER THE WEAKEN *** — the guard does not even notice"
    echo "               absent flags, which is a real defect. Fix before reading further."
fi

restore
trap - EXIT
trap restore EXIT

# --- STABILITY ---------------------------------------------------------------
echo
hr; echo "STABILITY — $ITERATIONS iterations, FULL lib suite, default parallel"; hr
STAB_BIN="$(build_test_bin "restored")"
echo "  built (restored): $STAB_BIN"
echo "  Full suite each iteration on purpose: filtering to one test removes the concurrent"
echo "  load that is the reason CLAUDE.md §6 requires the default parallel setting."
echo
pass=0; notok=0; suite_fail=0
for i in $(seq "$ITERATIONS"); do
    out="$(sudo -E "$STAB_BIN" 2>&1)"
    require_suite_ran "$out" "stability iteration $i"
    if printf '%s' "$out" | grep -qE "^test execute::tests::$TEST_NAME \.\.\. ok$"; then
        pass=$((pass + 1))
    else
        notok=$((notok + 1))
        echo "  iteration $i: the guard did NOT report ok"
        printf '%s' "$out" | grep -E "$TEST_NAME|panicked at" | sed 's/^/    /'
    fi
    printf '%s' "$out" | grep -q "test result: FAILED" && suite_fail=$((suite_fail + 1))
done

echo
echo "  GUARD:  ok $pass / not-ok $notok  of $ITERATIONS"
echo "  SUITE:  $suite_fail of $ITERATIONS iterations had ANY failing test"
echo
if [ "$pass" -eq "$ITERATIONS" ] && [ "$suite_fail" -eq 0 ]; then
    echo "  STABILITY VERDICT: $pass/$ITERATIONS clean under default parallel."
else
    echo "  STABILITY VERDICT: NOT STABLE. A flake is a fact about the test — do not"
    echo "                     re-run until green (CLAUDE.md §6)."
fi
hr
