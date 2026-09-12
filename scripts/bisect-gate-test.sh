#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# Decide whether `the_daemon_binary_runs_the_real_gate_d0a_r4_03`'s PERSISTENT failure
# (D0A-R35, runs 24 and 25, `pam_open_session failed`) belongs to this commit range.
#
# It failed 2/2 on runs carrying the negative-control commits and 0/3 on runs without them.
# That is a correlation with NO mechanism: the two hypotheses available were tested and
# eliminated — stale sessions (the pre-run check reported clean before AND after run 25) and
# test ordering (the inserted test SKIPS instantly, so it removes no slack). This converts the
# correlation into a cause or eliminates the range.
#
# TWO PROPERTIES THIS HARNESS MUST HAVE, and both are load-bearing:
#
#   1. IT REFUSES A SKIP. The test is root-gated, and a skipped test is scored as a PASS by
#      libtest (DEFECT_CLASSES 10). Run unprivileged, a bisect would report zero failures on
#      BOTH sides and conclude "no difference" from a test that never executed — a clean answer
#      from no measurement, which is the worst outcome available here.
#
#   2. IT ALTERNATES A/B/A/B. Running all of one side then all of the other confounds the
#      result with anything that drifts over the session — session pressure, accumulated
#      logind state, thermal. Alternating makes any drift hit both sides equally. This matters
#      because the failure being investigated is one whose only surviving hypothesis is
#      environmental.
set -euo pipefail

TEST=the_daemon_binary_runs_the_real_gate_d0a_r4_03
N=${1:-5}
OLD=${2:-b51bd8f}
WT=/tmp/delphi-bisect-$OLD
OUT=/tmp/bisect-$TEST-$(date -u +%Y%m%dT%H%M%SZ).txt

REFUSE() { echo "REFUSING: $*" >&2; exit 2; }

# D0A-R36-07: validate N BEFORE spending two builds on it. `seq 1 0` runs zero iterations and
# reports "0 pass / 0 fail" on both sides, which reads as a clean comparison.
case "$N" in ''|*[!0-9]*) REFUSE "iteration count '$N' is not a number" ;; esac
[ "$N" -ge 1 ] || REFUSE "iteration count must be at least 1; '$N' would compare nothing"

command -v cargo >/dev/null || REFUSE "cargo is not on PATH — build as the normal user, not root"
[ "$(id -u)" -ne 0 ] || REFUSE "run this as the NORMAL user; it builds with cargo and invokes \
sudo per iteration (root has no rustup toolchain)"

# D0A-R35: BUILD BOTH SIDES THE SAME WAY, INCLUDING THE FEATURE-GATED AUXILIARY BINARIES.
# The first run of this script compared a HEAD target dir CONTAMINATED with feature-built
# artifacts against a clean worktree, and the worktree side skipped:
#
#   SKIP r4_03_daemon_real_gate: measured blocker: .../delphi-surface-shell does not exist
#
# `delphi-surface-shell` carries `required-features = ["insecure-test-seams"]`, so a featureless
# build does not produce it — and the test SKIPS when it is absent. HEAD only ran because a
# previous Part B had left one in the shared target dir. Comparing a contaminated tree against a
# clean one measures the contamination.
build_both() {   # $1 = dir, $2 = target dir
    ( cd "$1" && CARGO_TARGET_DIR="$2" cargo test -p delphi-runtime --features \
        insecure-test-seams --test b1_integration --no-run >/dev/null 2>&1 ) \
      || REFUSE "feature build failed in $1"
    ( cd "$1" && CARGO_TARGET_DIR="$2" cargo test -p delphi-runtime --test b1_integration \
        --no-run --message-format=json 2>/dev/null \
      | python3 -c 'import sys,json
for l in sys.stdin:
    try: m=json.loads(l)
    except Exception: continue
    if m.get("executable") and m.get("profile",{}).get("test"): print(m["executable"])' \
      | sort -u )
}

echo "== building HEAD ($(git rev-parse --short HEAD)) =="
NEW_BIN=$(build_both "$PWD" "${CARGO_TARGET_DIR:-$PWD/target}")
[ -x "$NEW_BIN" ] || REFUSE "no HEAD test binary"

echo "== building $OLD in an isolated worktree =="
# A worktree whose directory is gone but whose REGISTRATION survives makes `add` fail with
# "missing but already registered". That is exactly what /tmp being cleaned between sessions
# produces — and it is the same hazard the lane's own retention fixed: state parked in /tmp does
# not survive, while the registration in .git does. Prune first, then add.
if [ ! -d "$WT" ]; then
    git worktree prune
    if git worktree list --porcelain | grep -qxF "worktree $WT"; then
        git worktree remove --force "$WT" 2>/dev/null || true
        git worktree prune
    fi
    git worktree add --detach "$WT" "$OLD" >/dev/null \
      || REFUSE "could not create the $OLD worktree at $WT"
fi
OLD_BIN=$(build_both "$WT" "$WT/target")
[ -x "$OLD_BIN" ] || REFUSE "no $OLD test binary"

# Both trees must now carry the auxiliary binary the test needs, or the comparison is between
# a test that runs and a test that skips.
for pair in "HEAD:${CARGO_TARGET_DIR:-$PWD/target}" "$OLD:$WT/target"; do
    d="${pair#*:}"
    [ -x "$d/debug/delphi-surface-shell" ] \
      || REFUSE "${pair%%:*} has no delphi-surface-shell — the test would SKIP on that side"
done

echo "HEAD: $NEW_BIN"
echo "$OLD: $OLD_BIN"
echo "alternating $N iteration(s) per side; transcript: $OUT"

run_one() {   # $1 = label, $2 = binary
    local out rc
    # `--exact` so the filter cannot select a DIFFERENT test that happens to share a prefix.
    out=$(sudo "$2" --exact "$TEST" --nocapture --test-threads=1 2>&1) && rc=0 || rc=$?
    printf '\n===== %s =====\n%s\n' "$1" "$out" >> "$OUT"
    # THE TEST MUST HAVE ACTUALLY RUN. Verified by building this and watching it print
    # "BOTH sides fail — the range is ELIMINATED" from ZERO measurements: `sudo` could not
    # authenticate, both invocations returned nonzero, and each was counted as a test failure.
    # A harness that reports a confident bisect from a binary that never executed is the exact
    # defect this one exists to avoid, and it had it on first use.
    if ! grep -qE '^test result:' <<<"$out"; then
        printf 'REFUSING: the test binary produced NO `test result:` line, so it did not run.\n' >&2
        printf 'Neither PASS nor FAIL is a measurement here. First 5 lines of its output:\n' >&2
        head -5 <<<"$out" >&2
        exit 2
    fi
    # A DAEMON THAT REFUSES ITS OWN HELPER NEVER REACHED THE GATE. `build.rs` compiles
    # `helper/delphi-drop.rs` into OUT_DIR and pins the digest of THAT binary, so a tree built
    # at a different path pins a different helper than the installed one — measured: the helper
    # source and build.rs are IDENTICAL across the two commits, so the mismatch is build-path
    # nondeterminism, not a source change. Counting it as a test failure produced
    # "only b51bd8f fails", which is a confident answer about a gate that never ran.
    if grep -q "is not the helper this daemon was built against" <<<"$out"; then
        printf 'REFUSING: %s pinned a helper that is not the installed one, so it never\n' "$1" >&2
        printf 'reached the gate. This is a NON-MEASUREMENT, not a FAIL.\n\n' >&2
        grep -o 'built [0-9a-f]\{16\}\|installed [0-9a-f]\{16\}' <<<"$out" | head -2 >&2
        printf '\nAn out-of-tree build cannot run against an installed helper. To measure an\n' >&2
        printf 'older commit you must install ITS helper first, which mutates system state --\n' >&2
        printf 'do that deliberately or not at all.\n' >&2
        exit 2
    fi
    if grep -q "SKIP r4_03_daemon_real_gate" <<<"$out"; then
        REFUSE "the test SKIPPED (not root?) — a skip is scored as a PASS, so counting it \
would report a clean bisect from a test that never ran"
    fi
    # D0A-R36-07: A SUMMARY LINE IS NOT EXECUTION OF THE REQUESTED TEST. `run_one` returned
    # PASS for a real libtest binary reporting `running 0 tests` / `test result: ok. 0 passed` —
    # so an older revision that simply does not CONTAIN the test scores clean, which is the
    # answer a bisect most wants to hear and least deserves to.
    if ! grep -qE "^test ${TEST} \.\.\." <<<"$out"; then
        REFUSE "the transcript never names $TEST, so this side ran SOMETHING ELSE (or nothing). \
A revision that does not contain the test is not a revision that passes it"
    fi
    if ! grep -qE '^test result: (ok|FAILED)\. [01] passed; [01] failed' <<<"$out"; then
        REFUSE "expected exactly one test to complete; the summary says: \
$(grep -E '^test result:' <<<"$out" | head -1)"
    fi
    if grep -qE '^test result: ok\. 0 passed' <<<"$out"; then
        REFUSE "ZERO tests ran and the binary still reported ok — a filter that matched no \
test is not a measurement of that test"
    fi
    if grep -qE '\.\.\. ignored' <<<"$out"; then
        REFUSE "the test was IGNORED, which libtest scores as a pass"
    fi
    if grep -qE '^test result: ok' <<<"$out"; then
        [ "$rc" -eq 0 ] || REFUSE "the summary says ok but the process exited $rc — the \
transcript and the exit status disagree, and neither is evidence while they do"
        echo PASS
    else
        [ "$rc" -ne 0 ] || REFUSE "the summary reports a failure but the process exited 0"
        echo "FAIL(rc=$rc)"
    fi
}

: > "$OUT"
head_pass=0; head_fail=0; old_pass=0; old_fail=0
for i in $(seq 1 "$N"); do
    scripts/check-stale-test-sessions.sh >/dev/null 2>&1 \
      || REFUSE "a stale session exists before iteration $i — the measurement would be \
confounded by the one hypothesis already eliminated"
    r=$(run_one "HEAD iteration $i" "$NEW_BIN")
    [ "$r" = PASS ] && head_pass=$((head_pass+1)) || head_fail=$((head_fail+1))
    printf '  %2d  HEAD %-10s' "$i" "$r"
    r=$(run_one "$OLD iteration $i" "$OLD_BIN")
    [ "$r" = PASS ] && old_pass=$((old_pass+1)) || old_fail=$((old_fail+1))
    printf '%s %s\n' "$OLD" "$r"
done

echo
echo "HEAD  : $head_pass pass / $head_fail fail   (of $N)"
echo "$OLD: $old_pass pass / $old_fail fail   (of $N)"
echo
if [ "$head_fail" -gt 0 ] && [ "$old_fail" -eq 0 ]; then
    echo "READING: the failure is IN THIS RANGE. The correlation becomes a cause and the"
    echo "         commits between $OLD and HEAD are the subject."
elif [ "$head_fail" -gt 0 ] && [ "$old_fail" -gt 0 ]; then
    echo "READING: BOTH sides fail — the range is ELIMINATED. The failure predates $OLD and"
    echo "         runs 20/21/23 passing it was luck, which makes it INTERMITTENT with a high"
    echo "         rate rather than persistent-since-my-change."
elif [ "$head_fail" -eq 0 ] && [ "$old_fail" -eq 0 ]; then
    echo "READING: NEITHER side fails. The 2/2 in runs 24-25 is then not reproducible in"
    echo "         isolation, which points at the FULL-SUITE context (something earlier in the"
    echo "         run) rather than at either commit. That is a third finding, not a clean bill."
else
    echo "READING: only $OLD fails, which contradicts runs 20/21/23. Suspect the harness before"
    echo "         believing it."
fi
echo
echo "transcript retained: $OUT"
echo "collect the worktree when done:  git worktree remove --force $WT"
