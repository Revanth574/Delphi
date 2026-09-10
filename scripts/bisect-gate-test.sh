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

command -v cargo >/dev/null || REFUSE "cargo is not on PATH — build as the normal user, not root"
[ "$(id -u)" -ne 0 ] || REFUSE "run this as the NORMAL user; it builds with cargo and invokes \
sudo per iteration (root has no rustup toolchain)"

echo "== building HEAD ($(git rev-parse --short HEAD)) =="
cargo test -p delphi-runtime --test b1_integration --no-run --message-format=json 2>/dev/null \
  | python3 -c 'import sys,json
for l in sys.stdin:
    try: m=json.loads(l)
    except Exception: continue
    if m.get("executable") and m.get("profile",{}).get("test"): print(m["executable"])' \
  | sort -u > /tmp/bisect-head.txt
NEW_BIN=$(cat /tmp/bisect-head.txt)
[ -x "$NEW_BIN" ] || REFUSE "no HEAD test binary"

echo "== building $OLD in an isolated worktree =="
if [ ! -d "$WT" ]; then git worktree add --detach "$WT" "$OLD" >/dev/null; fi
OLD_BIN=$(cd "$WT" && CARGO_TARGET_DIR="$WT/target" cargo test -p delphi-runtime --test \
  b1_integration --no-run --message-format=json 2>/dev/null \
  | python3 -c 'import sys,json
for l in sys.stdin:
    try: m=json.loads(l)
    except Exception: continue
    if m.get("executable") and m.get("profile",{}).get("test"): print(m["executable"])' \
  | sort -u)
[ -x "$OLD_BIN" ] || REFUSE "no $OLD test binary"

echo "HEAD: $NEW_BIN"
echo "$OLD: $OLD_BIN"
echo "alternating $N iteration(s) per side; transcript: $OUT"

run_one() {   # $1 = label, $2 = binary
    local out rc
    out=$(sudo "$2" "$TEST" --nocapture --test-threads=1 2>&1) && rc=0 || rc=$?
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
    if grep -q "SKIP r4_03_daemon_real_gate" <<<"$out"; then
        REFUSE "the test SKIPPED (not root?) — a skip is scored as a PASS, so counting it \
would report a clean bisect from a test that never ran"
    fi
    if grep -qE '^test result: ok' <<<"$out"; then echo PASS; else echo "FAIL(rc=$rc)"; fi
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
