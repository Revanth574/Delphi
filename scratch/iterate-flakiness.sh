#!/bin/bash
# STABILITY CHARACTERISATION — >=30 iterations under DEFAULT PARALLEL settings.
#
# Two purposes in one loop (they share the same expensive root setup):
#   1. FD-01 must pass EVERY iteration before it is weakened. It has already produced a
#      pass then a fail; the cause (fixture collision) is understood and fixed, but FIXED IS
#      NOT DEMONSTRATED STABLE. If it is still intermittent for any other reason, a FAIL
#      under the weaken cannot be distinguished from "it failed this time".
#   2. Characterise b1_integration's own flakiness (1 failure one run, 2 the next), which
#      currently blocks attributing b1_daemon_binary_runs_the_assembled_flow.
#
# DEFAULT PARALLELISM, deliberately — NOT --test-threads=1. leader_is_shell now holds two
# tests that each create a system account and open a PAM session; concurrent execution is
# exactly the interference this rule targets, and the collision just fixed proves the risk
# is real. Serialising would hide precisely what is being measured (CLAUDE.md, the Codex
# round-loop rule).
#
# Run UNPRIVILEGED; it builds as you and sudo's each iteration.
#     bash scratch/iterate-flakiness.sh [N]        (default N=30)
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/delphi-target}"
N="${1:-30}"

command -v cargo >/dev/null || { echo "cargo not found — run UNPRIVILEGED"; exit 1; }
echo "=== building (unprivileged) ==="
LIST=$(cargo test -p delphi-runtime --test leader_is_shell --test b1_integration \
        --no-run --message-format=json 2>/dev/null \
       | grep -o '"executable":"[^"]*"' | cut -d'"' -f4 | grep '/deps/')
[ -n "$LIST" ] || { echo "BUILD FAILED"; exit 1; }
echo "$LIST" | sed 's/^/  /'
sudo -v || { echo "CANNOT OBTAIN SUDO — nothing run; NOT a test result."; exit 2; }

PAMF=/etc/pam.d/delphi-runtime
[ -f "$PAMF" ] && PAM_BEFORE=$(sudo md5sum "$PAMF" | cut -d' ' -f1) || PAM_BEFORE=absent
[ "$PAM_BEFORE" = absent ] && echo "WARNING: PAM stack absent — root-gated tests will SKIP and prove nothing."

LOG=$(mktemp); trap 'rm -f "$LOG"' EXIT
declare -A FAILCOUNT
runs=0; iters_with_failure=0

echo; echo "=== $N iterations, DEFAULT parallelism ==="
for i in $(seq 1 "$N"); do
  iter_failed=0
  while read -r bin; do
    out=$(sudo "$bin" --nocapture 2>&1)          # NO --test-threads=1: parallel on purpose
    echo "$out" >> "$LOG"
    while read -r t; do
      FAILCOUNT["$t"]=$(( ${FAILCOUNT["$t"]:-0} + 1 )); iter_failed=1
    done < <(echo "$out" | grep -oP '^test \K[a-z0-9_]+(?= \.\.\. FAILED)')
  done <<< "$LIST"
  runs=$((runs+1)); [ "$iter_failed" -eq 1 ] && iters_with_failure=$((iters_with_failure+1))
  printf '\riteration %d/%d  (iterations with >=1 failure: %d)' "$i" "$N" "$iters_with_failure"
done
echo; echo

echo "════════ RESULTS over $runs iterations (parallel) ════════"
if [ ${#FAILCOUNT[@]} -eq 0 ]; then
  echo "NO FAILURES in any iteration."
else
  echo "per-test failure counts (test: failures/$runs):"
  for t in "${!FAILCOUNT[@]}"; do printf '  %-55s %d/%d\n' "$t" "${FAILCOUNT[$t]}" "$runs"; done
fi
echo
echo "SKIPs seen (a SKIP proves nothing):"
grep -oh "SKIP [a-z0-9_]*" "$LOG" | sort -u | sed 's/^/  /' || echo "  none"
echo
echo "FD-01 executions reaching the assertion:"
grep -c "B1-ASSERTION-EXECUTED(FD-01)" "$LOG" | sed 's/^/  markers: /'
echo "B-1 executions reaching the assertion:"
grep -c "^B1-ASSERTION-EXECUTED:" "$LOG" | sed 's/^/  markers: /'
echo
[ -f "$PAMF" ] && PAM_AFTER=$(sudo md5sum "$PAMF" | cut -d' ' -f1) || PAM_AFTER=absent
if [ "$PAM_BEFORE" = "$PAM_AFTER" ]; then
  echo "PAM stack SURVIVED unchanged ($PAM_AFTER) — Class 16 part 1 OK"
else
  echo "!!! PAM STACK CHANGED: before=$PAM_BEFORE after=$PAM_AFTER — any SKIP above is COLLATERAL"
fi
echo
echo "GATE FOR WEAKENING FD-01: it must show 0 failures AND a marker count equal to $runs."
echo "Anything less means 'fixed' is not yet 'demonstrated stable', and a FAIL under the"
echo "weaken could not be distinguished from an intermittent failure."
