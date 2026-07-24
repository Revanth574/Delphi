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
# Optional serialised control arm: `--serial` adds --test-threads=1 so the same loop can be
# run both ways. Parallel is the DEFAULT because that is the configuration the flakiness
# rule targets; the serial arm exists to attribute failures to interference vs product.
THREADS=""
[ "${2:-}" = "--serial" ] && THREADS="--test-threads=1"
# ARM label derived from the flag that will actually reach the binary — never hardcoded,
# since a summary string claiming the wrong arm is the same self-misreport class this
# tool has already exhibited three times.
if [ -n "$THREADS" ]; then ARM="SERIAL (--test-threads=1)"; else ARM="PARALLEL (default threads)"; fi

command -v cargo >/dev/null || { echo "cargo not found — run UNPRIVILEGED"; exit 1; }
echo "=== building (unprivileged) ==="
LIST=$(cargo test -p delphi-runtime --test leader_is_shell \
        --no-run --message-format=json 2>/dev/null \
       | grep -o '"executable":"[^"]*"' | cut -d'"' -f4 | grep '/deps/')
[ -n "$LIST" ] || { echo "BUILD FAILED"; exit 1; }
echo "$LIST" | sed 's/^/  /'
sudo -v || { echo "CANNOT OBTAIN SUDO — nothing run; NOT a test result."; exit 2; }

PAMF=/etc/pam.d/delphi-runtime
[ -f "$PAMF" ] && PAM_BEFORE=$(sudo md5sum "$PAMF" | cut -d' ' -f1) || PAM_BEFORE=absent
[ "$PAM_BEFORE" = absent ] && echo "WARNING: PAM stack absent — root-gated tests will SKIP and prove nothing."

# Persist the log to a known path (NOT mktemp+trap-delete): the per-iteration output is
# needed AFTER the run for the useradd/non-execution check below, and a run worth 30 sudo
# iterations is worth keeping. Overwritten each invocation.
LOG="$PWD/scratch/iterate-flakiness.last.log"; : > "$LOG"
declare -A FAILCOUNT
TOTAL_FAIL=0   # plain counter: ${#FAILCOUNT[@]} is itself unbound-under-set-u when empty
runs=0; iters_with_failure=0

echo; echo "=== $N iterations, $ARM ==="
for i in $(seq 1 "$N"); do
  iter_failed=0
  while read -r bin; do
    out=$(sudo "$bin" --nocapture $THREADS 2>&1)   # parallel by default; $THREADS set by --serial
    echo "$out" >> "$LOG"
    while read -r t; do
      FAILCOUNT["$t"]=$(( ${FAILCOUNT["$t"]:-0} + 1 )); TOTAL_FAIL=$((TOTAL_FAIL+1)); iter_failed=1
    done < <(echo "$out" | grep -oP '^test \K[a-z0-9_]+(?= \.\.\. FAILED)')
  done <<< "$LIST"
  runs=$((runs+1)); [ "$iter_failed" -eq 1 ] && iters_with_failure=$((iters_with_failure+1))
  printf '\riteration %d/%d  (iterations with >=1 failure: %d)' "$i" "$N" "$iters_with_failure"
done
echo; echo

echo "════════ RESULTS over $runs iterations, $ARM ════════"
if [ "$TOTAL_FAIL" -eq 0 ]; then
  echo "NO FAILURES in any iteration."
else
  # Safe to expand the map here: TOTAL_FAIL>0 guarantees >=1 key was assigned.
  echo "per-test failure counts (test: failures/$runs):"
  for t in "${!FAILCOUNT[@]}"; do printf '  %-55s %d/%d\n' "$t" "${FAILCOUNT[$t]}" "$runs"; done
fi
echo
echo "SKIPs seen (a SKIP proves nothing):"
# Require a real test name after SKIP. The previous regex `SKIP [a-z0-9_]*` also matched
# the phrase "A SKIP INVALIDATES ..." inside our own skip TEXT — uppercase letters gave a
# zero-length match, printing a bare "SKIP " that looked like a skip with no reason.
grep -ohP 'SKIP \K[a-z0-9_]+(?=:)' "$LOG" | sort | uniq -c | sed 's/^/  /' || echo "  none"
echo
# COUNTING BUG FIXED (found when 34 markers appeared over 30 iterations, which is
# impossible on its face). EXECUTED_MARKER appears in BOTH the println AND the assertion
# panic messages, so grep -c counted 2 lines per FAILING execution and 1 per passing one:
#   15 failures x2 + 4 passes x1 = 34, i.e. only 19 real executions, not 30.
# Count a substring UNIQUE TO THE PRINTLN instead:
#   FD-01 println has "exec_done="   ; its panics do not.
#   B-1   println has "pinned_pid="  ; its panics say "pinned pid" / "pinned", no "=".
# EXECUTIONS: count a substring UNIQUE TO THE PRINTLN, so a failing execution (which also
# prints the marker in its panic) is not double-counted. This is the denominator: "0
# failures" is NOT a sufficient gate on its own, because 30 NON-executions also yield 0
# failures. The gate needs executions == $runs too.
# Count each of the THREE leader_is_shell tests by a substring UNIQUE TO ITS PRINTLN
# (never the panic messages, which repeat the marker and would double-count a failure).
FD01_EXEC=$(grep -c "B1-ASSERTION-EXECUTED(FD-01): shell_pid=.*exec_done=" "$LOG")
B1_EXEC=$(grep -c "^B1-ASSERTION-EXECUTED: pinned_pid=" "$LOG")
B3_EXEC=$(grep -c "B1-ASSERTION-EXECUTED(B3): shell_pid=.*exec_done=" "$LOG")
FD01_FAIL=${FAILCOUNT[shell_inherits_only_the_allowlisted_fds_fd_01]:-0}
B1_FAIL=${FAILCOUNT[session_leader_is_the_shell_itself_r3_01c]:-0}
B3_FAIL=${FAILCOUNT[shell_child_drops_to_the_session_user_b3]:-0}
echo "B-1  : reached assertion $B1_EXEC/$runs, failed $B1_FAIL"
echo "FD-01: reached assertion $FD01_EXEC/$runs, failed $FD01_FAIL"
echo "B-3  : reached assertion $B3_EXEC/$runs, failed $B3_FAIL"

# THE 11-NON-EXECUTION CHECK (needs no new run — reads this run's persisted log).
# Hypothesis on file: useradd loses the /etc/passwd lock under parallel fixture setup and
# Setup::new panics with an explicit message BEFORE any marker prints. If true, the
# non-executions carry that assert text; if absent, the hypothesis is killed for this run.
echo
echo "non-execution cause probe (useradd fixture-setup panics in this run's log):"
UADD=$(grep -c "failed — this is FIXTURE SETUP" "$LOG")
echo "  useradd fixture-setup panics: $UADD"
if [ "$FD01_EXEC" -lt "$runs" ] && [ "$UADD" -eq 0 ]; then
  echo "  -> non-executions present ($((runs - FD01_EXEC))) but NOT explained by useradd."
  echo "     Hypothesis KILLED for this run. Look elsewhere (panic before the println:"
  echo "     ensure_runtime_dir / bind_approval_socket / canonicalize / launch().expect)."
fi
# CAVEAT recorded in output: under --nocapture with parallel tests, stdout/stderr of the two
# tests in leader_is_shell INTERLEAVE, so a `test NAME ... FAILED` line can be split and
# missed by the per-line grep — which would itself manufacture apparent "non-executions".
# The SERIAL arm has no interleaving, so its counts are authoritative; a parallel/serial
# execution-count gap that the useradd probe does not explain is very likely this.
[ -n "$THREADS" ] || echo "  (parallel run: FAILED-line counts may be corrupted by nocapture interleaving; trust the serial arm)"
echo
[ -f "$PAMF" ] && PAM_AFTER=$(sudo md5sum "$PAMF" | cut -d' ' -f1) || PAM_AFTER=absent
if [ "$PAM_BEFORE" = "$PAM_AFTER" ]; then
  echo "PAM stack SURVIVED unchanged ($PAM_AFTER) — Class 16 part 1 OK"
else
  echo "!!! PAM STACK CHANGED: before=$PAM_BEFORE after=$PAM_AFTER — any SKIP above is COLLATERAL"
fi
echo
if [ -z "$THREADS" ]; then
  echo "NOTE ($ARM): binaries run SEQUENTIALLY (no backgrounding), but tests WITHIN each"
  echo "binary run in PARALLEL. Shared state (the VT, the PAM stack, concurrent useradd/PAM"
  echo "sessions) is in scope. Compare against the serialised control arm to separate harness"
  echo "interference from product behaviour:"
  echo "    bash scratch/iterate-flakiness.sh $N --serial"
else
  echo "NOTE ($ARM): tests within each binary run ONE AT A TIME — no within-binary shared-state"
  echo "interference and no --nocapture interleaving. These counts are the AUTHORITATIVE arm; a"
  echo "failure here is product behaviour, and a parallel-only failure is interference."
fi
echo
echo "════════ STABILITY VERDICT — each of the 3 tests: 0 failures AND executions == $runs ═══"
# The gate is per-test and uses the EXECUTION denominator, not the iteration count: 30
# non-executions also yield 0 failures, so 'executions == runs' is what proves the test
# actually reached its assertion every time (the FD-01-saga lesson).
stable=1
check() { # name exec fail
  if [ "$3" -eq 0 ] && [ "$2" -eq "$runs" ]; then
    echo "  PASS  $1 — 0 failures, $2/$runs executions"
  else
    echo "  FAIL  $1 — $3 failures, $2/$runs executions (need 0 failures AND $runs executions)"
    stable=0
  fi
}
check "B-1  " "$B1_EXEC"   "$B1_FAIL"
check "FD-01" "$FD01_EXEC" "$FD01_FAIL"
check "B-3  " "$B3_EXEC"   "$B3_FAIL"
echo
if [ "$stable" -eq 1 ]; then
  echo "STABLE: all three tests reached their assertion every iteration and never failed"
  echo "under $ARM. This is the >=30-iteration run the re-aimed/new tests owed, and it also"
  echo "exercises the reap_children teardown under repetition."
else
  echo "NOT STABLE: at least one test failed or under-executed. A failure is a real defect to"
  echo "diagnose (Iron Law #15 clause 1 — do NOT weaken the assertion); an execution < $runs is"
  echo "a fixture/harness problem to diagnose (panic before the println, e.g. useradd lock"
  echo "contention). Do NOT declare stable until every test is 0-failures / $runs-executions."
fi
