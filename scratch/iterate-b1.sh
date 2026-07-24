#!/bin/bash
# Characterise b1_integration's flakiness + attribute b1_daemon_binary_runs_the_assembled_flow.
#
# Unlike leader_is_shell, b1_integration has THREE distinct flakiness sources, so this reports
# per-test failure counts AND the actual failure/panic MESSAGES (the message is the evidence,
# the count is not — carry-forward from settling the parallel failures the same way):
#
#   * launch()-calling tests (b1_happy_path, b1_token_expiry, b1_launcher_keeps_the_channel_out
#     _of_the_ai, b1_logind_deny) fork+PAM from the MULTITHREADED test runner → the CLAUDE.md §6
#     fork+PAM carve-out predicts parallel failures = harness artifact, serial = clean.
#   * b1_daemon_binary runs the DAEMON BINARY (single-threaded fork parent) → the carve-out does
#     NOT apply; its failure, if any, is a DIFFERENT thing — its message is what attributes it.
#   * terminal_contract_release_produces_eof_no_wedge — pre-existing ~7-10% fd/EOF flaky.
#
# Run UNPRIVILEGED (it sudo's the binary). Default SERIAL; `--parallel` for the other arm.
#     bash scratch/iterate-b1.sh [N] [--parallel]
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/delphi-target}"
N="${1:-30}"
THREADS="--test-threads=1"; ARM="SERIAL"
[ "${2:-}" = "--parallel" ] && { THREADS=""; ARM="PARALLEL"; }

command -v cargo >/dev/null || { echo "cargo not found — run UNPRIVILEGED"; exit 1; }
echo "== building b1_integration (unprivileged) =="
BIN=$(cargo test -p delphi-runtime --test b1_integration --no-run --message-format=json 2>/dev/null \
      | grep -o '"executable":"[^"]*"' | cut -d'"' -f4 | grep '/deps/b1_integration')
[ -n "$BIN" ] || { echo "BUILD FAILED"; exit 1; }
echo "  $BIN"
sudo -v || { echo "CANNOT OBTAIN SUDO — nothing run; NOT a test result."; exit 2; }

LOG="$PWD/scratch/iterate-b1.last.log"; : > "$LOG"
PAMF=/etc/pam.d/delphi-runtime
[ -f "$PAMF" ] && PAM_BEFORE=$(sudo md5sum "$PAMF" | cut -d' ' -f1) || PAM_BEFORE=absent

declare -A FAILCOUNT
TOTAL_FAIL=0   # plain counter: ${#FAILCOUNT[@]} is itself unbound-under-set-u when empty
echo; echo "== $N iterations, $ARM =="
for i in $(seq 1 "$N"); do
  out=$(sudo "$BIN" --nocapture $THREADS 2>&1)
  printf '\n===== iteration %d =====\n%s\n' "$i" "$out" >> "$LOG"
  while read -r t; do
    FAILCOUNT["$t"]=$(( ${FAILCOUNT["$t"]:-0} + 1 )); TOTAL_FAIL=$((TOTAL_FAIL+1))
  done < <(echo "$out" | grep -oP '^test \K[a-z0-9_]+(?= \.\.\. FAILED)')
  printf '\riteration %d/%d' "$i" "$N"
done
echo; echo

echo "════════ per-test failures over $N iterations, $ARM ════════"
if [ "$TOTAL_FAIL" -eq 0 ]; then
  echo "  NO FAILURES in any iteration."
else
  for t in "${!FAILCOUNT[@]}"; do printf '  %-52s %d/%d\n' "$t" "${FAILCOUNT[$t]}" "$N"; done
fi
echo
echo "════════ b1_daemon_binary — the ACTUAL failure text (message is the evidence) ════════"
# Its assert prints the daemon subprocess's stderr on failure; pull the panic + surrounding
# daemon output so the failure can be ATTRIBUTED, not reasoned.
if grep -q "b1_daemon_binary_runs_the_assembled_flow.*FAILED" "$LOG"; then
  grep -A 20 "panicked at.*b1_integration" "$LOG" | grep -iE "daemon|stderr|Completed|execve|pam|VT|session|thread_park|assert" | sort -u | head -20
  echo "  (full context in $LOG)"
else
  echo "  b1_daemon_binary did NOT fail in this arm."
fi
echo
[ -f "$PAMF" ] && PAM_AFTER=$(sudo md5sum "$PAMF" | cut -d' ' -f1) || PAM_AFTER=absent
[ "$PAM_BEFORE" = "$PAM_AFTER" ] && echo "PAM stack unchanged ($PAM_AFTER)" \
  || echo "!!! PAM stack CHANGED $PAM_BEFORE -> $PAM_AFTER — a fixture deleted/rewrote it (Class 16 regression)"
echo
echo "READING GUIDE:"
echo "  * launch()-tests failing in PARALLEL but 0 in SERIAL  -> fork+PAM carve-out (harness artifact)."
echo "  * b1_daemon_binary failing in SERIAL                   -> real defect; read its message above."
echo "  * b1_daemon_binary 0 in SERIAL now (was failing pre-C2)-> ATTRIBUTE to the C2 install"
echo "    (real /etc/pam.d/delphi-runtime now present), NOT to 'was always serial-clean'."
echo "  * terminal_contract failing in either arm             -> the known ~7-10% fd/EOF flaky."
