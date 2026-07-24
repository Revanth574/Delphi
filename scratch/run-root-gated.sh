#!/bin/bash
# Run the runtime crate's ROOT-GATED test binaries.
#
# Discipline (measured 2026-07-22): BUILD UNPRIVILEGED, RUN THE BINARY AS ROOT.
# `sudo cargo` does not work on this lane — sudo resets PATH so cargo is not found,
# and -E is disabled by sudoers. Building as root would also leave root-owned
# artifacts in the developer's CARGO_TARGET_DIR.
#
# So: run this script UNPRIVILEGED. It builds as you, then sudo's each test binary.
#
#   bash scratch/run-root-gated.sh
#
# --test-threads=1 throughout: `terminal_contract_release_produces_eof_no_wedge` is
# flaky at ~7-10% under parallel execution (pre-existing at d57442e). ALWAYS confirm
# a failing test's NAME before concluding anything.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

# The workspace .cargo/config.toml pins build.target-dir to /home/raven/delphi-target —
# the WSL2 dev box's path, which does NOT exist on this VM (CLAUDE.md documents the pin as
# a developer-local assumption overridable by CARGO_TARGET_DIR). Without an override every
# cargo invocation here dies with "Permission denied (os error 13)". Default it to this
# user's home, while still honouring an explicit override.
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/delphi-target}"
echo "CARGO_TARGET_DIR=$CARGO_TARGET_DIR"

LIST=$(mktemp)
trap 'rm -f "$LIST"' EXIT

echo "=== building (unprivileged) ==="
cargo test -p delphi-runtime --tests --no-run --message-format=json 2>/dev/null \
  | grep -o '"executable":"[^"]*"' | cut -d'"' -f4 | grep -v '^null$' | grep '/deps/' > "$LIST"
rc=${PIPESTATUS[0]}
[ "$rc" -eq 0 ] || { echo "BUILD FAILED (exit $rc)"; exit 1; }
echo "found $(wc -l < "$LIST") test binaries"

# Acquire (and cache) sudo ONCE. Without this every binary fails on auth and the summary
# reports N TEST FAILURES — a misleading report of an environment problem. Fail loudly and
# distinctly instead.
if ! sudo -v; then
  echo
  echo "CANNOT OBTAIN SUDO — aborting. These tests need root (pam_open_session, /run anchor)."
  echo "Nothing was run; this is NOT a test result."
  exit 2
fi
echo

# Sweep stale /run/delphi-* dirs from any prior killed run BEFORE this run starts —
# see scratch/lib-run-sweep.sh. Prevents the accumulate-until-full-tmpfs failure mode
# (measured: 113 dirs, an hour of misattribution) rather than diagnosing it again.
source "$(dirname "$0")/lib-run-sweep.sh"
sweep_stale_run_delphi_dirs
echo

# CLASS 16 PART 1: the operator-installed stack must SURVIVE the suite. Recording the
# before-state makes a deletion visible immediately, at its cause, instead of surfacing
# later as unrelated tests reporting "not installed".
PAMF=/etc/pam.d/delphi-runtime
if [ -f "$PAMF" ]; then
  PAM_BEFORE=$(sudo md5sum "$PAMF" | cut -d' ' -f1)
  echo "PAM stack present before run (md5 $PAM_BEFORE)"
else
  PAM_BEFORE=absent
  echo "PAM stack ABSENT before run — install it, or root-gated tests will skip."
fi
echo

fail=0
while read -r bin; do
  name=$(basename "$bin" | sed 's/-[a-f0-9]\{16\}$//')
  echo "──────── $name ────────"
  out=$(sudo "$bin" --nocapture --test-threads=1 2>&1); brc=$?
  # The result lines, plus any SKIP reasons (invisible without --nocapture).
  echo "$out" | grep -E "^test result:|SKIP |^test .* FAILED|B1-ASSERTION-EXECUTED" || true
  if echo "$out" | grep -q "sudo:"; then
    echo "  ^^ COULD NOT RUN AS ROOT (sudo error) — this is an ENVIRONMENT failure,"
    echo "     NOT a test result. Do not read it as a pass or a fail."
    fail=$((fail+1))
  elif [ "$brc" -ne 0 ]; then
    fail=$((fail+1))
    echo "  ^^ TESTS FAILED (exit $brc) — confirm the test NAME before concluding:"
    echo "$out" | sed -n '/failures:/,$p' | head -30
  fi
  echo
done < "$LIST"

echo "════════════════════════════════════════"
if [ -f "$PAMF" ]; then PAM_AFTER=$(sudo md5sum "$PAMF" | cut -d' ' -f1); else PAM_AFTER=absent; fi
if [ "$PAM_BEFORE" = "$PAM_AFTER" ]; then
  echo "PAM stack SURVIVED unchanged (md5 $PAM_AFTER) — Class 16 part 1 OK"
else
  echo "!!! PAM STACK CHANGED: before=$PAM_BEFORE after=$PAM_AFTER"
  echo "!!! A fixture deleted or rewrote an operator-installed system file (defect Class 16)."
  echo "!!! Any later SKIP on \"not installed\" in this run is COLLATERAL, not a result."
  fail=$((fail+1))
fi
if [ "$fail" -eq 0 ]; then echo "ALL BINARIES EXITED 0"; else echo "$fail FAILURE(S) — check names above"; fi
