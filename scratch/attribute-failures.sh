#!/bin/bash
# ATTRIBUTION: are systemd_smoke / b1_integration failures caused by C1, or pre-existing
# on this lane? Runs the SAME tests against the pre-C1 commit in a throwaway worktree.
#
# d57442e is the last commit before this session's runtime work: OLD launcher
# (Command/pre_exec, no pam_open_session at all), OLD two-line PAM fixture.
#
# Run UNPRIVILEGED (it sudo's the test binaries itself):  bash scratch/attribute-failures.sh
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/delphi-target}"

BASE=d57442e
WT=/tmp/delphi-pre-c1
SUITES="systemd_smoke b1_integration"

command -v cargo >/dev/null || { echo "cargo not found — run this UNPRIVILEGED"; exit 1; }
sudo -v || { echo "CANNOT OBTAIN SUDO — nothing run; this is NOT a test result."; exit 2; }

echo "### IMPORTANT: back up any installed PAM stack first."
echo "### The PRE-C1 fixtures unconditionally write AND delete /etc/pam.d/delphi-runtime."
if [ -f /etc/pam.d/delphi-runtime ]; then
  sudo cp -a /etc/pam.d/delphi-runtime /etc/pam.d/delphi-runtime.attrbak
  echo "backed up -> /etc/pam.d/delphi-runtime.attrbak"
fi
restore() {
  if [ -f /etc/pam.d/delphi-runtime.attrbak ]; then
    sudo mv /etc/pam.d/delphi-runtime.attrbak /etc/pam.d/delphi-runtime
    echo "restored /etc/pam.d/delphi-runtime"
  fi
  git worktree remove --force "$WT" 2>/dev/null
}
trap restore EXIT

git worktree add --detach "$WT" "$BASE" >/dev/null 2>&1 || { echo "worktree failed"; exit 1; }
echo "worktree at $BASE -> $WT"
echo

for suite in $SUITES; do
  echo "════════ $suite @ $BASE (PRE-C1) ════════"
  bin=$(cd "$WT" && cargo test -p delphi-runtime --test "$suite" --no-run --message-format=json 2>/dev/null \
        | grep -o '"executable":"[^"]*"' | cut -d'"' -f4 | grep -v '^null$' | tail -1)
  if [ -z "$bin" ]; then echo "  BUILD FAILED at $BASE"; continue; fi
  sudo "$bin" --nocapture --test-threads=1 2>&1 | grep -E "^test result:|^test .* FAILED|SKIP " || true
  echo
done

echo "════════════════════════════════════════"
echo "Compare with the HEAD run. Same failures at $BASE => PRE-EXISTING on this lane."
echo "Green at $BASE but failing at HEAD    => introduced by C1; diagnose before merging."
