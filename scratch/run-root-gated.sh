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

# Heal a systemd_smoke run SIGKILLed inside its backup→restore window: that would leave the
# TEST's binary at /usr/libexec/delphi-runtimed and the operator's REAL one at the fixed
# .smoke-bak, silently. Restore it BEFORE snapshotting the baseline, so ART_BEFORE is the true
# state and a heal is not misread as a mid-run artifact change — and so the systemd-not-booted
# case (where systemd_smoke SKIPs and never self-heals) is still covered. systemd_smoke.rs's
# restore_stale_backup() is AUTHORITATIVE (it also protects a direct `cargo test systemd_smoke`);
# this is the runner's pre-snapshot mirror. Same self-healing shape as the /run sweep above.
SMOKE_BAK=/usr/libexec/delphi-runtimed.smoke-bak
if sudo test -e "$SMOKE_BAK"; then
  echo "healing a prior interrupted systemd_smoke run: restoring /usr/libexec/delphi-runtimed from $SMOKE_BAK"
  sudo mv -f "$SMOKE_BAK" /usr/libexec/delphi-runtimed
  echo
fi

# ── CLASS 16 / 17: the operator-installed artifacts must SURVIVE the suite ──────────────
# The PAM stack was NOT the only installer-owned path a fixture deleted — systemd_smoke.rs
# was deleting /usr/libexec/delphi-runtimed (Class 16, on a SIBLING path). A survival check
# written for ONE path (the old PAM-only md5) is itself the Class-17 mistake: it cannot see
# the same defect one path over. So this checks EVERY path the installer writes. Extend this
# list the moment installer/install.sh writes a NEW path — same discipline as
# runtime/tests/fixture_hygiene.rs's SHARED_SYSTEM_PATHS.
ARTIFACTS=(
  /etc/pam.d/delphi-runtime
  /usr/libexec/delphi-runtimed
  /usr/libexec/delphi-shell
  /usr/libexec/delphi-minimal-ai
  /usr/lib/systemd/system/delphi-runtimed@.service
)
declare -A ART_BEFORE ART_AFTER
snapshot() {   # $1 = name of assoc array to populate
  local -n _arr="$1"; local p
  for p in "${ARTIFACTS[@]}"; do
    if [ -f "$p" ]; then _arr["$p"]=$(sudo md5sum "$p" 2>/dev/null | cut -d' ' -f1); else _arr["$p"]=absent; fi
  done
}
snapshot ART_BEFORE
echo "installer-owned artifacts before the run:"
for p in "${ARTIFACTS[@]}"; do printf '  %-52s %s\n' "$p" "${ART_BEFORE[$p]}"; done
[ "${ART_BEFORE[/etc/pam.d/delphi-runtime]}" = absent ] && \
  echo "  WARNING: PAM stack absent — root-gated tests will SKIP. Run installer/install.sh."
echo

# ── GAP 1: the live 'who-touches-it' probe (auditd). If absent, say so LOUDLY — a green ──
# before/after md5 detects a NET change but NOT the actor, and the same green md5 already
# failed twice to settle the PAM disappearance. Do not let its absence pass silently.
AUDIT=0
if command -v auditctl >/dev/null 2>&1 && sudo auditctl -s >/dev/null 2>&1; then
  for p in "${ARTIFACTS[@]}"; do sudo auditctl -w "$p" -p wa -k delphiartifact >/dev/null 2>&1; done
  AUDIT=1
  echo "auditd watch ARMED on all installer-owned paths (key: delphiartifact)."
else
  echo "!!! auditd/auditctl NOT available — the live 'who-deletes-it' probe did NOT run."
  echo "!!! The before/after md5 below sees a NET change but CANNOT name the actor."
  echo "!!! To actually probe: sudo apt-get install -y auditd && re-run this script."
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

# ── GAP 3: b1_daemon_binary SKIPs without the seam (a SKIP proves nothing). Build the ────
# feature binary and RUN it, so the assembled daemon flow actually COUNTS. With the seam
# compiled in + DELPHI_INSECURE_ASSUME_ACTIVE_SESSION set, the gate is bypassed and the flow
# runs to `Completed` deterministically on any root+bwrap host (seating-independent).
echo "──────── b1_daemon_binary (--features insecure-test-seams — making the SKIP COUNT) ────────"
FEATBIN=$(cargo test -p delphi-runtime --test b1_integration --features insecure-test-seams \
          --no-run --message-format=json 2>/dev/null \
          | grep -o '"executable":"[^"]*"' | cut -d'"' -f4 | grep '/deps/b1_integration' | head -1)
if [ -z "$FEATBIN" ]; then
  echo "  BUILD FAILED for the --features insecure-test-seams binary"; fail=$((fail+1))
else
  fout=$(sudo "$FEATBIN" b1_daemon_binary_runs_the_assembled_flow --nocapture --test-threads=1 2>&1); frc=$?
  echo "$fout" | grep -E "^test result:|DELPHI_RUNTIMED_OUTCOME|SKIP |FAILED" || true
  if [ "$frc" -ne 0 ] || echo "$fout" | grep -q "SKIP b1_daemon_binary"; then
    echo "  ^^ b1_daemon_binary did NOT positively COMPLETE (SKIP or fail) — the feature run is"
    echo "     REQUIRED for the daemon flow to count; a SKIP is not a pass (Iron Law #15)."
    fail=$((fail+1))
  fi
fi
echo

echo "════════════════════════════════════════"
# CLASS 16/17 net-survival verdict across ALL installer-owned paths.
snapshot ART_AFTER
changed=0
for p in "${ARTIFACTS[@]}"; do
  if [ "${ART_BEFORE[$p]}" != "${ART_AFTER[$p]}" ]; then
    echo "!!! ARTIFACT CHANGED: $p  before=${ART_BEFORE[$p]}  after=${ART_AFTER[$p]}"
    changed=$((changed+1))
  fi
done
if [ "$changed" -eq 0 ]; then
  echo "ALL installer-owned artifacts SURVIVED unchanged — Class 16/17 property OK"
  echo "  (includes /usr/libexec/delphi-runtimed — the file systemd_smoke.rs was deleting;"
  echo "   an unchanged md5 confirms backup-and-restore restored the ORIGINAL, not a copy.)"
else
  echo "!!! $changed installer-owned artifact(s) changed — a fixture destroyed/rewrote an"
  echo "!!! operator file mid-run (defect Class 16/17). Any later \"not installed\" SKIP is COLLATERAL."
  fail=$((fail+1))
fi

# Read back + disarm the audit watch (the actor, if anything touched a watched path).
if [ "$AUDIT" = 1 ]; then
  echo
  echo "=== audit events on installer-owned paths (the ACTOR — proctitle/comm/pid) ==="
  sudo ausearch -k delphiartifact -i 2>/dev/null \
    | grep -iE "type=(SYSCALL|PATH).*(unlink|rename|delete|open.*O_TRUNC)|comm=|proctitle=|exe=" \
    | tail -60 || echo "  (no write/delete events recorded — nothing modified a watched path)"
  for p in "${ARTIFACTS[@]}"; do sudo auditctl -W "$p" -p wa -k delphiartifact >/dev/null 2>&1; done
else
  echo
  echo "NOTE: no audit trail this run (auditd absent). If any artifact changed above, the actor"
  echo "      was NOT captured — install auditd and re-run to name it."
fi

if [ "$fail" -eq 0 ]; then echo "ALL BINARIES EXITED 0"; else echo "$fail FAILURE(S) — check names above"; fi
