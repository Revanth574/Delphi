#!/bin/bash
# SPDX-License-Identifier: MIT
#
# P3a-2 / tty2-probe runner — starts the REAL daemon by hand (not via systemd) so it inherits
# the graphical session's display, which a systemd SYSTEM service cannot have.
#
#   sudo -E bash scratch/p3-daemon-run.sh tty3 <session-user>   # P3a-2
#   sudo -E bash scratch/p3-daemon-run.sh tty2 <session-user>   # the FORECLOSED-SHAPE probe
#
# WHY BY HAND. `systemctl show-environment` on this box is exactly LANG + PATH: a system
# service has no DISPLAY/WAYLAND_DISPLAY, and `shell_argv_envp` (launcher.rs:729) inherits the
# daemon's env, so a unit-started daemon gives the WRY host no display and it PANICS at GTK
# init (measured: exit 101, "Failed to initialize gtk backend!"). Running the daemon from a
# terminal inside the session is what supplies the display. This is a DIAGNOSTIC SHAPE, not a
# deployment shape — see the labels below.
set -uo pipefail

VT="${1:-}"
SESSION_USER="${2:-${SUDO_USER:-}}"
[ -n "$VT" ] && [ -n "$SESSION_USER" ] || {
    echo "usage: sudo -E bash $0 <ttyN> <session-user>"; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "must run as root (the daemon opens PAM sessions)"; exit 1; }

MARKER=/tmp/delphi-p3-marker

case "$VT" in
tty3)
  cat <<'LABEL'
╔══════════════════════════════════════════════════════════════════════════════════════╗
║ P3a-2 — the composition UP TO THE GATE. The gate is EXPECTED TO DENY.                ║
║                                                                                      ║
║ The shell's PAM session lands on tty3, which is not seat0's ActiveSession (GNOME's    ║
║ session on tty2 is). So `session_passes_gate` fails and the run ends in Denied.       ║
║ THAT IS THE EXPECTED RESULT, not a failure of the composition.                        ║
║                                                                                      ║
║ SUCCESS IS *NOT* THE MARKER FILE. No marker is written — execution never happens.    ║
║ Success = the shell renders + an explicit deny reason in the output.                  ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
LABEL
  ;;
tty2)
  cat <<'LABEL'
╔══════════════════════════════════════════════════════════════════════════════════════╗
║ FORECLOSED-SHAPE PROBE — THIS IS NOT P3, NOT P5, NOT GATE-POSITIVE-IN-SHIPPING-SHAPE.║
║                                                                                      ║
║ Putting the Delphi session on GNOME's own VT is the SECONDARY shape, which            ║
║ docs/TRUST_MODEL.md §4 R3-02a explicitly FORECLOSES:                                  ║
║   "# DECISION: Delphi deploys in the PRIMARY shape."                                  ║
║                                                                                      ║
║ The open question this answers is narrow and mechanical: does logind report a SECOND  ║
║ session on the foreground VT as Active?                                               ║
║                                                                                      ║
║ IF THE GATE PASSES HERE, SAY SO IN EXACTLY THESE TERMS: the gate was satisfied in a   ║
║ configuration the design REJECTS. It is a state-machine result, not a gate proof.     ║
║ Writing it up as "P3 passed" would be false.                                          ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
LABEL
  ;;
*)
  echo "unexpected VT '$VT' — expected tty2 or tty3. Refusing rather than guessing."; exit 2 ;;
esac

echo
# The marker MUST be absent: a survivor from a previous attempt makes a FAILED run read as a
# success. The pre-flight refuses on this too; re-checked here because this script is the
# thing that would be fooled.
if [ -e "$MARKER" ]; then
    echo "REFUSE: $MARKER already exists — a failed run would read as success. rm it first."
    exit 1
fi
echo "marker absent: $MARKER (its later existence would mean the action really executed)"
echo "seat0 ActiveSession before: $(loginctl show-seat seat0 -p ActiveSession --value 2>/dev/null)"
echo "foreground VT before:       $(fgconsole 2>/dev/null)"
echo

export DELPHI_SHELL_VT="$VT"
export DELPHI_AI_BIN=/usr/libexec/delphi-minimal-ai
export DELPHI_AI_EXE=/usr/bin/touch
export DELPHI_AI_ARG="$MARKER"
export DELPHI_AI_BIND_RW=/tmp
# The display the host draws on. Absent these the host panics at GTK init.
: "${XDG_RUNTIME_DIR:=/run/user/$(id -u "$SESSION_USER")}"
export XDG_RUNTIME_DIR
echo "display env: DISPLAY=${DISPLAY:-<unset>} WAYLAND_DISPLAY=${WAYLAND_DISPLAY:-<unset>} XDG_RUNTIME_DIR=$XDG_RUNTIME_DIR"
if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
    echo "REFUSE: no display in the environment — did you forget \`sudo -E\`?"
    echo "        Without it the host panics at GTK init (exit 101) and proves nothing."
    exit 1
fi
echo

LOG=$(mktemp /tmp/delphi-p3-run-XXXXXX.log)
echo "running the daemon (serves ONE action then exits); log: $LOG"
echo "─────────────────────────────────────────────────────────────────────────────"
/usr/libexec/delphi-runtimed --session "$SESSION_USER" 2>&1 | tee "$LOG"
rc=${PIPESTATUS[0]}
echo "─────────────────────────────────────────────────────────────────────────────"
echo "daemon exit: $rc"
echo

echo "── OBSERVED ──"
echo "outcome line:   $(grep -o 'DELPHI_RUNTIMED_OUTCOME.*' "$LOG" | head -1)"
echo "deny reason:    $(grep -oE 'logind: [^"]*|PAM authentication failed|mint-confirm[^"]*' "$LOG" | head -1)"
if grep -q "Failed to initialize gtk backend" "$LOG"; then
    echo "GTK INIT:       PANICKED — the host had no usable display (horn 1)."
else
    echo "GTK INIT:       ok (no panic) — the host got a display."
fi
if [ -e "$MARKER" ]; then
    echo "marker:         PRESENT — the action EXECUTED (gate passed, PAM passed, mint ok)"
    echo "                owner: $(stat -c '%U' "$MARKER")"
else
    echo "marker:         absent — no execution (expected for the tty3 run)"
fi
echo "seat0 ActiveSession after: $(loginctl show-seat seat0 -p ActiveSession --value 2>/dev/null)"
echo
echo "Full log kept at $LOG"
[ -e "$MARKER" ] && echo "NOTE: remove $MARKER before any subsequent run."
exit 0
