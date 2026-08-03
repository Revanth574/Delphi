#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Refuse to start while a PREVIOUS run's logind session or throwaway account survives.
#
# WHY THIS EXISTS, AND WHY IT LOOKS AT SESSIONS RATHER THAN PROCESSES
# -------------------------------------------------------------------
# Measured on the lane, and it cost three wrong diagnoses: after a P3a-2 daemon run a session
# `c523` owned by `delphi-r402-119101` survived **on tty1**, left by the earlier weaken. Every
# subsequent test then failed `VirtualTerminalAlreadyTaken` at `pam_open_session`. The failures
# were blamed first on a just-landed cleanup fix (0/30 immediately after it merged) and then on
# a PAM regression. Ground truth came from the journal, not from the checks.
#
# The cleanup that should have caught it looked for **processes on tty3**, because it had been
# written for the weaken's tty3 scenario. The survivor was a **session on tty1** — tty1 being
# the VT the tests actually use. Wrong resource, wrong VT.
#
# So this checks the resource the SUBJECT uses:
#   * SESSIONS, not processes — a session outlives its last process in `closing`, and it is the
#     session that holds the VT;
#   * ANY VT, not a hard-coded one — the tests use tty1, the weaken used tty3, and a future
#     scenario will use something else;
#   * accounts too, as a second signal: an account can outlive its session, and `userdel`
#     failing is how the last leak stayed invisible.
#
# Exit: 0 clean, 1 something survives.

set -uo pipefail

# Both throwaway-account spellings in the tree:
#   leader_is_shell.rs:136  format!("delphi-{tag}-{pid}")
#   b1_integration.rs:134   format!("db1{tag}{pid % 10000}")
PATTERN='^(delphi-|db1)'

stale_sessions=""
if command -v loginctl >/dev/null 2>&1; then
    # --no-legend columns: SESSION UID USER SEAT LEADER CLASS TTY IDLE SINCE
    stale_sessions=$(loginctl list-sessions --no-legend 2>/dev/null \
        | awk -v pat="$PATTERN" '$3 ~ pat {print}')
fi

stale_accounts=$(getent passwd 2>/dev/null | awk -F: -v pat="$PATTERN" '$1 ~ pat {print $1}')

if [ -z "$stale_sessions" ] && [ -z "$stale_accounts" ]; then
    echo "no stale test sessions or accounts"
    exit 0
fi

echo "STALE TEST STATE FROM A PREVIOUS RUN — this is a PRECONDITION failure."
echo "Left in place it presents as a CODE regression: every launch fails"
echo "VirtualTerminalAlreadyTaken at pam_open_session, on a VT nobody is looking at."
echo

if [ -n "$stale_sessions" ]; then
    n=$(printf '%s\n' "$stale_sessions" | wc -l)
    echo "  SESSIONS ($n) — these hold the VT, and they are the ones that break the next run:"
    printf '%s\n' "$stale_sessions" | sed 's/^/    /'
    echo
    echo "  Clear with:"
    printf '%s\n' "$stale_sessions" | awk '{print $3}' | sort -u \
        | sed 's/^/    sudo loginctl terminate-user /'
    echo
fi

if [ -n "$stale_accounts" ]; then
    n=$(printf '%s\n' "$stale_accounts" | wc -l)
    echo "  ACCOUNTS ($n) — lower priority: they consume uids and clutter, but only a"
    echo "  SESSION holds the VT. Showing the first 5:"
    printf '%s\n' "$stale_accounts" | head -5 | sed 's/^/    /'
    [ "$n" -gt 5 ] && echo "    … and $((n - 5)) more"
    echo
    echo "  Remove ALL of them with one command (review the list first):"
    echo "    getent passwd | awk -F: '\$1 ~ /^(delphi-|db1)/ {print \$1}' \\"
    echo "      | while read -r u; do sudo userdel -f \"\$u\"; done"
    echo
fi

echo "Re-run this check until it prints \"no stale test sessions or accounts\"."
exit 1
