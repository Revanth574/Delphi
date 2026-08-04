#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Refuse to start while a previous run's logind session still holds a VT.
#
#   scripts/check-stale-test-sessions.sh            # any VT — the go/no-go gate
#   scripts/check-stale-test-sessions.sh --vt tty1  # one VT — a per-test entry assertion
#
# KEYED ON WHAT OUR CODE WRITES, NOT ON WHAT WE HAPPEN TO NAME ACCOUNTS (D0-R6-01)
# --------------------------------------------------------------------------------
# The first version matched sessions by USERNAME PREFIX (`delphi-`, `db1`). Enumerating the
# tree found FIVE prefixes, not two — `db1*`, `dsmoke*`, `dpam*`, `delphi-*`, `de2e*` — so it
# reported clean against three of them, including the two whose accounts had leaked in bulk.
# The prefix set had grown three times without the matcher following, which is what a naming
# convention does: it is a thing someone must remember to extend.
#
# So the key is now (a) the PAM SERVICE our own code passes to `pam_start` — a property this
# project writes and controls — and (b) the target VT, which is the resource that actually
# breaks the next run. Neither depends on anyone remembering to add a prefix.
#
# WHY THERE IS A --vt MODE (D0-R6-11, the granularity fix)
# --------------------------------------------------------
# A once-before-the-run check cannot see mid-run leakage BY CONSTRUCTION, and running it more
# often at the same level does not help: mid-run session *creation* is normal — every
# `launch()` opens one — while mid-run *leakage* is the hazard. That is the 9-consecutive-
# failures shape: one test's teardown fails and every later test dies at `pam_open_session`
# with a message naming neither the cause nor the culprit.
#
# `--vt` is the per-test entry assertion. It turns an obscure `VirtualTerminalAlreadyTaken`
# deep in PAM into a named precondition failure at the point of entry, attributed to the
# PREVIOUS test rather than the current one. Same script either way: the last checker's
# failure was two callers with divergent assumptions, so there is one construction site.
#
# FAILS CLOSED (D0-R6-02). A missing or erroring `loginctl`, or output it cannot parse, is a
# REFUSAL — never "nothing found, looks clean".

set -uo pipefail

REFUSE() { echo "REFUSING to certify the environment: $*" >&2; exit 2; }

TARGET_VT=""
if [ "${1:-}" = "--vt" ]; then
    TARGET_VT="${2:-}"
    [ -n "$TARGET_VT" ] || REFUSE "--vt needs a VT name (e.g. tty1)"
fi

# The service name our PAM stack is installed as, and what `pam_start` is called with.
# Single source: installer/pam/delphi-runtime + the SERVICE consts in the test crates.
PAM_SERVICE="delphi-runtime"

command -v loginctl >/dev/null 2>&1 || REFUSE "loginctl not found — cannot determine whether a \
previous run's session still holds a VT. This is not 'clean'; it is 'unknown'."

sessions_raw=$(loginctl list-sessions --no-legend 2>&1)
if [ $? -ne 0 ]; then
    REFUSE "loginctl list-sessions failed: ${sessions_raw}"
fi

hits=""
while read -r sid _rest; do
    [ -n "$sid" ] || continue
    props=$(loginctl show-session "$sid" -p Service -p TTY -p Name -p State 2>&1)
    if [ $? -ne 0 ]; then
        # A session that vanished between listing and inspection is fine; anything else is not.
        printf '%s' "$props" | grep -qi 'not.*known\|No such' && continue
        REFUSE "loginctl show-session $sid failed: ${props}"
    fi
    svc=$(printf '%s\n' "$props" | sed -n 's/^Service=//p')
    tty=$(printf '%s\n' "$props" | sed -n 's/^TTY=//p')
    who=$(printf '%s\n' "$props" | sed -n 's/^Name=//p')
    state=$(printf '%s\n' "$props" | sed -n 's/^State=//p')
    # Parse must succeed. An empty Service on a real session means the format moved.
    [ -n "$svc$tty" ] || REFUSE "could not parse session $sid (Service/TTY both empty)"

    match=""
    [ "$svc" = "$PAM_SERVICE" ] && match="service=$svc"
    if [ -n "$TARGET_VT" ] && [ "$tty" = "$TARGET_VT" ]; then
        match="${match:+$match, }vt=$tty"
    fi
    [ -n "$match" ] && hits="${hits}${sid}|${who}|${tty}|${state}|${match}"$'\n'
done <<< "$sessions_raw"

if [ -z "$hits" ]; then
    if [ -n "$TARGET_VT" ]; then
        echo "no stale session on $TARGET_VT"
    else
        echo "no stale sessions opened by $PAM_SERVICE"
    fi
    exit 0
fi

echo "STALE SESSION FROM A PREVIOUS RUN — a PRECONDITION failure, not a code regression."
echo "Left in place, every launch fails VirtualTerminalAlreadyTaken at pam_open_session,"
echo "and the message names neither the cause nor the test that caused it."
echo
printf '  %-6s %-24s %-6s %-9s %s\n' SESSION USER TTY STATE MATCHED
printf '%s' "$hits" | while IFS='|' read -r sid who tty state match; do
    [ -n "$sid" ] || continue
    printf '  %-6s %-24s %-6s %-9s %s\n' "$sid" "$who" "$tty" "$state" "$match"
done
echo
echo "  Clear with:"
printf '%s' "$hits" | awk -F'|' 'NF{print "    sudo loginctl terminate-session " $1}'
echo "  If a session stays `closing`, reboot the lane."
exit 1
