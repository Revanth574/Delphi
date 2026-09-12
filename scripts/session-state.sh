#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# The accumulated-session state a lane failure might depend on, captured identically at every
# point the procedure samples it (D0A-R36-09). One shape, three moments: BEFORE the lane, AT a
# producer failure, and AFTER the run. A single sample cannot show what ACCUMULATED — which is
# why the r4_03 investigation could eliminate five hypotheses and still be unable to test the
# one axis that differed.
#
# EVERY COMMAND'S STATUS IS REPORTED. `loginctl … | wc -l` returns 0 both when there are no
# sessions and when loginctl failed, and a zero that means "could not tell" is worse than no
# number at all.
echo "=== captured ==="; date -u +%Y-%m-%dT%H:%M:%SZ
echo "=== boot identity and uptime ==="
uptime -s 2>&1; uptime -p 2>&1
if [ -r /proc/sys/kernel/random/boot_id ]; then
    echo "boot_id: $(cat /proc/sys/kernel/random/boot_id)"
else
    echo "boot_id: UNREADABLE"
fi

echo "=== leftover test accounts ==="
if accounts=$(getent passwd 2>&1); then
    n=$(grep -cE '^(db1|delphi-)' <<<"$accounts" || true)
    echo "count: $n"
    grep -E '^(db1|delphi-)' <<<"$accounts" || echo "(none)"
else
    echo "count: UNKNOWN — getent failed: $accounts"
fi

echo "=== logind sessions ==="
if sessions=$(loginctl list-sessions --no-legend 2>&1); then
    if [ -z "${sessions// }" ]; then echo "count: 0"; else
        printf 'count: %s\n%s\n' "$(wc -l <<<"$sessions")" "$sessions"
    fi
else
    echo "count: UNKNOWN — loginctl failed (rc=$?): $sessions"
fi

echo "=== delphi-runtime PAM/session traces ==="
if [ -d /run/delphi ]; then ls -la /run/delphi 2>&1; else echo "/run/delphi: absent"; fi
