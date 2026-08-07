#!/bin/bash
# SPDX-License-Identifier: MIT
#
# D0A-R2-02 — does the barrier cross the interval it names?
#
# THE CLAIM UNDER TEST IS NOT "the delegation holds". It is that this harness suspends
# `sd_pidfd_get_session` AT THE ACTUAL FIRST PIDFD READ IT PERFORMS, and recycles the pid
# while the call is mid-flight. Three earlier proofs on this branch failed by sampling around
# the interval instead of across it (DEFECT_CLASSES 22), so "we crossed it" is the thing that
# has to be demonstrated before any answer read out of the call means anything.
#
# WHAT THIS CANNOT SETTLE HERE, and it is designed for rather than discovered:
# Codex bounded its own citation — the pidfd re-verification runs on every SUCCESSFUL
# session-returning path and is SKIPPED on error paths such as ENODATA. On a box where the
# victim is in no session, the lookup returns ENODATA before any verification, so the answer
# is identical whether the delegation holds or not. **The answer-discrimination is lane-only.**
# This harness is what makes that lane run mean something when it happens.
#
# Fails closed: an unbuildable shim, a missing namespace, or a barrier that never fires is a
# FAILURE, never a quiet pass.

set -uo pipefail
cd "$(dirname "$0")/../.."

SP="${TMPDIR:-/tmp}/delphi-barrier-$$"
mkdir -p "$SP"
trap 'rm -rf "$SP"' EXIT

pass=0; fail=0
ok()   { pass=$((pass+1)); printf '  %-56s PASS\n' "$1"; }
bad()  { fail=$((fail+1)); printf '  %-56s FAIL — %s\n' "$1" "$2"; }

echo "=== D0A-R2-02: the barrier crosses the interval ==="

command -v gcc >/dev/null 2>&1 || { echo "REFUSING: gcc absent — cannot build the shim"; exit 2; }
command -v unshare >/dev/null 2>&1 || { echo "REFUSING: unshare absent"; exit 2; }

gcc -shared -fPIC -O0 -o "$SP/preload.so" runtime/tests/barrier/preload.c -ldl \
  || { echo "REFUSING: shim did not build"; exit 2; }
gcc -O0 -o "$SP/driver" runtime/tests/barrier/driver.c -lsystemd \
  || { echo "REFUSING: driver did not build (libsystemd-dev absent?)"; exit 2; }

run_barrier() {  # run_barrier [suffix-override] -> transcript on stdout
    if [ $# -gt 0 ]; then
        unshare -Ur -p --fork --mount-proc \
            env LD_PRELOAD="$SP/preload.so" DELPHI_BARRIER_SUFFIX="$1" "$SP/driver" 2>&1
    else
        unshare -Ur -p --fork --mount-proc \
            env LD_PRELOAD="$SP/preload.so" "$SP/driver" 2>&1
    fi
}

echo "--- shipped configuration ---"
OUT=$(run_barrier)
printf '%s\n' "$OUT" | sed 's/^/    /'

# 1. The interposition reached the ACTUAL read this call performs.
if printf '%s' "$OUT" | grep -q '^BARRIER MATCHED /proc/[0-9]*/cgroup$'; then
    ok "barrier matched the victim's own cgroup read (fopen64)"
else
    bad "barrier matched the victim's own cgroup read (fopen64)" "no MATCHED line — the interposition never reached that read"
fi

# 2. The recycle happened, and put a LIVE process at the victim's pid.
VICTIM=$(printf '%s' "$OUT" | sed -n 's/^VICTIM \([0-9]*\)$/\1/p')
IMP=$(printf '%s' "$OUT" | sed -n 's/^BARRIER FIRED victim=[0-9]* impostor=\([0-9]*\)$/\1/p')
if [ -n "$VICTIM" ] && [ "$VICTIM" = "$IMP" ]; then
    ok "the impostor occupies the victim's pid ($VICTIM)"
else
    bad "the impostor occupies the victim's pid" "victim=${VICTIM:-?} impostor=${IMP:-none}"
fi
# NOT an assertion: "the pid is occupied" reads `yes` in the weaken too, because there the
# ORIGINAL victim was never killed. It cannot tell an impostor from a survivor, so it is
# recorded and the discriminating claim is left to the FIRED line's two pids.
echo "  [recorded] $(printf '%s' "$OUT" | grep '^PID .* OCCUPIED AFTER CALL' || echo 'no occupancy line')"

# 3. ORDERING: the barrier fired BETWEEN the call's start and its return. This is the leg the
#    three earlier proofs lacked — they observed before and after, never across.
ORDER=$(printf '%s\n' "$OUT" | grep -n 'CALL BEGIN\|BARRIER FIRED\|CALL RETURNED' | cut -d: -f1 | tr '\n' ' ')
set -- $ORDER
if [ $# -eq 3 ] && [ "$1" -lt "$2" ] && [ "$2" -lt "$3" ]; then
    ok "fired INSIDE the call (BEGIN < FIRED < RETURNED)"
else
    bad "fired INSIDE the call" "line order was '$ORDER' — not begin/fired/returned"
fi

# 4. The answer, recorded but NOT asserted as discrimination — see the header.
RC=$(printf '%s' "$OUT" | sed -n 's/^CALL RETURNED rc=\(-\?[0-9]*\).*/\1/p')
echo "  [recorded] sd_pidfd_get_session returned rc=$RC across the barrier."
echo "  [recorded] rc=-61 (ENODATA) is EXPECTED off-lane: no session exists, so the lookup"
echo "             returns before any verification and the answer cannot discriminate."

# 5. WEAKEN: aim the barrier at a path this call never opens. It must then NOT fire, and the
#    assertions above must fail — otherwise they were passing for some other reason.
echo
echo "--- weaken: barrier aimed at a path the call never opens ---"
WOUT=$(run_barrier /no-such-file)
if printf '%s' "$WOUT" | grep -q '^BARRIER FIRED'; then
    bad "weaken: barrier must NOT fire on a path never opened" "it fired anyway — the match is not doing the work"
else
    ok "weaken: barrier does not fire, so leg 1 is not vacuous"
fi
if printf '%s' "$WOUT" | grep -q '^BARRIER MATCHED'; then
    bad "weaken: no MATCHED line either" "it matched a path the call never opens"
else
    ok "weaken: no MATCHED line either, so leg 1 measures the path and not the preload"
fi

echo
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ] && { echo "ALL PASS"; exit 0; }
echo "SUITE FAILED"; exit 1
