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
gcc -O0 -o "$SP/resolve" runtime/tests/barrier/resolve.c -lsystemd \
  || { echo "REFUSING: resolve helper did not build"; exit 2; }

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

# ── ROOT SECTION: the ANSWER, not just the interval (D0A-R3-01) ──────────────────────────
#
# ROOT-GATED IS NOT LANE-ONLY, and the distinction is the point of this section. "Skips without
# sudo" and "needs a physical seated machine with a free VT" are different constraints; the
# ledger carried the second while the first was true. Codex settled it: a remote or seatless
# logind session suffices, and this box has one.
echo
echo "--- answer-discrimination (requires real root + a resolvable logind session) ---"
if [ "$(id -u)" != 0 ]; then
    echo "  SKIP: not root. This leg places processes into a session cgroup and writes the"
    echo "        global ns_last_pid; both need real uid 0 (a userns-mapped root cannot)."
    echo "        Re-run: sudo runtime/tests/pidfd-barrier.test.sh"
else
    # Find a session scope whose members actually resolve. Not "a scope exists" — a scope that
    # sd_pid_get_session answers for, since that is what the lookup will consult.
    SCOPE=""
    for d in /sys/fs/cgroup/user.slice/*/session-*.scope; do
        [ -r "$d/cgroup.procs" ] || continue
        m=$(head -1 "$d/cgroup.procs" 2>/dev/null)
        [ -n "$m" ] || continue
        got=$("$SP/resolve" "$m" 2>/dev/null)
        [ -n "$got" ] && { SCOPE="$d"; SESSION="$got"; break; }
    done
    if [ -z "$SCOPE" ]; then
        bad "a resolvable logind session exists" "none found — cannot discriminate the answer"
    else
        echo "  using $SCOPE (session $SESSION)"

        # (a) POSITIVE CONTROL: victim IN the session, NO barrier. The call must resolve it.
        #     Without this, "the barrier run returned no session" cannot be told apart from
        #     "nothing on this box ever resolves".
        COUT=$(DELPHI_VICTIM_JOIN_CGROUP="$SCOPE/cgroup.procs" \
               LD_PRELOAD="$SP/preload.so" "$SP/driver" 2>&1)
        printf '%s\n' "$COUT" | sed 's/^/    /'
        if printf '%s' "$COUT" | grep -q "^CALL RETURNED rc=0 session=$SESSION$"; then
            ok "control: a victim in the session RESOLVES (rc=0 session=$SESSION)"
        else
            bad "control: a victim in the session resolves" "it did not — the negative below would be meaningless"
        fi

        # (b) THE BARRIER RUN: victim sessionless; the IMPOSTOR is placed in the session, so
        #     the lookup takes the SUCCESSFUL path — the only one on which the delegated
        #     verification is claimed to run.
        BOUT=$(DELPHI_BARRIER_JOIN_CGROUP="$SCOPE/cgroup.procs" \
               LD_PRELOAD="$SP/preload.so" "$SP/driver" 2>&1)
        printf '%s\n' "$BOUT" | sed 's/^/    /'
        if printf '%s' "$BOUT" | grep -q '^BARRIER PLACED'; then
            ok "barrier: the impostor was placed in the session"
        else
            bad "barrier: the impostor was placed in the session" "placement failed — the successful path is not exercised"
        fi
        if printf '%s' "$BOUT" | grep -q "^CALL RETURNED rc=0 session=$SESSION$"; then
            bad "THE DELEGATION IS FALSIFIED" \
                "the call answered session=$SESSION for a pidfd whose process was reaped — that is the IMPOSTOR's session attributed to the victim's pidfd"
        else
            ok "barrier: the call did NOT answer with the impostor's session"
        fi

        # (c) SAME ROUTE: both runs must reach the lookup the same way, or the control proves
        #     less than it appears to. The OBSERVED line is logged regardless of matching.
        CR=$(printf '%s' "$COUT" | grep -c '^OBSERVED /proc/[0-9]*/cgroup$')
        BR=$(printf '%s' "$BOUT" | grep -c '^OBSERVED /proc/[0-9]*/cgroup$')
        if [ "$CR" -ge 1 ] && [ "$BR" -ge 1 ]; then
            ok "both runs reached the same lookup route (OBSERVED in each)"
        else
            bad "both runs reached the same lookup route" "control=$CR barrier=$BR observed lookups"
        fi

        # (d) WEAKEN: drop the impostor's placement. The lookup then returns ENODATA and (b)
        #     passes VACUOUSLY — so the control is what has to catch it.
        WB=$(LD_PRELOAD="$SP/preload.so" "$SP/driver" 2>&1)
        if printf '%s' "$WB" | grep -q '^BARRIER PLACED'; then
            bad "weaken: no placement means no PLACED line" "it placed anyway"
        else
            ok "weaken: without placement the run is vacuous — which is why (a) exists"
        fi
    fi
fi

echo
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ] && { echo "ALL PASS"; exit 0; }
echo "SUITE FAILED"; exit 1
