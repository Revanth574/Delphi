#!/bin/bash
# SPDX-License-Identifier: MIT
#
# D0A-R10-12 — measure the PRE-DROP WINDOW before designing its mitigation.
#
# The register (docs/CONFORMANCE_REGISTER.md, "OPENED 2026-08-16") accepts the window on a
# trade and records TWO things as unmeasured:
#   (1) its DURATION — "'the pre-drop window is short' is currently an intuition ... if
#       ancestor emission on a deep path makes it materially longer, the calculus shifts";
#   (2) WHICH capabilities each occupant holds, at each point.
# This probe answers both by measurement. It decides nothing (CLAUDE.md §6 tier 2, the
# `scratch/**` row) — it prints raw inputs alongside every derived number so a reader can
# redo the arithmetic rather than trust it.
#
# WHAT THE WINDOW IS: from bwrap's start to `setresuid` completing in `delphi-drop`.
# Measured as t_payload - t0, where t0 is taken immediately before the spawn and t_payload
# by the first thing that runs after the drop. That OVERESTIMATES (it includes the payload's
# own execve) — deliberately, because an overestimate is the safe direction for a window a
# security trade rests on.
#
# LEG STRUCTURE. The production profile has NO user namespace (D0A-R9-01 shape E), so it
# runs only as root. Unprivileged, bwrap needs `--unshare-user` — which is precisely the
# variable under study, so leg 1 is NOT the production configuration and is labelled as a
# SHAPE measurement (does depth matter, and by how much), never as the answer.
#
#   leg 1  timing sweep, --unshare-user       unprivileged   SHAPE ONLY
#   leg 2  timing sweep, production profile   root           THE ANSWER
#   leg 3  capability census at each point    root           THE ANSWER
#
# Every leg reports EXECUTED or SKIPPED with its reason. A SKIP PROVES NOTHING.

set -u -o pipefail

BWRAP="${BWRAP:-/usr/bin/bwrap}"
DROP_HELPER="${DROP_HELPER:-/usr/libexec/delphi-drop}"
REPS="${REPS:-20}"
# D0A-R17-02: RESOLVED, not assumed. These were hard-coded 997:997 while the installer's
# account is uid 997 / gid 972 — the group is `delphi-tool`, not a same-numbered group — so
# every leg dropped to a gid production never uses, and the validation regex checked Uid
# only, so the wrong gid passed silently. Resolve from the system; refuse if absent.
TOOL_ACCOUNT="${TOOL_ACCOUNT:-delphi-tool}"
TOOL_UID="${TOOL_UID:-$(getent passwd "$TOOL_ACCOUNT" 2>/dev/null | cut -d: -f3)}"
TOOL_GID="${TOOL_GID:-$(getent passwd "$TOOL_ACCOUNT" 2>/dev/null | cut -d: -f4)}"

EXECUTED=0
SKIPPED=0

if [ -z "$TOOL_UID" ] || [ -z "$TOOL_GID" ]; then
    echo "REFUSING: cannot resolve '$TOOL_ACCOUNT' — installer/install.sh creates it."
    echo "  Probing a guessed uid/gid measures a configuration production does not have,"
    echo "  which is how 997:997 stood in for the real 997:972 (D0A-R17-02)."
    exit 1
fi
if [ "$TOOL_UID" = "$TOOL_GID" ]; then
    echo "NOTE: $TOOL_ACCOUNT resolves to $TOOL_UID:$TOOL_GID — uid and gid coincide here."
    echo "  Both are still checked independently; this note exists so a reader does not"
    echo "  mistake the coincidence for the assumption D0A-R17-02 removed."
fi

hr() { printf '%s\n' "------------------------------------------------------------"; }

skip() { # skip <leg> <reason>
    printf 'LEG %s: SKIPPED — %s\n' "$1" "$2"
    SKIPPED=$((SKIPPED + 1))
}

# D0A-R16-07. The capability legs used to pipe bwrap straight into `sed`, so the pipeline's
# status was sed's and a bwrap that produced NOTHING printed an empty indented block that
# read as a successful measurement — while EXECUTED was incremented regardless. A leg that
# cannot produce its measurement is a FAILED leg, not a quiet one.
PROBE_FAILURES=0
probe_fail() { printf '    *** MEASUREMENT FAILED: %s\n' "$1"; PROBE_FAILURES=$((PROBE_FAILURES + 1)); }

# cap_read <label> <required-regexes, ';'-separated> <command...>
#
# ALL patterns must match. D0A-R17-02: a single pattern let the drop legs assert `Uid:` and
# say nothing about `Gid:`, so a drop to the wrong group read as a clean measurement. What
# is being observed is a credential PAIR, and the check has to be the same shape.
cap_read() {
    local label="$1" required="$2"; shift 2
    local out rc pat
    out="$("$@" 2>&1)"; rc=$?
    if [ "$rc" -ne 0 ]; then
        printf '    %s\n' "$out" | head -4
        probe_fail "$label — command exited $rc"
        return 1
    fi
    local IFS=';'
    for pat in $required; do
        [ -n "$pat" ] || continue
        if ! printf '%s' "$out" | grep -qE "$pat"; then
            printf '    %s\n' "${out:-（no output）}" | head -6
            probe_fail "$label — output lacks /$pat/, so there is nothing to read"
            return 1
        fi
    done
    printf '%s\n' "$out" | sed 's/^/    /'
    return 0
}

# ---------------------------------------------------------------------------
# The profile, transcribed from runtime/src/sandbox.rs SandboxProfile::derive.
# Ancestor emission (`--perms 0755 --dir <ancestor>`) is emitted BEFORE the binds and
# PARENT-FIRST, exactly as derive() does, because the depth of that emission is the
# variable the register singles out.
# ---------------------------------------------------------------------------

base_profile() { # base_profile <netpolicy:none|full>
    printf '%s\n' \
        --unshare-ipc --unshare-pid --unshare-uts --unshare-cgroup-try \
        --die-with-parent --new-session \
        --proc /proc --dev /dev
    if [ "$1" = "none" ]; then printf '%s\n' --unshare-net; else printf '%s\n' --share-net; fi
}

# System binds every realistic action needs: a dynamic tool cannot exec without its
# loader, so these are not padding — they are what "realistic" means.
system_binds() {
    printf '%s\n' --ro-bind /usr /usr --ro-bind /bin /bin
    [ -d /lib ]   && printf '%s\n' --ro-bind /lib /lib
    [ -d /lib64 ] && printf '%s\n' --ro-bind /lib64 /lib64
    return 0
}

# ancestors <path>... -> the DEDUPLICATED proper ancestors of every path, shallowest first.
#
# D0A-R16-06: this took one path and was called per bind, so N binds under a shared deep
# root emitted that root's chain N times. Production's `ancestor_dirs` collects into a
# BTreeSet, so it emits each ancestor ONCE — the probe was making bwrap do duplicate --dir
# work that production never does, inflating the per-bind slope it was measuring. It now
# takes all paths at once and dedupes, matching production's assembly.
ancestors() {
    local p acc comp
    for p in "$@"; do
        acc=""
        IFS='/' read -ra comps <<< "${p#/}"
        for comp in "${comps[@]}"; do
            [ -n "$comp" ] || continue
            acc="$acc/$comp"
            [ "$acc" = "$p" ] && break
            printf '%s\n' "$acc"
        done
    done | sort -u
}

now_ns() { date +%s%N; }

# ---------------------------------------------------------------------------
# One timed run. Prints the window in microseconds, or FAIL:<rc> with stderr.
# ---------------------------------------------------------------------------
timed_run() { # timed_run <userns:0|1> <n_binds> <depth> [--with-helper]
    local userns="$1" n_binds="$2" depth="$3" with_helper="${4:-}"
    local -a args=()
    local root dir i

    mapfile -t -O "${#args[@]}" args < <(base_profile none)
    [ "$userns" = "1" ] && args+=(--unshare-user)
    mapfile -t -O "${#args[@]}" args < <(system_binds)

    # A bind path of the requested DEPTH, under a real writable root, so ancestor
    # emission has genuine work to do.
    root="$(mktemp -d)"
    dir="$root"
    for ((i = 0; i < depth; i++)); do dir="$dir/d$i"; done
    mkdir -p "$dir"

    local -a bind_paths=()
    for ((i = 0; i < n_binds; i++)); do
        mkdir -p "$dir/b$i"
        bind_paths+=("$dir/b$i")
    done
    # Ancestors ONCE for the whole bind set, deduplicated, before the binds — as
    # `ancestor_dirs` + `derive` do (D0A-R16-06).
    while read -r a; do args+=(--perms 0755 --dir "$a"); done < <(ancestors "${bind_paths[@]}")
    for p in "${bind_paths[@]}"; do args+=(--bind "$p" "$p"); done

    args+=(--chdir /)

    local t0 t1 out rc
    if [ -n "$with_helper" ]; then
        # D0A-R16-05: the helper path is what SHIPS, and what ships now carries the
        # capability restriction. Timing it without the flags measured the pre-mitigation
        # path and reported the number as the mitigated window's.
        args+=(--cap-drop ALL --cap-add CAP_SETUID --cap-add CAP_SETGID)
        t0="$(now_ns)"
        out="$("$BWRAP" "${args[@]}" -- "$DROP_HELPER" "$TOOL_UID" "$TOOL_GID" - \
              /bin/sh sh -c 'date +%s%N' 2>&1)"; rc=$?
    else
        t0="$(now_ns)"
        out="$("$BWRAP" "${args[@]}" -- /bin/sh -c 'date +%s%N' 2>&1)"; rc=$?
    fi
    rm -rf "$root"

    if [ "$rc" -ne 0 ]; then printf 'FAIL:%s %s\n' "$rc" "$(printf '%s' "$out" | tr '\n' ' ')"; return 1; fi
    t1="$(printf '%s' "$out" | tail -1 | tr -dc '0-9')"
    if [ -z "$t1" ]; then printf 'FAIL:noclock %s\n' "$(printf '%s' "$out" | tr '\n' ' ')"; return 1; fi
    printf '%s\n' $(( (t1 - t0) / 1000 ))
}

# THE BASELINE, and why the probe is wrong without it. The timed run measures
# t_payload - t0, so it includes the payload's OWN exec chain (`/bin/sh` then `date`).
# On this box that chain alone is ~21 ms — the same order as the whole measurement — so
# a raw window number is mostly payload cost misattributed to bwrap. Every sweep prints
# this row first, and the bwrap-attributable cost is the DIFFERENCE. Subtracting by hand
# in a report is the arithmetic-by-subtraction shape this project has already been burned
# by; the instrument does it or it is not done.
baseline() {
    local -a samples=()
    local r t0 t1
    for ((r = 0; r < REPS; r++)); do
        t0="$(now_ns)"; t1="$(/bin/sh -c 'date +%s%N')"
        samples+=( $(( (t1 - t0) / 1000 )) )
    done
    mapfile -t sorted < <(printf '%s\n' "${samples[@]}" | sort -n)
    local cnt=${#sorted[@]}
    BASELINE_MED="${sorted[$((cnt / 2))]}"
    printf '%-8s %-7s %-10s %-10s %-10s %-12s %s\n' \
        "(none)" "-" "${sorted[0]}" "${sorted[$((cnt / 2))]}" "${sorted[$((cnt - 1))]}" "-" "$cnt"
}

sweep() { # sweep <userns> <label> [--with-helper]
    local userns="$1" label="$2" helper="${3:-}"
    printf '\n%s\n' "$label"
    printf '%-8s %-7s %-10s %-10s %-10s %-12s %s\n' \
        binds depth min_us med_us max_us med-baseline n
    BASELINE_MED=""
    baseline
    local n_binds depth
    for spec in "1 1" "1 4" "1 8" "4 4" "8 4" "8 8"; do
        read -r n_binds depth <<< "$spec"
        local -a samples=()
        local r fails=0
        for ((r = 0; r < REPS; r++)); do
            local v; v="$(timed_run "$userns" "$n_binds" "$depth" $helper)"
            if [[ "$v" == FAIL:* ]]; then
                fails=$((fails + 1))
                [ "$fails" -le 1 ] && printf '%-8s %-7s  %s\n' "$n_binds" "$depth" "$v"
                continue
            fi
            samples+=("$v")
        done
        if [ "${#samples[@]}" -eq 0 ]; then
            printf '%-8s %-7s  (no successful runs)\n' "$n_binds" "$depth"
            probe_fail "sweep cell binds=$n_binds depth=$depth produced no measurement"
            continue
        fi
        mapfile -t sorted < <(printf '%s\n' "${samples[@]}" | sort -n)
        local cnt=${#sorted[@]}
        # D0A-R17-04: BASELINE_MED was computed and never read, so the payload's own exec
        # chain stayed folded into every reported number. Subtract it here — that difference
        # is the only bwrap-attributable figure this probe produces.
        local med="${sorted[$((cnt / 2))]}" attributable="-"
        [ -n "${BASELINE_MED:-}" ] && attributable=$(( med - BASELINE_MED ))
        printf '%-8s %-7s %-10s %-10s %-10s %-12s %s\n' \
            "$n_binds" "$depth" "${sorted[0]}" "$med" "${sorted[$((cnt - 1))]}" "$attributable" "$cnt"
    done
}

# ---------------------------------------------------------------------------
hr; printf 'D0A-R10-12 PRE-DROP WINDOW PROBE\n'; hr
printf 'uid            : %s\n' "$(id -u)"
printf 'bwrap          : %s\n' "$(ls -l "$BWRAP" 2>/dev/null || echo MISSING)"
printf 'bwrap file caps: %s\n' "$(getcap "$BWRAP" 2>/dev/null || echo '(none)')"
printf 'drop helper    : %s\n' "$(ls -l "$DROP_HELPER" 2>/dev/null || echo MISSING)"
printf 'reps per cell  : %s\n' "$REPS"

# --- LEG 1 : unprivileged shape sweep ---------------------------------------
hr
if [ ! -x "$BWRAP" ]; then
    skip 1 "bwrap not executable at $BWRAP"
elif ! "$BWRAP" --unshare-user --ro-bind /usr /usr --ro-bind /bin /bin --bind /lib /lib \
        --bind /lib64 /lib64 -- /bin/true >/dev/null 2>&1; then
    skip 1 "unprivileged bwrap with --unshare-user does not run here"
else
    printf 'LEG 1: EXECUTED — unprivileged, --unshare-user ADDED.\n'
    printf '  NOT the production profile. Shape only: does bind count/depth move the number?\n'
    sweep 1 "  [leg 1] bwrap setup only, no helper (userns)"
    EXECUTED=$((EXECUTED + 1))
fi

# --- LEG 2 : production profile, root ---------------------------------------
hr
if [ "$(id -u)" -ne 0 ]; then
    skip 2 "needs root — the production profile has no user namespace (shape E)"
elif [ ! -x "$DROP_HELPER" ]; then
    skip 2 "drop helper missing at $DROP_HELPER"
else
    printf 'LEG 2: EXECUTED — production profile (no userns), root.\n'
    sweep 0 "  [leg 2a] bwrap setup only, no helper"
    sweep 0 "  [leg 2b] bwrap + real delphi-drop interposed" --with-helper
    printf '\n  WINDOW = leg 2b. HELPER SHARE = 2b - 2a.\n'
    EXECUTED=$((EXECUTED + 1))
fi

# --- LEG 3 : capability census ----------------------------------------------
hr
if [ "$(id -u)" -ne 0 ]; then
    skip 3 "needs root — the census is of a root-spawned window"
else
    printf 'LEG 3: EXECUTED — capability census across the window.\n'
    printf '\n  [point 0] the spawning parent (stands for delphi-runtimed)\n'
    grep -E '^(Uid|Gid|CapInh|CapPrm|CapEff|CapBnd|CapAmb):' /proc/self/status | sed 's/^/    /'

    printf '\n  [point 1] bwrap ITSELF, sampled while its payload is alive\n'
    # CORRECTED. The first version sampled `coproc BW { ... }`, whose $BW_PID is the BASH
    # SUBSHELL, not bwrap — and as root a root bash holds the identical full set, so the
    # output could not tell the two apart. PASS/PASS (Iron Law #15 clause 2): the same
    # reading whether the property holds or not. A backgrounded SIMPLE command execs bwrap
    # in the forked child, so $! is bwrap; and the sample now PRINTS `comm`, so the reading
    # identifies its own subject instead of asking the reader to assume it.
    "$BWRAP" $(base_profile none | tr '\n' ' ') $(system_binds | tr '\n' ' ') \
        --chdir / -- /bin/sh -c 'sleep 2' &
    bw=$!   # NOT `local` — leg 3 runs at script top level, where `local` is an error and
            # `set -u` then kills the script on the unbound variable. The unprivileged
            # smoke run SKIPPED this leg, so the bug was invisible to the check that ran.
    sleep 0.3
    if [ -r "/proc/$bw/status" ]; then
        printf '    comm = %s\n' "$(cat "/proc/$bw/comm" 2>&1)"
        grep -E '^(Uid|Gid|CapInh|CapPrm|CapEff|CapBnd|CapAmb):' "/proc/$bw/status" | sed 's/^/    /'
        printf '    NOTE: sampled AFTER setup completed (payload alive). This shows what bwrap\n'
        printf '          RETAINS for the tool lifetime, NOT what it needed during setup.\n'
    else
        printf '    (bwrap exited before sampling — no reading)\n'
    fi
    wait "$bw" 2>/dev/null

    printf '\n  [point 2] bwrap PAYLOAD, pre-drop (where delphi-drop starts)\n'
    cap_read "point 2 (pre-drop payload)" '^CapPrm:' \
        "$BWRAP" $(base_profile none | tr '\n' ' ') $(system_binds | tr '\n' ' ') --chdir / \
        -- /bin/sh -c 'grep -E "^(Uid|Gid|Groups|CapInh|CapPrm|CapEff|CapBnd|CapAmb):" /proc/self/status'

    printf '\n  [point 3] the TOOL, post-drop through the real delphi-drop\n'
    cap_read "point 3 (tool, post-drop)" \
        "^Uid:[[:space:]]+$TOOL_UID\b;^Gid:[[:space:]]+$TOOL_GID\b" \
        "$BWRAP" $(base_profile none | tr '\n' ' ') $(system_binds | tr '\n' ' ') --chdir / \
        -- "$DROP_HELPER" "$TOOL_UID" "$TOOL_GID" - \
        /bin/sh sh -c 'grep -E "^(Uid|Gid|Groups|CapInh|CapPrm|CapEff|CapBnd|CapAmb):" /proc/self/status'
    EXECUTED=$((EXECUTED + 1))
fi

# --- LEG 4 : is "restrict the helper" implementable at all? ------------------
# R10-12 names the mitigation as "restrict the helper payload to the minimal
# CAP_SETUID/CAP_SETGID set". Which SET you restrict is not a detail: on execve by a
# process with euid 0 and a file carrying no file capabilities, the kernel treats the
# file's permitted set as all-ones, so P'(permitted) = F(permitted) & P(bounding) =
# P(bounding). If that holds, lowering CapPrm/CapEff before the exec is UNDONE by the
# exec, and only the BOUNDING set restricts anything. Measured here rather than asserted,
# because it decides the mitigation's whole shape.
hr
if [ "$(id -u)" -ne 0 ]; then
    skip 4 "needs root — dropping bounding capabilities requires CAP_SETPCAP"
elif ! command -v capsh >/dev/null 2>&1; then
    skip 4 "capsh not available"
else
    printf 'LEG 4: EXECUTED — capability transformation across a root execve.\n'
    CAPSH="$(command -v capsh)"
    show='grep -E "^Cap(Prm|Eff|Bnd):" /proc/self/status'

    printf '\n  [4a] baseline: root exec, nothing restricted\n'
    cap_read "4a (baseline root exec)" '^CapPrm:' /bin/sh -c "$show"

    printf '\n  [4b] CapPrm/CapEff lowered to setuid+setgid, BOUNDING left intact\n'
    printf '       If permitted comes back full, lowering p/e alone buys NOTHING.\n'
    cap_read "4b (p/e lowered, bounding intact)" '^CapPrm:' \
        "$CAPSH" --caps="cap_setuid,cap_setgid=eip" -- -c "$show"

    # Everything the bounding set currently holds, minus the two the helper needs.
    drop_list="$("$CAPSH" --print 2>/dev/null | sed -n 's/^Bounding set =//p' | tr ',' '\n' \
        | grep -vxE 'cap_setuid|cap_setgid' | paste -sd, -)"
    printf '\n  [4c] BOUNDING dropped to setuid+setgid only, then exec\n'
    cap_read "4c (bounding dropped)" '^CapPrm:' "$CAPSH" --drop="$drop_list" -- -c "$show"

    # RELABELLED after its first run. This drops the bounding set in the DAEMON, before
    # bwrap — the "restrict bwrap" variant, NOT the "restrict the helper" mitigation R10-12
    # names. The distinction was in the original framing of this work and my first version
    # of this leg collapsed it. The result is kept because the falsification is a real one:
    # it establishes that the restriction CANNOT be applied daemon-side.
    printf '\n  [4d] the DAEMON-SIDE variant: bounding dropped BEFORE bwrap\n'
    printf '       Expected to FAIL — bwrap needs CAP_SYS_ADMIN to build its namespaces.\n'
    if [ -x "$DROP_HELPER" ]; then
        "$CAPSH" --drop="$drop_list" -- -c \
            "$BWRAP $(base_profile none | tr '\n' ' ') $(system_binds | tr '\n' ' ') --chdir / \
             -- $DROP_HELPER $TOOL_UID $TOOL_GID - /bin/sh sh -c \
             'grep -E \"^(Uid|Gid|CapPrm|CapEff|CapBnd):\" /proc/self/status'" 2>&1 | sed 's/^/    /'
    else
        printf '    (drop helper missing — leg 4d not run)\n'
    fi
    EXECUTED=$((EXECUTED + 1))
fi

# --- LEG 5 : the PAYLOAD-SIDE variant, which is the one R10-12 names ---------
# Leg 4d falsified the daemon-side drop. The restriction has to land AFTER bwrap's setup
# and BEFORE the helper — and bwrap 0.11.1 has exactly that seam: `--cap-drop`/`--cap-add`,
# documented as applying "when running as privileged user". Measured unprivileged (userns)
# to give CapPrm/CapEff/CapBnd = 00000000000000c0, i.e. CAP_SETGID(6)+CAP_SETUID(7) and
# nothing else. This leg confirms it on the ROOT path that actually ships, and — 5b — that
# the real helper still drops under it.
hr
if [ "$(id -u)" -ne 0 ]; then
    skip 5 "needs root — this is the privileged bwrap path"
else
    printf 'LEG 5: EXECUTED — the payload-side restriction (bwrap --cap-drop/--cap-add).\n'
    CAPFLAGS="--cap-drop ALL --cap-add CAP_SETUID --cap-add CAP_SETGID"

    printf '\n  [5a] pre-drop payload under the restriction (expect 00000000000000c0)\n'
    cap_read "5a (restricted pre-drop payload)" '^CapPrm:' \
        "$BWRAP" $(base_profile none | tr '\n' ' ') $(system_binds | tr '\n' ' ') $CAPFLAGS --chdir / \
        -- /bin/sh -c 'grep -E "^(Uid|CapPrm|CapEff|CapBnd):" /proc/self/status'

    printf '\n  [5b] FEASIBILITY: the real delphi-drop under the restriction\n'
    printf '       Does it still drop, and does the TOOL inherit the narrowed bounding set?\n'
    if [ -x "$DROP_HELPER" ]; then
        cap_read "5b (tool under the restriction)" \
            "^Uid:[[:space:]]+$TOOL_UID\b;^Gid:[[:space:]]+$TOOL_GID\b" \
            "$BWRAP" $(base_profile none | tr '\n' ' ') $(system_binds | tr '\n' ' ') $CAPFLAGS --chdir / \
            -- "$DROP_HELPER" "$TOOL_UID" "$TOOL_GID" - \
            /bin/sh sh -c 'grep -E "^(Uid|Gid|Groups|CapPrm|CapEff|CapBnd):" /proc/self/status'
        printf '\n       Point 3 without the restriction had CapBnd 000001ffffffffff.\n'
        printf '       If CapBnd is 00000000000000c0 here, ONE change closes both.\n'
    else
        printf '    (drop helper missing — leg 5b not run)\n'
    fi
    EXECUTED=$((EXECUTED + 1))
fi

# --- LEG 6 : does the leg-5 restriction actually BITE? -----------------------
# 5a measured CapPrm/CapEff = c0 at the pre-drop payload WITH CapBnd still full. That is in
# tension with 4b, where a root execve restored p/e from the bounding set. Something is
# suppressing the root-exec rule — most likely SECBIT_NOROOT. It matters completely: if the
# rule is NOT suppressed, the helper holds c0 and can recover the full set by exec'ing any
# root-owned binary, and the restriction is COSMETIC.
#
# 6b is the discriminating leg. A restriction that reads as a restriction and does not bite
# is the failure this branch keeps finding; measuring the securebits alone would not settle
# it, so the probe performs the recovery instead of inferring it.
hr
if [ "$(id -u)" -ne 0 ]; then
    skip 6 "needs root — the privileged bwrap path"
else
    printf 'LEG 6: EXECUTED — does the leg-5 restriction bite?\n'
    CAPFLAGS="--cap-drop ALL --cap-add CAP_SETUID --cap-add CAP_SETGID"

    printf '\n  [6a] securebits at the restricted pre-drop payload\n'
    "$BWRAP" $(base_profile none | tr '\n' ' ') $(system_binds | tr '\n' ' ') $CAPFLAGS --chdir / \
        -- /usr/sbin/capsh --print 2>&1 | grep -iE 'secure|current:|bounding' | sed 's/^/    /'

    tmp6b="$(mktemp)"; tmp6c="$(mktemp)"
    printf '\n  [6b] THE BITE TEST: exec a further root binary under the restriction\n'
    printf '       If CapPrm returns to 000001ffffffffff, the c0 is cosmetic.\n'
    "$BWRAP" $(base_profile none | tr '\n' ' ') $(system_binds | tr '\n' ' ') $CAPFLAGS --chdir / \
        -- /bin/sh -c 'echo "  [before further exec]"; grep -E "^Cap(Prm|Eff|Bnd):" /proc/self/status; echo "  [after further exec]"; exec /bin/sh -c "grep -E \"^Cap(Prm|Eff|Bnd):\" /proc/self/status"' \
        > "$tmp6b" 2>&1 || probe_fail "6b — bwrap exited non-zero"
    grep -qE '^CapPrm:' "$tmp6b" || probe_fail "6b — no CapPrm line; nothing to read"
    sed 's/^/    /' "$tmp6b"; rm -f "$tmp6b"

    printf '\n  [6c] CONTROL: the same further exec WITHOUT the restriction\n'
    printf '       Both legs must not read alike, or 6b discriminates nothing.\n'
    "$BWRAP" $(base_profile none | tr '\n' ' ') $(system_binds | tr '\n' ' ') --chdir / \
        -- /bin/sh -c 'exec /bin/sh -c "grep -E \"^Cap(Prm|Eff|Bnd):\" /proc/self/status"' \
        > "$tmp6c" 2>&1 || probe_fail "6c — bwrap exited non-zero"
    grep -qE '^CapPrm:' "$tmp6c" || probe_fail "6c — no CapPrm line; the CONTROL is absent"
    sed 's/^/    /' "$tmp6c"; rm -f "$tmp6c"
    EXECUTED=$((EXECUTED + 1))
fi

# --- LEG 7 : is the --cap-add set MINIMAL? -----------------------------------
# 5b showed the helper drops correctly with exactly CAP_SETUID+CAP_SETGID. That is
# SUFFICIENCY. It says nothing about NECESSITY: a set containing a capability the helper
# does not need would pass 5b identically. Minimality is the claim that removing EITHER
# one breaks the drop, and nothing had tested it — so it was an assertion, not a result.
#
# `delphi-drop` calls setgroups -> setresgid -> setresuid. setgroups/setresgid need
# CAP_SETGID; setresuid needs CAP_SETUID. Each variant below must FAIL. A variant that
# SUCCEEDS proves that capability was never required, and the set should shrink.
hr
if [ "$(id -u)" -ne 0 ]; then
    skip 7 "needs root — the privileged bwrap path"
elif [ ! -x "$DROP_HELPER" ]; then
    skip 7 "drop helper missing at $DROP_HELPER"
else
    printf 'LEG 7: EXECUTED — minimality of the --cap-add set.\n'
    printf '  Each variant MUST fail. A success means that capability is not needed.\n\n'
    printf '  %-34s %-8s %s\n' variant verdict detail
    minimal=yes
    while IFS='|' read -r label flags; do
        [ -n "$label" ] || continue
        out="$("$BWRAP" $(base_profile none | tr '\n' ' ') $(system_binds | tr '\n' ' ') \
            --cap-drop ALL $flags --chdir / \
            -- "$DROP_HELPER" "$TOOL_UID" "$TOOL_GID" - /bin/sh sh -c 'echo DROPPED-OK' 2>&1)"
        rc=$?
        if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q 'DROPPED-OK'; then
            printf '  %-34s %-8s %s\n' "$label" "SUCCESS" "*** NOT MINIMAL — this cap is unnecessary ***"
            minimal=no
        else
            printf '  %-34s %-8s rc=%s %s\n' "$label" "failed" "$rc" \
                "$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-46)"
        fi
    done <<EOF
only CAP_SETUID (no SETGID)|--cap-add CAP_SETUID
only CAP_SETGID (no SETUID)|--cap-add CAP_SETGID
neither (control)|
EOF
    printf '\n  Positive control — BOTH caps, must SUCCEED:\n'
    out="$("$BWRAP" $(base_profile none | tr '\n' ' ') $(system_binds | tr '\n' ' ') \
        --cap-drop ALL --cap-add CAP_SETUID --cap-add CAP_SETGID --chdir / \
        -- "$DROP_HELPER" "$TOOL_UID" "$TOOL_GID" - /bin/sh sh -c 'echo DROPPED-OK' 2>&1)"
    if printf '%s' "$out" | grep -q 'DROPPED-OK'; then
        printf '  both caps                          SUCCESS  (control holds)\n'
    else
        printf '  both caps                          FAILED   *** control broken: %s ***\n' \
            "$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-40)"
        minimal=unknown
    fi
    printf '\n  MINIMALITY VERDICT: %s\n' "$minimal"
    # D0A-R17-03: a verdict of anything but `yes` is a measurement that did not come out,
    # and it was reaching the summary without touching the exit status.
    [ "$minimal" = "yes" ] || probe_fail "minimality verdict is '$minimal', not 'yes'"
    EXECUTED=$((EXECUTED + 1))
fi

hr
printf 'LEGS EXECUTED %s / SKIPPED %s / MEASUREMENTS FAILED %s\n' \
    "$EXECUTED" "$SKIPPED" "$PROBE_FAILURES"
printf 'A SKIPPED LEG PROVES NOTHING. Leg 1 alone cannot answer the duration question:\n'
printf 'it measures a DIFFERENT namespace configuration from the one that ships.\n'
# D0A-R16-07: a leg that could not produce its measurement must not exit 0. EXECUTED counts
# legs that RAN, which is not the same as legs that MEASURED.
if [ "$PROBE_FAILURES" -gt 0 ]; then
    printf 'EXITING NON-ZERO — %s measurement(s) absent or failed.\n' "$PROBE_FAILURES"
    hr
    exit 1
fi
hr
