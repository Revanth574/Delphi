#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Free-space precondition across EVERY filesystem this project writes to.
#
# WHY ALL FOUR, AND WHY IT NAMES THE SHORT ONE
# --------------------------------------------
# One session exhausted or nearly exhausted four different filesystems, and each failed
# differently and confusingly:
#   /run                 — 113 stale anchor dirs; cost an hour of misattribution.
#   /tmp (3.7G tmpfs)    — 80% full; protoc failed for want of scratch, and the failure
#                          presented as a BUILD error in an unrelated crate.
#   $CARGO_TARGET_DIR    — 9.6G, on a root filesystem at 80%.
#   $TMPDIR              — used as the workaround for /tmp, i.e. a fifth place to fill.
# A check that covers only one of them reports "fine" while the run dies on another, and the
# resulting error names the wrong subsystem — which is exactly what happened. So this reports
# EVERY path it checked with its free space, and names WHICH one is short rather than
# returning a bare pass/fail.
#
# Exit: 0 all clear, 1 at least one below its floor.

set -uo pipefail

# Per-path floors. They differ because the failures differ: /run holds small anchor dirs, /tmp
# holds protoc scratch and test bundles, a cargo target dir holds gigabytes of objects.
declare -A FLOOR_MB=( ["/run"]=64 ["/tmp"]=512 )

# D0A-R29-08: ASK CARGO WHERE IT WILL WRITE. This used to read $CARGO_TARGET_DIR and then
# fall back to grepping `.cargo/config.toml` for `target-dir` — a pin CLAUDE.md §6 records as
# REMOVED on 2026-08-15 because it was a machine-specific absolute path. So in the DEFAULT
# configuration (env var unset, no pin) the grep found nothing, no target filesystem was added,
# and this script checked only /run and /tmp and printed "All checked filesystems above their
# floors". Reproduced: it returned success while cargo's real target directory went unexamined.
#
# That is the worst shape available for this particular guard, because its whole purpose is to
# stop a full filesystem being MISATTRIBUTED to a compiler error in an unrelated crate. A guard
# that silently checks nothing does not merely fail to help — it supplies false assurance in
# exactly the situation it exists for. The free-space trend recorded across lane runs 15-17 was
# therefore measured by the lane procedure's own `export CARGO_TARGET_DIR`, not by this check;
# anyone building outside that procedure had no protection at all.
#
# `cargo metadata` resolves the env var, any config pin, and the built-in default, so it
# answers the question actually being asked.
target_dir="${CARGO_TARGET_DIR:-}"
if [ -z "$target_dir" ] && command -v cargo >/dev/null 2>&1; then
    target_dir=$(cargo metadata --format-version 1 --no-deps 2>/dev/null \
        | python3 -c 'import sys,json; print(json.load(sys.stdin).get("target_directory",""))' 2>/dev/null)
fi
if [ -z "$target_dir" ]; then
    # Last resort: cargo's documented default, relative to this repository. Better an assumed
    # path that gets checked than no target check at all — the failure this guard exists for
    # does not care why the path was not resolved.
    target_dir="$(cd "$(dirname "$0")/.." && pwd)/target"
    echo "NOTE: could not resolve cargo's target directory; assuming $target_dir" >&2
fi
[ -n "$target_dir" ] && FLOOR_MB["$target_dir"]=2048
[ -n "${TMPDIR:-}" ] && [ "${TMPDIR%/}" != "/tmp" ] && FLOOR_MB["${TMPDIR%/}"]=512

short=()
printf '%-42s %10s %10s  %s\n' "PATH" "FREE" "FLOOR" "STATUS"
for path in "${!FLOOR_MB[@]}"; do
    floor=${FLOOR_MB[$path]}
    # D0-R6-08: an output path that does not exist YET still lands on a filesystem. Treating
    # it as "not checked" reported success for the one path a run was about to fill. Walk up
    # to the nearest existing ancestor, which is the filesystem it will actually be created on.
    probe="$path"
    while [ ! -e "$probe" ] && [ "$probe" != "/" ]; do
        probe=$(dirname "$probe")
    done
    [ "$probe" = "$path" ] || printf '%-42s %10s %10s  %s\n' "$path" "-" "-" "absent → checking $probe"
    free_mb=$(df -Pm "$probe" 2>/dev/null | awk 'NR==2 {print $4}')
    if ! [[ "$free_mb" =~ ^[0-9]+$ ]]; then
        printf '%-42s %10s %10s  %s\n' "$path" "?" "${floor}M" "UNREADABLE — treating as SHORT"
        short+=("$path")
        continue
    fi
    if [ "$free_mb" -lt "$floor" ]; then
        printf '%-42s %9sM %9sM  %s\n' "$path" "$free_mb" "$floor" "*** SHORT ***"
        short+=("$path")
    else
        printf '%-42s %9sM %9sM  ok\n' "$path" "$free_mb" "$floor"
    fi
done

if [ ${#short[@]} -gt 0 ]; then
    echo
    echo "SHORT ON SPACE: ${short[*]}"
    echo "This is a PRECONDITION failure, not a build or test failure — a run started here will"
    echo "fail somewhere unrelated (protoc scratch, a bundle write, an object file) and name the"
    echo "wrong subsystem. Free space on the path(s) above before re-running."
    exit 1
fi
echo
echo "All checked filesystems above their floors."
