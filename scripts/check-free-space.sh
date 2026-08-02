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

target_dir="${CARGO_TARGET_DIR:-}"
if [ -z "$target_dir" ]; then
    # Mirror .cargo/config.toml's build.target-dir when the env var is unset, so the check
    # looks where cargo will actually write rather than where we assume it will.
    target_dir=$(grep -oE '^target-dir *= *"[^"]+"' .cargo/config.toml 2>/dev/null \
        | sed 's/.*"\(.*\)"/\1/' | head -1)
fi
[ -n "$target_dir" ] && FLOOR_MB["$target_dir"]=2048
[ -n "${TMPDIR:-}" ] && [ "${TMPDIR%/}" != "/tmp" ] && FLOOR_MB["${TMPDIR%/}"]=512

short=()
printf '%-42s %10s %10s  %s\n' "PATH" "FREE" "FLOOR" "STATUS"
for path in "${!FLOOR_MB[@]}"; do
    floor=${FLOOR_MB[$path]}
    if [ ! -e "$path" ]; then
        printf '%-42s %10s %10s  %s\n' "$path" "-" "${floor}M" "ABSENT (not checked)"
        continue
    fi
    free_mb=$(df -Pm "$path" 2>/dev/null | awk 'NR==2 {print $4}')
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
