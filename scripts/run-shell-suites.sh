#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Run every `*.test.sh` in the repo and fail if any of them does.
#
# WHY THIS EXISTS. The shell suites were run by NOTHING — not `cargo test`, not CI (which
# has no step for them), not the pre-commit hook (scoped to staged `runtime/` paths). Two of
# them were RED from cdc3418 onward — 15 further commits landed on top — after `delphi-drop`
# entered the installer without their fixtures, and one of those two is the tier-1 SOLE
# EVIDENCE for the tree-replace invariant (CLAUDE.md §6). Nobody noticed because nothing
# looked. This is the something that looks.
#
# DISCOVERED, AND CHECKED AGAINST A RECORDED MANIFEST (D0A-R11-03). Discovery alone refused
# only at ZERO, so deleting `tree-install.test.sh` while eight others survived stayed green —
# the exact disappearance this runner was built for, in the runner itself. The manifest is
# `scripts/shell-suites.manifest`, one path per line; a suite present-but-unlisted or
# listed-but-absent REFUSES. It is a list, which class 17 warns about — but a list whose
# drift is itself detected, which is the difference between a manifest and a copy.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

mapfile -t SUITES < <(find . -name '*.test.sh' -not -path './target/*' | sort)
if [ "${#SUITES[@]}" -eq 0 ]; then
    echo "REFUSING: found no *.test.sh — a discovery that finds nothing is not a pass." >&2
    exit 2
fi

MANIFEST="${DELPHI_SHELL_SUITES_MANIFEST:-scripts/shell-suites.manifest}"
if [ ! -r "$MANIFEST" ]; then
    echo "REFUSING: no manifest at $MANIFEST — a deleted suite would be invisible." >&2
    printf '%s\n' "${SUITES[@]}" | sed 's/^/  /' >&2
    exit 2
fi
expected=$(grep -vE '^\s*(#|$)' "$MANIFEST" | sort -u)
found=$(printf '%s\n' "${SUITES[@]}" | sort -u)
if [ "$expected" != "$found" ]; then
    echo "REFUSING: the discovered suites differ from $MANIFEST." >&2
    echo "  MISSING (listed, not found — deleted?):" >&2
    comm -23 <(printf '%s\n' "$expected") <(printf '%s\n' "$found") | sed 's/^/    /' >&2
    echo "  UNLISTED (found, not listed — add it):" >&2
    comm -13 <(printf '%s\n' "$expected") <(printf '%s\n' "$found") | sed 's/^/    /' >&2
    exit 2
fi

# External tools the suites invoke. Missing ones are reported UP FRONT, because the failure
# they cause otherwise surfaces as an unrelated assertion deep inside a suite.
missing=()
for tool in apparmor_parser unshare strace python3; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
[ "${#missing[@]}" -eq 0 ] || echo "NOTE: not on PATH: ${missing[*]} — suites needing them will FAIL, not skip."

printf 'running %d shell suite(s):\n' "${#SUITES[@]}"
failed=0
for t in "${SUITES[@]}"; do
    out=$(bash "$t" 2>&1); rc=$?
    tail_line=$(printf '%s\n' "$out" | grep -iE 'passed=|passed,|ALL PASS|FAILURES|SUITE FAILED' | tail -1)
    # D0A-R12-09, AS A CLASS: a suite that exits 0 having reported no result did not run its
    # subject, and "ok" for it is a green about nothing. tree-install did exactly that on CI
    # for every run. Requiring the summary line makes the same mistake in any other suite
    # loud, rather than closing only the instance.
    if [ "$rc" -eq 0 ] && [ -z "$tail_line" ]; then
        failed=$((failed + 1))
        printf '  FAIL  %-44s exited 0 but reported NO result — it did not run\n' "$t"
        printf '%s\n' "$out" | tail -10 | sed 's/^/        | /'
        continue
    fi
    if [ "$rc" -eq 0 ]; then
        printf '  ok    %-44s %s\n' "$t" "$tail_line"
    else
        failed=$((failed + 1))
        printf '  FAIL  %-44s rc=%s  %s\n' "$t" "$rc" "$tail_line"
        printf '%s\n' "$out" | tail -20 | sed 's/^/        | /'
    fi
done

echo
if [ "$failed" -eq 0 ]; then
    printf 'ALL %d SHELL SUITES PASS\n' "${#SUITES[@]}"
    exit 0
fi
printf '%d of %d SHELL SUITES FAILED\n' "$failed" "${#SUITES[@]}"
exit 1
