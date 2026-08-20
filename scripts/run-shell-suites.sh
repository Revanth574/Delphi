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
# DISCOVERED, NOT ENUMERATED (class 17): a list here would be the fourth copy of a list this
# repo has already let drift. Zero discoveries REFUSES — a runner that finds nothing must
# not report success.
#
# RESIDUAL, stated rather than left implicit: a suite that is DELETED is invisible to this —
# the discovered count is printed, not asserted against a baseline. The printed list is what
# makes a disappearance visible in a CI log or a diff.

set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

mapfile -t SUITES < <(find . -name '*.test.sh' -not -path './target/*' | sort)
if [ "${#SUITES[@]}" -eq 0 ]; then
    echo "REFUSING: found no *.test.sh — a discovery that finds nothing is not a pass." >&2
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
