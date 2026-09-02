#!/bin/bash
# SPDX-License-Identifier: MIT
#
# RED-proof for `scripts/lane-run.sh`'s GATES (D0A-R22-01). Tier 1 by clause (d): the
# script's exit status is the evidence that a lane result was bound to a prior expectation.
#
# Only the GATES are exercised — they all fire before any sudo, any cargo and any test run,
# so this is deterministic, unprivileged and offline. The lane itself is not run here; that
# is what the artifact is for.
set -uo pipefail
SCRIPT="$(cd "$(dirname "$0")" && pwd)/lane-run.sh"
fail=0
check() { # name want-rc want-substr got-rc got-out
    if [ "$4" = "$2" ] && [[ "$5" == *"$3"* ]]; then printf '  ok    %s\n' "$1"
    else printf '  FAIL  %s\n        want rc=%s containing %q\n        got  rc=%s: %s\n' \
        "$1" "$2" "$3" "$4" "${5//$'\n'/ | }"; fail=1; fi
}

WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
cd "$WORK" || exit 1
git init -q .; git config user.email t@t; git config user.name t
mkdir -p .githooks scripts
cp "$SCRIPT" scripts/lane-run.sh
printf 'EXPECTED_EXECUTED=10\nEXPECTED_SKIPPED=2\n' > .githooks/runtime-test-count-baseline.expected
printf 'EXECUTED=10\nSKIPPED=2\n' > .githooks/runtime-test-count-baseline.root
git add -A; git commit -qm "both files in ONE commit"

echo "lane-run.sh gate RED-proof"

# GATE 3 — a prediction committed beside a measurement establishes no ordering.
OUT=$(bash scripts/lane-run.sh 2>&1); RC=$?
check "expectation committed WITH a result is refused" 2 "ALSO touches" "$RC" "$OUT"

# Separate them: the result moves to its own later commit.
printf 'EXECUTED=11\nSKIPPED=2\n' > .githooks/runtime-test-count-baseline.root
git add .githooks/runtime-test-count-baseline.root; git commit -qm "result alone"

# GATE 1 — an on-disk-only expectation is the post-hoc case.
printf '\n# edited after committing\n' >> .githooks/runtime-test-count-baseline.expected
OUT=$(bash scripts/lane-run.sh 2>&1); RC=$?
check "uncommitted expectation is refused" 2 "uncommitted changes" "$RC" "$OUT"
git checkout -- .githooks/runtime-test-count-baseline.expected

# GATE 4 — an expectation with no numeric values is not an expectation.
printf 'EXPECTED_EXECUTED=\nEXPECTED_SKIPPED=\n' > .githooks/runtime-test-count-baseline.expected
git add -A; git commit -qm "blank expectation alone"
OUT=$(bash scripts/lane-run.sh 2>&1); RC=$?
check "blank expectation is refused" 2 "no numeric EXPECTED_EXECUTED" "$RC" "$OUT"

# GATE 5 — a dirty tree cannot be named by a commit SHA.
printf 'EXPECTED_EXECUTED=10\nEXPECTED_SKIPPED=2\n' > .githooks/runtime-test-count-baseline.expected
git add -A; git commit -qm "real expectation alone"
echo stray > stray.txt
OUT=$(bash scripts/lane-run.sh 2>&1); RC=$?
check "a dirty working tree is refused" 2 "modified path" "$RC" "$OUT"
rm -f stray.txt

# POSITIVE CONTROL — with every gate satisfied it must get PAST them. It then fails on the
# build (no cargo project here), which is the point: the gates are not refusing everything.
OUT=$(bash scripts/lane-run.sh 2>&1); RC=$?
check "gates PASS on a well-formed setup (fails later, at the build)" 2 "build failed" "$RC" "$OUT"

echo
if [ "$fail" -eq 0 ]; then echo "ALL PASS"; else echo "FAILURES ABOVE"; fi
exit "$fail"
