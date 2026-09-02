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

# POSITIVE CONTROL — with the repository-state gates satisfied it must get PAST them. It
# prints "gates passed" with the tree and blob, and then stops at the LAST gate, sudo, which
# no unprivileged offline test can satisfy. That is the point: the git/expectation gates are
# not refusing everything, and the control names exactly how far it got.
#
# It previously expected "build failed" — correct until GATE 6 (sudo priming) was added ahead
# of the build. The control was asserting the OLD last gate, so it broke the moment a new one
# landed in front of it. A positive control has to name the boundary it actually reaches.
OUT=$(bash scripts/lane-run.sh 2>&1); RC=$?
check "repository-state gates PASS on a well-formed setup" 2 "LANE RUN — gates passed" "$RC" "$OUT"
check "...and it stops at the LAST gate (sudo), not an earlier one" 2 "sudo is not usable" "$RC" "$OUT"

# ── THE SELF-BLOCK, which only a SECOND run can find ────────────────────────────────────
# The artifact used to be written to `scratch/lane-artifacts/` — untracked, un-ignored, and
# INSIDE the tree — so the first run dirtied the tree and the SECOND failed GATE 5. A
# single-run test of the gates could never see it. This asserts the default artifact
# directory is outside any repository, which is the property that makes the runner re-runnable
# AND the reason an artifact naming a tree must not live in it.
DEFAULT_DIR=$(grep -E '^ARTIFACT_DIR=' "$SCRIPT" | tail -1)
check "the default artifact dir is OUTSIDE the repo (self-block: only run TWO finds it)" \
      0 "" 0 "$DEFAULT_DIR"
case "$DEFAULT_DIR" in
    *scratch/*|*./*) printf '  FAIL  default artifact dir is inside the tree: %s\n' "$DEFAULT_DIR"; fail=1 ;;
    *XDG_STATE_HOME*|*HOME*) printf '  ok    default artifact dir resolves outside the repo\n' ;;
    *) printf '  FAIL  cannot tell where the default artifact dir points: %s\n' "$DEFAULT_DIR"; fail=1 ;;
esac

echo
if [ "$fail" -eq 0 ]; then echo "ALL PASS"; else echo "FAILURES ABOVE"; fi
exit "$fail"
