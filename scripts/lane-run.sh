#!/bin/bash
# SPDX-License-Identifier: MIT
#
# The sanctioned way to run the root lane (D0A-R22-01).
#
# ── WHAT THIS REPLACES, AND WHY A SCRIPT WAS NEEDED ──────────────────────────────────────
#
# `.githooks/runtime-test-count-baseline.expected` was introduced by D0A-R21-07 after two
# consecutive lane runs had a correct figure and a wrong explanation. Its claimed proof was
# COMMIT ORDERING: expectation committed alone before the run, result committed alone after.
#
# D0A-R22-01 found that nothing consumed it. No hook, no runner, no CI job read the
# expectation before a run, so the ordering was a CONVENTION THE AUTHOR FOLLOWED rather than
# an invariant anything enforced — measure first, commit an expectation second, commit a
# matching result third, and the history is indistinguishable from the required sequence.
#
# This script converts that claim about the author's behaviour into facts a runner verifies:
# it reads the COMMITTED blob, refuses if the working copy differs, refuses if the expectation
# was committed together with a result, and binds tree + expectation blob + counts + captured
# times into one artifact.
#
# ── WHAT IT STILL CANNOT DO, STATED SO IT IS NOT THE NEXT OVERSTATED GUARANTEE ───────────
#
# It CANNOT stop someone amending the expectation and re-running. Nothing short of a job on a
# machine the author does not control can. What it does instead is RECORD THE EXPECTATION BLOB
# SHA in the artifact, so an amend-and-rerun is VISIBLE in review rather than impossible: the
# artifact names a blob the file no longer hashes to.
#
# Run UNPRIVILEGED. It sudo's for the test binaries only, for the reason the red-proof
# harness does: sudo's secure_path omits ~/.cargo/bin and $HOME becomes /root.

set -u -o pipefail

EXPECTED_FILE=".githooks/runtime-test-count-baseline.expected"
RESULT_FILE=".githooks/runtime-test-count-baseline.root"
ARTIFACT_DIR="${ARTIFACT_DIR:-scratch/lane-artifacts}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$HOME/delphi-target}"

die() { printf 'REFUSING: %s\n' "$*" >&2; exit 2; }
hr() { printf '%s\n' "------------------------------------------------------------"; }

[ -f "$EXPECTED_FILE" ] || die "run from the repo root (no $EXPECTED_FILE)"
[ "$(id -u)" -ne 0 ] || die "run UNPRIVILEGED — this sudo's for the test binaries only"
command -v cargo >/dev/null || die "cargo not on PATH"

# ── GATE 1: the expectation must be COMMITTED, and the working copy must match it ────────
# Without this the runner could read an expectation that exists only on disk — which is the
# post-hoc case the whole protocol exists to exclude.
git diff --quiet HEAD -- "$EXPECTED_FILE" \
    || die "$EXPECTED_FILE has uncommitted changes. The expectation must be COMMITTED before
  the run; an on-disk-only expectation is exactly the post-hoc case this refuses."

EXPECTED_BLOB="$(git rev-parse "HEAD:$EXPECTED_FILE" 2>/dev/null)" \
    || die "$EXPECTED_FILE is not tracked at HEAD"
DISK_BLOB="$(git hash-object "$EXPECTED_FILE")"
[ "$EXPECTED_BLOB" = "$DISK_BLOB" ] \
    || die "the working copy of $EXPECTED_FILE does not hash to its committed blob
  committed: $EXPECTED_BLOB
  on disk:   $DISK_BLOB"

# ── GATE 2: the expectation's commit must be IN HISTORY ──────────────────────────────────
EXPECT_COMMIT="$(git log -1 --format=%H -- "$EXPECTED_FILE")"
[ -n "$EXPECT_COMMIT" ] || die "no commit in history touches $EXPECTED_FILE"
git merge-base --is-ancestor "$EXPECT_COMMIT" HEAD \
    || die "the commit that last touched $EXPECTED_FILE ($EXPECT_COMMIT) is not an ancestor
  of HEAD — the expectation is not in this branch's history."

# ── GATE 3: the expectation must have been committed ALONE, not beside a result ──────────
# This is the mechanical form of protocol step 2/4. A commit carrying BOTH the prediction and
# a measurement proves nothing about which came first, and that is the exact shape the file's
# own protocol forbids in prose and nothing checked.
if git show --stat --format= --name-only "$EXPECT_COMMIT" | grep -qxF "$RESULT_FILE"; then
    die "the expectation's commit ($EXPECT_COMMIT) ALSO touches $RESULT_FILE.
  A prediction committed beside a measurement establishes no ordering between them."
fi

# ── The expectation's values ─────────────────────────────────────────────────────────────
EXP_EXEC="$(grep -E '^EXPECTED_EXECUTED=' "$EXPECTED_FILE" | tail -1 | cut -d= -f2)"
EXP_SKIP="$(grep -E '^EXPECTED_SKIPPED=' "$EXPECTED_FILE" | tail -1 | cut -d= -f2)"
[[ "$EXP_EXEC" =~ ^[0-9]+$ && "$EXP_SKIP" =~ ^[0-9]+$ ]] \
    || die "no numeric EXPECTED_EXECUTED / EXPECTED_SKIPPED in $EXPECTED_FILE
  (found EXECUTED='$EXP_EXEC' SKIPPED='$EXP_SKIP') — derive and commit one before running."

TREE="$(git rev-parse HEAD)"
DIRTY="$(git status --porcelain | wc -l)"
[ "$DIRTY" -eq 0 ] || die "the working tree has $DIRTY modified path(s). A lane result must
  name the tree it measured; an unclean tree cannot be named by a commit SHA."

hr
printf 'LANE RUN — gates passed\n'
printf '  tree             %s\n' "$TREE"
printf '  expectation blob %s\n' "$EXPECTED_BLOB"
printf '  expectation cmt  %s\n' "$EXPECT_COMMIT"
printf '  expecting        EXECUTED=%s SKIPPED=%s\n' "$EXP_EXEC" "$EXP_SKIP"
hr

# ── Build unprivileged, enumerate, run under sudo ────────────────────────────────────────
cargo test -p delphi-runtime --tests --no-run >/dev/null 2>&1 || die "build failed"
mapfile -t TARGETS < <(cargo test -p delphi-runtime --tests --no-run --message-format=json 2>/dev/null \
  | python3 -c 'import sys,json
for l in sys.stdin:
    try: m=json.loads(l)
    except Exception: continue
    if m.get("executable") and m.get("profile",{}).get("test"): print(m["executable"])' | sort -u)
N="${#TARGETS[@]}"
[ "$N" -gt 0 ] || die "enumerated no test targets"
printf 'enumerated %s targets\n' "$N"

LOG="$(mktemp)"; STATUS="$(mktemp)"
START_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
for b in "${TARGETS[@]}"; do
    echo "### $b" >> "$LOG"
    sudo "$b" --nocapture --test-threads=1 >> "$LOG" 2>&1
    printf '%s\t%s\n' "$?" "$b" >> "$STATUS"
done
END_UTC="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

PRODUCER_FAILS="$(awk -F'\t' '$1 != 0' "$STATUS" | wc -l)"

# ── Count through the extractor, gated ───────────────────────────────────────────────────
COUNT_OUT="$(DELPHI_TESTCOUNT_EXPECT_TARGETS="$N" DELPHI_TESTCOUNT_LOG="$LOG" \
    scripts/test-count.sh 2>&1)"; COUNT_RC=$?
OBS_EXEC="$(printf '%s' "$COUNT_OUT" | grep -oE 'EXECUTED [0-9]+' | grep -oE '[0-9]+' | head -1)"
OBS_SKIP="$(printf '%s' "$COUNT_OUT" | grep -oE 'SKIPPED [0-9]+' | grep -oE '[0-9]+' | head -1)"

# ── The artifact — written WHATEVER the outcome ──────────────────────────────────────────
# A mismatch that leaves no record is a mismatch that can be re-run away. The artifact is
# written before the exit status is decided, for that reason.
mkdir -p "$ARTIFACT_DIR"
ART="$ARTIFACT_DIR/lane-$(date -u +%Y%m%dT%H%M%SZ)-${TREE:0:7}.txt"
{
    printf 'tree=%s\n' "$TREE"
    printf 'expectation_file=%s\n' "$EXPECTED_FILE"
    printf 'expectation_blob=%s\n' "$EXPECTED_BLOB"
    printf 'expectation_commit=%s\n' "$EXPECT_COMMIT"
    printf 'expected_executed=%s\nexpected_skipped=%s\n' "$EXP_EXEC" "$EXP_SKIP"
    printf 'observed_executed=%s\nobserved_skipped=%s\n' "${OBS_EXEC:-none}" "${OBS_SKIP:-none}"
    printf 'targets_enumerated=%s\nproducer_failures=%s\n' "$N" "$PRODUCER_FAILS"
    printf 'extractor_rc=%s\n' "$COUNT_RC"
    printf 'started_utc=%s\nended_utc=%s\n' "$START_UTC" "$END_UTC"
    printf 'match=%s\n' \
      "$([ "${OBS_EXEC:-x}" = "$EXP_EXEC" ] && [ "${OBS_SKIP:-x}" = "$EXP_SKIP" ] && echo yes || echo NO)"
} > "$ART"
rm -f "$LOG" "$STATUS"

hr
cat "$ART"
hr
printf 'artifact: %s\n' "$ART"

RC=0
[ "$PRODUCER_FAILS" -eq 0 ] || { printf '%s producer(s) exited non-zero\n' "$PRODUCER_FAILS" >&2; RC=1; }
[ "$COUNT_RC" -eq 0 ] || { printf 'the extractor refused or found failures (rc=%s)\n' "$COUNT_RC" >&2; RC=1; }
if [ "${OBS_EXEC:-x}" != "$EXP_EXEC" ] || [ "${OBS_SKIP:-x}" != "$EXP_SKIP" ]; then
    printf 'MISMATCH: expected %s/%s, observed %s/%s.\n' \
        "$EXP_EXEC" "$EXP_SKIP" "${OBS_EXEC:-none}" "${OBS_SKIP:-none}" >&2
    printf 'This is a RESULT. Record which side was wrong — the derivation in %s is the\n' "$EXPECTED_FILE" >&2
    printf 'auditable half, so check it before adjusting anything.\n' >&2
    RC=1
fi
exit "$RC"
