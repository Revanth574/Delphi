#!/bin/bash
# D0-A — WHICH GREENS BITE? A mutation audit, REBUILT after D0A-R11-01.
#
# THE FIRST VERSION HAD NO BASELINE, AND THAT IS FATAL, NOT COSMETIC. It declared a mutant
# "caught" whenever any test in four hard-coded namespaces failed, minus two names it knew.
# In a sandbox where two bwrap tests fail AMBIENTLY (`loopback: Failed RTM_NEWADDR`), that
# condition is true for every mutant including the null one, so the reviewer's run reported
# 12/12 caught — including `tool_credentials() -> None`, which catches nothing. It erred the
# other way too: a mutant that failed to COMPILE, or that broke a test outside those four
# namespaces, read as NOT CAUGHT. And its EXIT trap copied the originals to /dev/null, so an
# interrupt left the working tree mutated.
#
# WHAT MAKES A VERDICT MEANINGFUL HERE, and each of these is a rule the old one broke:
#
#   * A BASELINE, measured before any mutation: cargo's status, the result-line count, the
#     executed/skipped pair, and the FULLY-QUALIFIED set of failing tests. "Caught" is then
#     `mutant_failures \ baseline_failures != {}` — ambient failures cancel by construction.
#   * COMPILATION FAILURE IS CAUGHT. A mutation the type system rejects is a defect the
#     toolchain refuses; scoring it NOT CAUGHT understates the suite.
#   * NO VERDICT ON UNEXPLAINED STATE. A changed result-line count, a vanished baseline
#     failure, or a changed executed count means the run is not comparable to the baseline.
#     Say so and exit non-zero — an unexplained run must not average into a percentage.
#   * `--lib --bins`. The old one ran `--lib`, so every mutation in `delphi-runtimed.rs`
#     (the login.defs grammar, the account guards) was invisible to it.
#   * AN ISOLATED WORKTREE. The live tree is never written to, so an interrupt cannot leave
#     it mutated — structural, not a trap that has to fire.
#
# Usage: scratch/d0a-mutation-audit.sh [--quick]     (--quick: the 6 fastest mutants)

set -uo pipefail
cd "$(dirname "$0")/.." || exit 2
REPO=$PWD

[ -z "$(git status --porcelain)" ] || {
    echo "REFUSING: the working tree is dirty. The audit runs against a worktree at HEAD," >&2
    echo "so uncommitted work would not be measured and could be misattributed." >&2
    exit 2
}

WORK=$(mktemp -d)
TREE="$WORK/tree"
cleanup() {
    git -C "$REPO" worktree remove --force "$TREE" >/dev/null 2>&1
    rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

git -C "$REPO" worktree add --detach "$TREE" HEAD >/dev/null 2>&1 || {
    echo "REFUSING: could not create an isolated worktree" >&2; exit 2; }

# ITS OWN TARGET DIR — the first version shared the main tree's, and that was WRONG in a way
# that took a disagreeing figure to notice.
#
# WHAT HAPPENED (2026-08-21). Sharing `$REPO/target` let a mutant's build land in the cache
# the main tree reads. After a run, `cargo test` in the repo reported 112 executed against a
# recorded 114, with two `system_account_guard` tests failing — which reads exactly like a
# real regression and is not one: the binary still contained the LAST mutant
# (`if tuid == suid || tgid == sgid` neutered). `touch` + rebuild restored 114. That is
# `docs/DEFECT_CLASSES.md` class 30, introduced by the instrument built to detect defects,
# and it would have mis-attributed the next commit's measurement.
#
# The isolation that matters is BOTH source and artifacts. Kept outside the repo so it
# survives between runs (a cold dependency build otherwise costs minutes every time), and
# never equal to the caller's CARGO_TARGET_DIR.
AUDIT_TARGET="${DELPHI_AUDIT_TARGET:-${TMPDIR:-/tmp}/delphi-mutation-audit-target}"
if [ "$AUDIT_TARGET" = "${CARGO_TARGET_DIR:-}" ] || [ "$AUDIT_TARGET" = "$REPO/target" ]; then
    echo "REFUSING: the audit's target dir must not be the tree's — a mutant build would" >&2
    echo "poison the cache the repo reads (class 30). Set DELPHI_AUDIT_TARGET elsewhere." >&2
    exit 2
fi
mkdir -p "$AUDIT_TARGET"
export CARGO_TARGET_DIR="$AUDIT_TARGET"

SANDBOX="$TREE/runtime/src/sandbox.rs"
EXECUTE="$TREE/runtime/src/execute.rs"
DAEMON="$TREE/runtime/src/bin/delphi-runtimed.rs"

# ── one measured run ───────────────────────────────────────────────────────────────────
# Sets: RUN_RC, RUN_COMPILED, RUN_RESULT_LINES, RUN_FAILURES (sorted, newline-separated),
#       RUN_RAN (passed + failed), RUN_SKIPPED.
#
# TWO THINGS THIS GOT WRONG ON ITS FIRST RUN, both worth stating because both produced a
# confident-looking wrong answer:
#
#   * `--nocapture` is REQUIRED to see skips at all. The project's gated tests `eprintln!`
#     their SKIP marker, and libtest captures stderr for passing tests — without it the run
#     reported SKIPPED=0 for a suite with a known skip, i.e. a skipped test counted as
#     executed. `scripts/test-count.sh` documents exactly this and I did not carry it over.
#   * The stability invariant is PASSED + FAILED, not EXECUTED. A CAUGHT mutant moves tests
#     from passed to failed, so an executed-count derived from `passed` alone drops on every
#     successful catch — which the first run then reported as UNEXPLAINED, for thirteen
#     mutants including several that were plainly caught. The number that must not move is
#     how many tests RAN.
measure() {
    local log="$WORK/log"
    ( cd "$TREE" && cargo test -p delphi-runtime --lib --bins --no-fail-fast \
        -- --test-threads=1 --nocapture ) &> "$log"
    RUN_RC=$?
    if grep -qE '^error(\[|: could not compile)' "$log"; then
        RUN_COMPILED=0
    else
        RUN_COMPILED=1
    fi
    RUN_RESULT_LINES=$(grep -cE '^test result:' "$log")
    # FROM LIBTEST'S `failures:` SUMMARY BLOCK, not from the per-test verdict lines.
    # `--nocapture` interleaves a failing test's own output between `test <name> ... ` and
    # `FAILED`, so `^test <name> \.\.\. FAILED` matches NOTHING — measured: the baseline
    # reported zero failures for a suite with two known ones, and every mutant then read
    # NOT CAUGHT. The end-of-run block lists fully-qualified names one per line and is
    # unaffected by interleaving.
    RUN_FAILURES=$(awk '
        /^failures:$/ { inblock = 1; next }
        inblock && /^    [A-Za-z0-9_:]+$/ { gsub(/^ +/, ""); print; next }
        inblock { inblock = 0 }
    ' "$log" | sort -u)
    local passed failed
    passed=$(grep -E '^test result:' "$log" | grep -oE '[0-9]+ passed' | grep -oE '^[0-9]+' \
        | awk '{s+=$1} END {print s+0}')
    failed=$(grep -E '^test result:' "$log" | grep -oE '[0-9]+ failed' | grep -oE '^[0-9]+' \
        | awk '{s+=$1} END {print s+0}')
    RUN_RAN=$(( passed + failed ))
    RUN_SKIPPED=$(grep -cE '^test [^ ]+ \.\.\. (SKIP|DEFER)' "$log")
}

apply() {  # apply <file> <old> <new>  -> 0 applied, 1 not applied
    python3 - "$1" "$2" "$3" <<'PY'
import sys
p, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(p).read()
if s.count(old) != 1:
    sys.exit(1)
open(p, 'w').write(s.replace(old, new))
PY
}

revert() { git -C "$TREE" checkout -- runtime/src >/dev/null 2>&1; }

# ── baseline ───────────────────────────────────────────────────────────────────────────
echo "=== D0-A mutation audit (rebuilt for D0A-R11-01) ==="
echo "worktree: $TREE"
echo "target:   $CARGO_TARGET_DIR   (isolated — never the tree's, see the header)"
echo
echo "measuring the BASELINE (no mutation) …"
measure
[ "$RUN_COMPILED" -eq 1 ] || { echo "REFUSING: the baseline does not COMPILE." >&2; exit 2; }
[ "$RUN_RESULT_LINES" -gt 0 ] || { echo "REFUSING: the baseline produced no test results." >&2; exit 2; }
BASE_RC=$RUN_RC
BASE_LINES=$RUN_RESULT_LINES
BASE_FAILURES=$RUN_FAILURES
BASE_RAN=$RUN_RAN
BASE_SKIPPED=$RUN_SKIPPED
printf 'baseline: cargo rc=%s  result lines=%s  RAN=%s (of which SKIPPED=%s)\n' \
    "$BASE_RC" "$BASE_LINES" "$BASE_RAN" "$BASE_SKIPPED"
if [ -n "$BASE_FAILURES" ]; then
    echo "baseline FAILURES (these cancel out of every verdict below):"
    printf '  %s\n' $BASE_FAILURES
else
    echo "baseline FAILURES: none"
fi
echo

caught=0; missed=0; unexplained=0
verdict() {  # verdict <label>
    local label=$1
    if [ "$RUN_COMPILED" -eq 0 ]; then
        caught=$((caught+1)); printf '  %-46s CAUGHT (does not compile)\n' "$label"; return
    fi
    if [ "$RUN_RESULT_LINES" -ne "$BASE_LINES" ] || [ "$RUN_RAN" -ne "$BASE_RAN" ] \
       || [ "$RUN_SKIPPED" -ne "$BASE_SKIPPED" ]; then
        unexplained=$((unexplained+1))
        printf '  %-46s UNEXPLAINED — lines %s/%s ran %s/%s skip %s/%s (no verdict)\n' \
            "$label" "$RUN_RESULT_LINES" "$BASE_LINES" "$RUN_RAN" "$BASE_RAN" \
            "$RUN_SKIPPED" "$BASE_SKIPPED"
        return
    fi
    local new gone
    new=$(comm -13 <(printf '%s\n' $BASE_FAILURES | sort -u) <(printf '%s\n' $RUN_FAILURES | sort -u) | tr '\n' ' ')
    gone=$(comm -23 <(printf '%s\n' $BASE_FAILURES | sort -u) <(printf '%s\n' $RUN_FAILURES | sort -u) | tr '\n' ' ')
    if [ -n "${gone// /}" ]; then
        unexplained=$((unexplained+1))
        printf '  %-46s UNEXPLAINED — a baseline failure DISAPPEARED: %s\n' "$label" "$gone"
        return
    fi
    if [ -n "${new// /}" ]; then
        caught=$((caught+1)); printf '  %-46s CAUGHT by %s\n' "$label" "$new"
    else
        missed=$((missed+1)); printf '  %-46s NOT CAUGHT\n' "$label"
    fi
}

run_case() {  # run_case <label> <file> <old> <new>
    local label=$1
    if ! apply "$2" "$3" "$4"; then
        unexplained=$((unexplained+1))
        printf '  %-46s NOT APPLIED (no verdict — the text did not match)\n' "$label"
        revert; return
    fi
    measure
    verdict "$label"
    revert
}

QUICK=${1:-}

echo "mutants:"

# ── the denylist (D0A-R9-10 / R10-04): three relations, three legs ─────────────────────
run_case "denylist: symlink-resolved leg removed" "$SANDBOX" \
  '        std::fs::canonicalize(path).ok().map(|p| lexical_normalize(&p)),' \
  '        None,'
run_case "denylist: ancestor-containment leg removed" "$SANDBOX" \
  '            || base_n.starts_with(&candidate)
' '
'
run_case "denylist: equality leg removed (redundant?)" "$SANDBOX" \
  '        if candidate == base_n
            || candidate.starts_with(&base_n)' \
  '        if candidate.starts_with(&base_n)'
run_case "lexical_normalize: parent-dir folding removed" "$SANDBOX" \
  '            Component::ParentDir => {
                out.pop();
            }' \
  '            Component::ParentDir => {}'

# ── the approved SCOPE — including the translation R10-05 was about ────────────────────
# Codex named this omission: read-only -> read-write is R10-05's vulnerability in mutation
# form, and the first set did not contain it.
run_case "binds: ro-bind TRANSLATED to rw (R10-05's shape)" "$SANDBOX" \
  '            let flag = match mode {
                BindMode::ReadOnly => "--ro-bind",' \
  '            let flag = match mode {
                BindMode::ReadOnly => "--bind",'
run_case "binds: parent-first ordering removed" "$SANDBOX" \
  '        ordered.sort_by_key(|b| lexical_normalize(&b.0));' '        '
run_case "binds: env_delta never emitted" "$SANDBOX" \
  '        for (k, v) in &action.env_delta {
            args.push("--setenv".to_string());' \
  '        for (k, v) in std::iter::empty::<&(String, String)>() {
            args.push("--setenv".to_string());'

# ── class 40, the ancestors ───────────────────────────────────────────────────────────
run_case "ancestors: 0755 -> 0700 (class 40's own value)" "$SANDBOX" \
  '            args.push("0755".to_string());' \
  '            args.push("0700".to_string());'
run_case "ancestors: inside-a-bind exclusion removed" "$SANDBOX" \
  '    wanted.retain(|a| !norm.iter().any(|b| a == b || a.starts_with(b)));' '    '
run_case "ancestors: emission removed entirely" "$SANDBOX" \
  '        for dir in ancestor_dirs(&action.fs_binds) {
            args.push("--perms".to_string());
            args.push("0755".to_string());
            args.push("--dir".to_string());
            args.push(dir);
        }' '        '

# ── namespaces + env ──────────────────────────────────────────────────────────────────
run_case "net: --unshare-net dropped for None" "$SANDBOX" \
  '            NetPolicy::None => args.push("--unshare-net".to_string()),' \
  '            NetPolicy::None => {}'
run_case "net: --share-net dropped for Full" "$SANDBOX" \
  '            NetPolicy::Full => args.push("--share-net".to_string()),' \
  '            NetPolicy::Full => {}'
run_case "env: --clearenv dropped" "$SANDBOX" \
  '            "--clearenv".to_string(),' '            '
run_case "ns: --unshare-pid dropped" "$SANDBOX" \
  '            "--unshare-pid".to_string(),' '            '

# ── the host-creating bind, and its CLASSIFICATION (R10-08) ───────────────────────────
run_case "host-creating bind: guard neutered" "$SANDBOX" \
  '        if !path.exists() {' '        if false {'
run_case "host-creating bind: error VARIANT swapped" "$SANDBOX" \
  '            return Err(crate::RuntimeError::BindWouldCreateOnHost { path: path.clone() });' \
  '            return Err(crate::RuntimeError::DeniedBind { path: path.clone(), base: std::path::PathBuf::from("/run/delphi") });'

if [ "$QUICK" != "--quick" ]; then
# ── the gate itself (sanity: these MUST be caught loudly) ─────────────────────────────
run_case "gate: token verification neutered" "$EXECUTE" \
  '    if !token::verify(key, token, &digest, now) {' '    if false {'
run_case "one-shot: the ledger never refuses a replay" "$EXECUTE" \
  '    if !ledger.consume(&action.pending_id) {' '    if false {'
run_case "script: full-seal requirement neutered" "$EXECUTE" \
  '    if seals & ScriptPin::FULL_SEALS != ScriptPin::FULL_SEALS {' '    if false {'

# ── the credential drop ───────────────────────────────────────────────────────────────
run_case "drop: helper never interposed" "$EXECUTE" \
  '    let creds = tool_credentials()?;' \
  '    let creds: Option<(u32, u32)> = None;'
run_case "drop: approved argv0 not passed to the tool" "$EXECUTE" \
  '    if helper_fd.is_some() {
        args.push(action.argv.first().cloned().unwrap_or_else(|| format!("/proc/self/fd/{program_fd}")));
    }' '    '
run_case "drop: --argv0 emitted even with a helper" "$EXECUTE" \
  '    if helper_fd.is_none()
        && let Some(argv0) = action.argv.first()' \
  '    if let Some(argv0) = action.argv.first()'

# ── the daemon binary: proves --bins is IN SCOPE for this harness ─────────────────────
run_case "login.defs: first definition wins, not last" "$DAEMON" \
  '        found = Some(value);' \
  '        if found.is_none() { found = Some(value); }'
run_case "login.defs: leading blanks not skipped" "$DAEMON" \
  "    let line = line.trim_start_matches([' ', '\\t']);" '    let line = line;'
run_case "guards: the tool-account uid check removed" "$DAEMON" \
  '    if tuid == suid || tgid == sgid {' '    if false {'
fi

echo
printf 'CAUGHT %d   NOT CAUGHT %d   UNEXPLAINED %d\n' "$caught" "$missed" "$unexplained"
if [ "$unexplained" -gt 0 ]; then
    echo "THE RUN IS NOT A CLEAN MEASUREMENT — $unexplained mutant(s) produced state this"
    echo "harness cannot compare to the baseline. Fix those before quoting any figure."
    exit 1
fi
exit 0
