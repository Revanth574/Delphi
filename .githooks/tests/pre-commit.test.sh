#!/bin/bash
# SPDX-License-Identifier: MIT
#
# RED proofs for .githooks/pre-commit's test gate.
#
# WHY THIS FILE EXISTS. The hook is scoped to staged `runtime/` paths, so a change to the
# hook skips it — hook edits are the one class that lands unexecuted, and it has now shipped
# broken twice on exactly that exemption (`tail -1`, then G1/G2/G3 below). A gate that cannot
# run itself needs something else that runs it. This is that something.
#
# TIER 1 by §6 clause (d): the hook's printed figures are quoted in commit messages as the
# evidence a commit was verified. So: RED plus a second weaken, per leg.
#
# The subject is the REAL hook, reached through a SYMLINK into a fake repo (DEFECT_CLASSES
# 25 — a copy would be a different artifact). `cargo` and `scripts/test-count.sh` are stubs
# that MODEL the real tools' measured behaviour, including the two that caused G1 and G3:
# test-count.sh exits non-zero whenever the suite has any failure, and cargo without
# --no-fail-fast stops at the first failing target.

set -uo pipefail
cd "$(dirname "$0")/../.."
REAL=$PWD/.githooks/pre-commit

work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0; fail=0

# mkrepo <hook> <lib-failures> <bins-failures> <cargo-mode> [baseline "EXEC SKIP"] -> repo dir
#   cargo-mode: normal | compile-error
mkrepo() {
    local hook=$1 libf=$2 binsf=$3 mode=$4 baseline=${5:-} reds=${6:-} expect_reds=${7:-} r="$work/repo-$RANDOM$RANDOM"
    mkdir -p "$r"/{runtime/src,scripts,bin,.githooks}
    if [ -n "$baseline" ]; then
        printf 'EXECUTED=%s\nSKIPPED=%s\n' ${baseline} > "$r/.githooks/runtime-test-count-baseline"
        # The EXPECTED failing tests are data in the same file (D0A-R11-02). `expect_reds`
        # defaults to the two intentional names; a leg overrides it to model a swap, and
        # "none" models a suite that must be fully green.
        if [ "${expect_reds:-default}" != "none" ]; then
            for n in ${expect_reds:-execute::tests::nested_interpreter_substitution_executes_unapproved_content execute::tests::same_inode_overwrite_executes_unapproved_content}; do
                echo "RED=$n" >> "$r/.githooks/runtime-test-count-baseline"
            done
        fi
    fi
    ln -s "$hook" "$r/.githooks/pre-commit"
    echo '[package]' > "$r/runtime/Cargo.toml"
    echo 'fn main() {}' > "$r/runtime/src/main.rs"

    # Stub cargo. `clippy` passes. `test` MODELS cargo's fail-fast behaviour: without
    # --no-fail-fast it stops after the first failing target, so only ONE result line exists.
    cat > "$r/bin/cargo" <<STUB
#!/bin/bash
REDS="${reds:-execute::tests::nested_interpreter_substitution_executes_unapproved_content execute::tests::same_inode_overwrite_executes_unapproved_content}"
case "\$1" in
  clippy) exit 0 ;;
  test)
    if [ "$mode" = "integration-red" ]; then
        # D0A-R15-05: a failure that lives in an INTEGRATION target, so the narrow scope
        # cannot see it and the wide one can. The only leg where the gate's SCOPE decides
        # the outcome. (No backticks in this comment: the heredoc is UNQUOTED, so a
        # backtick here is command substitution and bash runs the flag as a command.)
        case " \$* " in
          *" --tests "*)
            echo "test result: ok. 99 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.46s"
            echo "failures:"
            echo ""
            echo "failures:"
            echo "    b1_a_snapshot_mismatch_consumes_the_approval_and_blames_the_snapshot"
            echo ""
            echo "test result: FAILED. 14 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.04s"
            exit 101 ;;
          *)
            echo "test result: ok. 99 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.46s"
            exit 0 ;;
        esac
    fi
    if [ "$mode" = "compile-error" ]; then
        echo "error[E0004]: non-exhaustive patterns" >&2
        echo "error: could not compile \\\`delphi-runtime\\\` (lib test) due to 1 previous error" >&2
        exit 101
    fi
    if [ "$libf" -gt 0 ]; then
        echo "failures:"
        echo ""
        echo "failures:"
        i=0
        for name in \$REDS; do i=\$((i+1)); [ "\$i" -le "$libf" ] && echo "    \$name"; done
        echo ""
    fi
    echo "test result: FAILED. 99 passed; $libf failed; 0 ignored; 0 measured; 0 filtered out; finished in 3.46s"
    case " \$* " in *" --no-fail-fast "*)
        echo "test result: FAILED. 8 passed; $binsf failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s" ;;
    esac
    [ $((libf + binsf)) -eq 0 ] && exit 0 || exit 101 ;;
esac
exit 0
STUB
    # Stub test-count.sh — exits NON-ZERO on any failure, exactly as the real one does.
    # That exit status is what killed the shipped hook under `set -e` (G1).
    cat > "$r/scripts/test-count.sh" <<STUB
#!/bin/bash
echo "EXECUTED 98 / SKIPPED 1 / reported 99   (3660ms total, 37ms per executed test)"
[ $((libf + binsf)) -eq 0 ] && exit 0 || exit 101
STUB
    chmod +x "$r/bin/cargo" "$r/scripts/test-count.sh"

    git -C "$r" init -q 2>/dev/null
    git -C "$r" add -A 2>/dev/null
    printf '%s' "$r"
}

# run <name> <want-rc> <repo> [want-substring]
run() {
    local name=$1 want=$2 r=$3 want_str=${4:-} out rc
    out=$(cd "$r" && PATH="$r/bin:$PATH" bash .githooks/pre-commit 2>&1); rc=$?
    LAST_OUT=$out
    if [ "$rc" != "$want" ]; then
        fail=$((fail+1)); printf '  FAIL %-52s rc=%s, wanted %s\n' "$name" "$rc" "$want"
        printf '%s\n' "$out" | tail -4 | sed 's/^/       | /'; return
    fi
    if [ -n "$want_str" ] && [[ "$out" != *"$want_str"* ]]; then
        fail=$((fail+1)); printf '  FAIL %-52s rc ok but message lacked: %s\n' "$name" "$want_str"
        printf '%s\n' "$out" | tail -4 | sed 's/^/       | /'; return
    fi
    pass=$((pass+1)); printf '  PASS %-52s (rc=%s)\n' "$name" "$rc"
}

echo "=== .githooks/pre-commit test gate ==="

run "clean suite, no REDs recorded -> allow"       0 "$(mkrepo "$REAL" 0 0 normal "98 1" "" none)" "FAILED across all targets: 0"
run "the 2 intentional R9-02 REDs -> allow"       0 "$(mkrepo "$REAL" 2 0 normal "98 1")" "failures match the 2 recorded"
run "a third failure -> REFUSE"                   1 "$(mkrepo "$REAL" 3 0 normal "98 1" "execute::tests::nested_interpreter_substitution_executes_unapproved_content execute::tests::same_inode_overwrite_executes_unapproved_content sandbox::tests::a_created_ancestor_is_0755_inside_a_real_jail")" "not the ones"
run "a 3rd failure the block does NOT list -> REFUSE" 1 "$(mkrepo "$REAL" 2 1 normal "98 1")" "disagree"
echo "       ^ identity ALONE passed this: the names matched while a third test failed"
run "suite did not COMPILE -> REFUSE"             1 "$(mkrepo "$REAL" 0 0 compile-error "98 1")" "did not RUN"

# POSITIVE CONTROL for the scope condition: no staged runtime/ path means no test gate at
# all, so "allow" above cannot be confused with "the gate never ran".
R=$(mkrepo "$REAL" 3 0 normal "98 1")
git -C "$R" rm -q --cached -r runtime >/dev/null 2>&1
echo doc > "$R/README.md"; git -C "$R" add README.md
run "nothing staged under runtime/ -> gate skipped" 0 "$R"
case "$LAST_OUT" in *"runtime test gate"*) fail=$((fail+1)); echo "       ^ but the gate RAN";;
  *) pass=$((pass+1)); echo "       ...and the gate did not run ✓";; esac

# ── SCOPE: the gate must reach INTEGRATION targets (D0A-R15-05) ───────────────────────
# The self-test modelled --no-fail-fast and nothing else, so reverting the gate to
# `--lib --bins` reopened D0A-R14-03 while every leg stayed green. The suite proved the gate
# EXISTED, not that it catches what it was widened to catch. This stub's red is reachable
# only through --tests.
echo
echo "  --- scope: a red that only --tests can see ---"
run "integration-only failure -> REFUSE"          1 "$(mkrepo "$REAL" 0 0 integration-red "98 1" "" none)" "not the ones"

# RED PROOF for that leg: the SAME fixture against a hook narrowed back to `--lib --bins`
# must be ALLOWED — the defect walks through. Derived, never hard-coded (the G1 lesson).
sed -E 's#(cargo test --no-fail-fast -p delphi-runtime) --tests#\1 --lib --bins#' \
    "$REAL" > "$work/hook-scope"
if ! grep -q -- '--lib --bins' "$work/hook-scope"; then
    echo "  WEAKEN SCOPE DID NOT APPLY — the next line would be about the SHIPPED hook"; fail=$((fail+1))
else
    chmod +x "$work/hook-scope"
    run "scope narrowed: the same red -> ALLOWED"  0 "$(mkrepo "$work/hook-scope" 0 0 integration-red "98 1" "" none)"
    echo "       ^ so --tests is load-bearing, not decoration"
fi

# ── IDENTITY, not count (D0A-R11-02) ──────────────────────────────────────────────────
# The gate counted failures, so a RED/GREEN IDENTITY SWAP passed it: fix an R9-02 test,
# break a security test, total still two. These legs hold the count at two and change WHICH
# tests fail.
echo
echo "  --- identity: two failures, but not THOSE two ---"
run "2 failures, one is a SECURITY test -> REFUSE" 1 \
    "$(mkrepo "$REAL" 2 0 normal "98 1" "execute::tests::same_inode_overwrite_executes_unapproved_content sandbox::tests::a_bind_containing_the_runtime_directory_is_refused")" \
    "not the ones"
run "2 failures, NEITHER expected -> REFUSE"       1 \
    "$(mkrepo "$REAL" 2 0 normal "98 1" "sandbox::tests::every_spelling_of_the_runtime_directory_is_refused sandbox::tests::a_created_ancestor_is_0755_inside_a_real_jail")" \
    "not the ones"
run "an R9-02 test starts PASSING (only 1 red) -> REFUSE" 1 "$(mkrepo "$REAL" 1 0 normal "98 1")" \
    "not the ones"
echo "       ^ deliberate: a fixed R9-02 test is NEWS, to be recorded, not absorbed"

# ── The DISAPPEARANCE gate (2026-08-20) ───────────────────────────────────────────────
# The stub emits EXECUTED 98 / SKIPPED 1, so a baseline of "98 1" matches.
echo
echo "  --- disappearance gate: counts must equal the recorded pair ---"
run "counts match the baseline -> allow"            0 "$(mkrepo "$REAL" 2 0 normal "98 1")" "counts match"
run "a test VANISHED (99 recorded, 98 measured) -> REFUSE" 1 "$(mkrepo "$REAL" 2 0 normal "99 1")" "measured: EXECUTED=98 SKIPPED=1"
run "a test started SKIPPING (0 recorded, 1 measured) -> REFUSE" 1 "$(mkrepo "$REAL" 2 0 normal "98 0")" "recorded: EXECUTED=98 SKIPPED=0"
# D0A-R11-02: a MISSING baseline used to exit 0 with a note. An absent guard that reports
# success is the exact shape this gate exists to catch, so it now refuses.
run "no baseline present -> REFUSE (was: allowed with a note)" 1 "$(mkrepo "$REAL" 2 0 normal)" "would be UNGATED"

echo
echo "  --- weakens: each must let a defect through ---"
# G1: restore the `set -e`-killing form (the command substitution without `|| true`).
# DERIVED, not hard-coded (2026-08-23). This sed named the hook's exact arguments, so
# widening the gate's scope from `--lib --bins` to `--tests` left the weaken matching
# nothing — and the suite correctly refused to report a result about the SHIPPED hook,
# which counted as a failure for three commits. A weaken that hard-codes its subject's
# text is the fixture-follows-subject problem (class 17) inside a weaken.
sed -E 's#(counts=\$\(scripts/test-count\.sh .*) \|\| true\)#\1)#' \
    "$REAL" > "$work/hook-g1"; chmod +x "$work/hook-g1"
if diff -q "$REAL" "$work/hook-g1" >/dev/null; then
    echo "  WEAKEN G1 DID NOT APPLY — the next line would be about the SHIPPED hook"; fail=$((fail+1))
else
    # 101, not 1: `set -e` propagates test-count.sh's OWN exit status, so the hook never
    # reaches a decision of its own. The expectation was written as 1 and corrected to the
    # measured value — the leg still discriminates (an unweakened hook allows with 0), and
    # 101 is itself the diagnosis: that status belongs to the counter, not to the gate.
    run "G1 weakened: 2 intentional REDs -> hook DIES"  101 "$(mkrepo "$work/hook-g1" 2 0 normal "98 1")"
    echo "       ^ this is what blocked every runtime commit on this branch"
fi

# G2: drop the no-result-line refusal.
python3 - "$REAL" "$work/hook-g2" <<'PY'
import sys
src, dst = sys.argv[1], sys.argv[2]
s = open(src).read()
old = '''    if [ "$result_lines" -eq 0 ]; then
        echo "REFUSING: no 'test result:' line — the suite did not RUN (compile error?)." >&2
        printf '%s\\n' "$out" | tail -15 >&2
        exit 1
    fi
'''
assert s.count(old) == 1, f"WEAKEN G2 DID NOT APPLY ({s.count(old)} matches)"
open(dst, 'w').write(s.replace(old, ''))
PY
chmod +x "$work/hook-g2"
# After D0A-R11-02 the compile-error case is caught TWICE — the result-line check and the
# identity check (no results means no failures block, so the expected REDs are absent). So
# removing the result-line check alone no longer lets it through, and this leg records the
# REDUNDANCY rather than pretending to isolate one check. Honest: it no longer proves the
# result-line check bites on its own.
run "G2 weakened: compile error still REFUSED (by identity)" 1 "$(mkrepo "$work/hook-g2" 0 0 compile-error "98 1")" \
    "not the ones"
echo "       ^ two independent checks now cover a suite that did not run"

# G3: drop --no-fail-fast, so the second target's failure is never counted.
sed 's/cargo test --no-fail-fast /cargo test /' "$REAL" > "$work/hook-g3"; chmod +x "$work/hook-g3"
grep -q 'cargo test -p delphi-runtime' "$work/hook-g3" || { echo "  WEAKEN G3 DID NOT APPLY"; fail=$((fail+1)); }
run "G3 weakened: 2+1 failures -> PASSES (counted 2)" 0 "$(mkrepo "$work/hook-g3" 2 1 normal "98 1")"
echo "       ^ cargo stopped at the failing lib; the bins' failure was never in the sum"

echo
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ] && { echo "ALL PASS"; exit 0; }
echo "SUITE FAILED"; exit 1
