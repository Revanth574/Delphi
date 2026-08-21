#!/bin/bash
# SPDX-License-Identifier: MIT
#
# RED proof for installer/build.sh's `stage` — that what lands in staging IS what was built.
#
# Lane run 2 installed a delphi-shell that invocation had not produced. build.sh asserted
# nothing about its own copies, so the divergence surfaced three steps later as the shell-host
# staleness guard refusing — and read as a false positive for four attempts.
#
# TIER 2 (§6): a defect here is caught downstream, by that same staleness guard. So: RED plus
# ONE weaken, no stability run. The downstream catch is real defence in depth, not a hope —
# it is what caught this.
#
# The subject is the REAL script, reached through a SYMLINK into a fake repo, so `dirname $0`
# roots it there. A copy would be DEFECT_CLASSES 25.

set -uo pipefail
cd "$(dirname "$0")/../.."
REAL=$PWD/installer/build.sh

work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0; fail=0

# The build products build.sh stages, DERIVED FROM build.sh rather than listed here.
#
# D0A-R10-10: this fixture listed three products while build.sh staged four. `delphi-drop`
# was added at cdc3418 and the fixture was not, so every leg below failed with
# `MISSING BUILD PRODUCT` and the suite has been RED ever since — 15 further commits landed
# on top — unnoticed because nothing runs it (cargo does not, and the pre-commit gate is
# scoped to staged runtime/ paths).
# A fixture that enumerates what its subject reads is a second copy of a list, and
# the copy drifts (class 17). Deriving it means the next artifact needs no edit here; a
# derivation that yields nothing REFUSES rather than quietly testing an empty set.
products_of() {  # products_of <build.sh> -> one relative path per line
    grep -oE '^stage "\$TARGET/[^"]+"' "$1" | sed 's/^stage "\$TARGET\///; s/"$//'
}
mapfile -t PRODUCTS < <(products_of "$REAL")
[ "${#PRODUCTS[@]}" -gt 0 ] || { echo "REFUSING: could not derive the staged products from $REAL"; exit 2; }
printf 'build.sh stages %d product(s): %s\n\n' "${#PRODUCTS[@]}" "${PRODUCTS[*]}"

# A fake repo with everything build.sh reads, and stub cargo/pnpm so no real build runs.
mkrepo() {  # mkrepo <build.sh-to-link> -> repo dir
    local sut=$1 r="$work/repo-$RANDOM"
    mkdir -p "$r"/{installer/pam,installer/apparmor,runtime/systemd,shell/dist,bin}
    ln -s "$sut" "$r/installer/build.sh"
    echo "unit"    > "$r/runtime/systemd/delphi-runtimed@.service"
    echo "pam"     > "$r/installer/pam/delphi-runtime"
    echo "profile" > "$r/installer/apparmor/delphi-shell"
    echo "<html>"  > "$r/shell/dist/index.html"
    local t="$r/target" rel
    # Derived from THE SUBJECT of this run, not from the shipped script: that is what makes
    # the fixture follow build.sh instead of tracking it.
    while read -r rel; do
        [ -n "$rel" ] || continue
        mkdir -p "$t/$(dirname "$rel")"
        # Distinct bytes per product, so a mixed-up copy is visible rather than benign.
        printf 'REAL-BYTES-%s\n' "$(basename "$rel")" > "$t/$rel"
    done < <(products_of "$sut")
    printf '#!/bin/bash\nexit 0\n' > "$r/bin/cargo"
    printf '#!/bin/bash\nexit 0\n' > "$r/bin/pnpm"
    chmod +x "$r/bin/cargo" "$r/bin/pnpm"
    printf '%s' "$r"
}
# A `cp` that copies, then corrupts the destination — the divergence build.sh must catch.
mkbadcp() {
    local d="$work/badbin-$RANDOM"; mkdir -p "$d"
    cat > "$d/cp" <<'STUB'
#!/bin/bash
args=("$@"); dst=${args[-1]}
/bin/cp "$@" || exit $?
[ -f "$dst" ] && case "$dst" in */staging/delphi-shell) echo "STALE-BYTES" > "$dst";; esac
exit 0
STUB
    chmod +x "$d/cp"; printf '%s' "$d"
}

run() {  # run <name> <want-rc> <repo> [extra-PATH-dir]
    local name=$1 want=$2 r=$3 extra=${4:-}
    local out rc
    out=$(cd "$r" && PATH="${extra:+$extra:}$r/bin:$PATH" CARGO_TARGET_DIR="$r/target" \
          bash installer/build.sh 2>&1); rc=$?
    if [ "$rc" = "$want" ]; then pass=$((pass+1)); printf '  %-52s PASS (rc=%s)\n' "$name" "$rc"
    else fail=$((fail+1)); printf '  %-52s FAIL (rc=%s, wanted %s)\n' "$name" "$rc" "$want"
         printf '%s\n' "$out" | tail -6 | sed 's/^/      | /'; fi
    LAST_OUT="$out"
}

echo "=== installer/build.sh staging RED proofs ==="

R=$(mkrepo "$REAL")
run "honest cp — staged == built" 0 "$R"
case "$LAST_OUT" in *"staged delphi-shell"*sha256*) echo "    ...and prints delphi-shell's sha ✓"; pass=$((pass+1));;
  *) echo "    ...but printed no sha for delphi-shell"; fail=$((fail+1));; esac
if [ "$(cat "$R/installer/staging/delphi-shell")" = "REAL-BYTES-delphi-shell" ]; then
    pass=$((pass+1)); echo "    ...and staging holds the built bytes ✓"
else fail=$((fail+1)); echo "    ...but staging does NOT hold the built bytes"; fi

R=$(mkrepo "$REAL")
run "cp that corrupts the destination -> REFUSE" 1 "$R" "$(mkbadcp)"
case "$LAST_OUT" in *"STAGING MISMATCH"*) echo "    ...naming the mismatch ✓"; pass=$((pass+1));;
  *) echo "    ...but did not say STAGING MISMATCH"; fail=$((fail+1));; esac

R=$(mkrepo "$REAL"); rm "$R/target/shell-host/release/delphi-shell"
run "build product absent -> REFUSE" 1 "$R"
case "$LAST_OUT" in *"MISSING BUILD PRODUCT"*) echo "    ...naming the path ✓"; pass=$((pass+1));;
  *) echo "    ...but did not say MISSING BUILD PRODUCT"; fail=$((fail+1));; esac

# --- WEAKEN: drop the equality, keep everything else ---------------------------------------
echo
echo "  --- weaken: remove the built-vs-staged comparison ---"
sed -E 's/^    \[ "\$a" = "\$b" \] \|\| \{$/    false \&\& {/' "$REAL" > "$work/build-weak.sh"
chmod +x "$work/build-weak.sh"
grep -q 'false && {' "$work/build-weak.sh" || { echo "  WEAKEN DID NOT APPLY — the next result"; \
    echo "  would be about the SHIPPED script."; exit 2; }
R=$(mkrepo "$work/build-weak.sh")
run "weakened + corrupting cp -> passes silently" 0 "$R" "$(mkbadcp)"
if [ "$(cat "$R/installer/staging/delphi-shell")" = "STALE-BYTES" ]; then
    pass=$((pass+1)); echo "    ^ staged STALE-BYTES and exited 0 — lane run 2's defect, reconstructed."
else fail=$((fail+1)); echo "    ^ expected STALE-BYTES in staging; the weaken proved nothing."; fi

# --- the fixture must FOLLOW build.sh, not track it -----------------------------------------
# The proof that the derivation is load-bearing: give a copy of build.sh a FIFTH product it
# has never staged before. A fixture with a hard-coded list fails with MISSING BUILD PRODUCT
# (this suite's state since cdc3418); a derived one just works.
echo
echo "  --- one more staged artifact needs no edit here ---"
sed 's#^stage "\$TARGET/release/delphi-drop" delphi-drop$#&\nstage "$TARGET/release/delphi-future" delphi-future#' \
    "$REAL" > "$work/build-five.sh"
chmod +x "$work/build-five.sh"
# DERIVED, not hard-coded (D0A-R11-04): asserting "5" bakes in today's count, so the leg
# breaks the day production genuinely stages a fifth artifact — a test failing because the
# product grew, which trains the reader to edit the test.
want_n=$(( ${#PRODUCTS[@]} + 1 ))
if [ "$(products_of "$work/build-five.sh" | wc -l)" -ne "$want_n" ]; then
    echo "  SETUP DID NOT APPLY — expected $want_n products in the copy"; fail=$((fail+1))
else
    R=$(mkrepo "$work/build-five.sh")
    run "build.sh gains one MORE product -> fixture follows" 0 "$R"
    [ -f "$R/installer/staging/delphi-future" ] && { pass=$((pass+1)); echo "    ...and it reached staging ✓"; } \
        || { fail=$((fail+1)); echo "    ...but it never reached staging"; }
fi

echo
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ] && { echo "ALL PASS"; exit 0; }
echo "SUITE FAILED"; exit 1
