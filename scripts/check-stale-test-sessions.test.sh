#!/bin/bash
# SPDX-License-Identifier: MIT
#
# RED proofs for scripts/check-stale-test-sessions.sh.
#
# WHY THIS FILE EXISTS AT ALL (lane run 2)
# ----------------------------------------
# The checker had NO committed test. Its refusal paths were proven by hand in round 7 and the
# proofs were not kept; its REPORT branch — the one that runs when a stale session IS found —
# had never been executed by anything. So a backtick inside a double-quoted `echo` shipped:
# `closing` ran as a command, printed `closing: command not found`, and the sentence came out
# with a hole in it. **The error path of the tool built to make errors legible was its least
# executed code.** Both branches are exercised here.
#
# `loginctl` is stubbed on PATH from a fixture, so every branch is reachable without a seat.

set -uo pipefail
cd "$(dirname "$0")/.."

SUT=scripts/check-stale-test-sessions.sh
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT
pass=0; fail=0

# A stub loginctl driven by a spec file: SID|USER|TTY|SERVICE|STATE|SHOWRC|SHOWMSG
mkloginctl() {  # mkloginctl <spec-file> -> a PATH dir
    local spec=$1 d="$work/bin-$RANDOM"; mkdir -p "$d"
    cat > "$d/loginctl" <<STUB
#!/bin/bash
spec='$spec'
case "\$1" in
  list-sessions)
    [ -s "\$spec" ] || exit 0
    while IFS='|' read -r sid user tty svc state rc msg; do
      [ -n "\$sid" ] || continue
      printf '%s 1000 %s seat0 %s\n' "\$sid" "\$user" "\$tty"
    done < "\$spec" ;;
  show-session)
    while IFS='|' read -r sid user tty svc state rc msg; do
      [ "\$sid" = "\$2" ] || continue
      if [ "\$rc" != 0 ]; then echo "\$msg" >&2; echo "\$msg"; exit "\$rc"; fi
      [ "\$svc" != "-" ] && echo "Service=\$svc"
      echo "TTY=\$tty"; echo "Name=\$user"; echo "State=\$state"
      exit 0
    done < "\$spec"
    echo "Failed to get session: No such session '\$2'" ; exit 1 ;;
esac
STUB
    chmod +x "$d/loginctl"; printf '%s' "$d"
}
mkspec() { local f="$work/spec-$RANDOM"; printf '%s\n' "$1" > "$f"; printf '%s' "$f"; }

check() {  # check <name> <want-rc> <sut> <path-dir> [args...]
    local name=$1 want=$2 sut=$3 dir=$4; shift 4
    local out rc
    out=$(PATH="$dir:$PATH" "$sut" "$@" 2>&1); rc=$?
    if [ "$rc" = "$want" ]; then pass=$((pass+1)); printf '  %-56s PASS (rc=%s)\n' "$name" "$rc"
    else fail=$((fail+1)); printf '  %-56s FAIL (rc=%s, wanted %s)\n' "$name" "$rc" "$want"
         printf '%s\n' "$out" | sed 's/^/      | /'; fi
    LAST_OUT="$out"
}

echo "=== check-stale-test-sessions RED proofs ==="

CLEAN=$(mkloginctl "$(mkspec 'c1|alice|tty2|login|active|0|')")
OURS=$(mkloginctl  "$(mkspec 'c121|delphi-b1-32828|tty1|delphi-runtime|closing|0|')")
OTHERVT=$(mkloginctl "$(mkspec 'c9|someone|tty3|gdm-password|active|0|')")

check "clean lane"                       0 "$SUT" "$CLEAN"
check "OUR service holding a VT"         1 "$SUT" "$OURS"

# --- the REPORT branch: the bug that shipped, and its absence now -------------------------
echo "  --- the report branch's own text ---"
case "$LAST_OUT" in
  *"command not found"*) echo "    executes text as a COMMAND — the shipped bug"; fail=$((fail+1));;
  *'stays `closing`, reboot'*) echo "    sentence intact, backticks literal ✓"; pass=$((pass+1));;
  *) echo "    sentence MANGLED (neither intact nor the known bug):"; printf '%s\n' "$LAST_OUT" | tail -3; fail=$((fail+1));;
esac
for want in 'c121' 'delphi-b1-32828' 'tty1' 'terminate-session c121'; do
  case "$LAST_OUT" in *"$want"*) pass=$((pass+1));;
    *) echo "    report omits '$want' — it must name the survivor and the fix"; fail=$((fail+1));; esac
done

# --- --vt: the per-test entry assertion ----------------------------------------------------
check "--vt tty1, a session on tty1"      1 "$SUT" "$OTHERVT" --vt tty3
check "--vt tty1, sessions only on tty3"  0 "$SUT" "$OTHERVT" --vt tty1
check "--vt with no VT argument"          2 "$SUT" "$CLEAN"   --vt

# --- fail-closed: unknown must never read as clean -----------------------------------------
NOLOGINCTL="$work/empty-bin"; mkdir -p "$NOLOGINCTL"
out=$(PATH="$NOLOGINCTL" "$SUT" 2>&1); rc=$?
[ "$rc" = 2 ] && { pass=$((pass+1)); echo "  loginctl absent -> REFUSE                                 PASS (rc=2)"; } \
              || { fail=$((fail+1)); echo "  loginctl absent -> REFUSE                                 FAIL (rc=$rc)"; }

BUSFAIL=$(mkloginctl "$(mkspec 'c1|alice|tty2|login|active|1|Failed to connect to bus: No such file or directory')")
VANISHED=$(mkloginctl "$(mkspec 'c1|alice|tty2|login|active|1|Failed to get session: No such session '"'"'c1'"'"'')")
NOSVC=$(mkloginctl "$(mkspec 'c1|alice|tty2|-|active|0|')")

check "show-session: BUS failure (R7-02)"  2 "$SUT" "$BUSFAIL"
check "show-session: session vanished"     0 "$SUT" "$VANISHED"
check "session reports no Service= (R7-03)" 2 "$SUT" "$NOSVC"

# --- WEAKEN (a): restore R7-02's loose substring --------------------------------------------
echo
echo "  --- weaken (a): anchored 'no such session' -> the loose 'No such' substring ---"
sed -E "s/grep -qiE '\^\(Failed to get session:\|\.\*Unit \.\* not loaded\)\.\*\[Nn\]o such \(session\|unit\)'/grep -qi 'No such'/" \
    "$SUT" > "$work/sut-loose.sh"; chmod +x "$work/sut-loose.sh"
grep -q "grep -qi 'No such'" "$work/sut-loose.sh" || { echo "  WEAKEN (a) DID NOT APPLY — the next"; \
    echo "  result would be about the SHIPPED script, not the weakened one."; exit 2; }
check "loose match + a BUS failure -> reads as CLEAN" 0 "$work/sut-loose.sh" "$BUSFAIL"
echo "    ^ a total loss of logind classified as 'the session went away'. Shipped: rc=2 above."

# --- WEAKEN (b): restore R7-03's concatenation ----------------------------------------------
echo
echo "  --- weaken (b): [ -n \"\$svc\" ] -> [ -n \"\$svc\$tty\" ] ---"
sed -E 's/\[ -n "\$svc" \] \|\| REFUSE/[ -n "$svc$tty" ] || REFUSE/' "$SUT" > "$work/sut-concat.sh"
chmod +x "$work/sut-concat.sh"
grep -q '\[ -n "\$svc\$tty" \]' "$work/sut-concat.sh" || { echo "  WEAKEN (b) DID NOT APPLY."; exit 2; }
check "concatenation + a Service-less session -> CLEAN" 0 "$work/sut-concat.sh" "$NOSVC"
echo "    ^ satisfied by TTY alone, so the check meant to catch this passes it. Shipped: rc=2."

echo
echo "passed=$pass failed=$fail"
[ "$fail" -eq 0 ] && { echo "ALL PASS"; exit 0; }
echo "SUITE FAILED"; exit 1
