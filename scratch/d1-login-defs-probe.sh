#!/bin/bash
# D0A-R10-07 — MEASURE shadow's own login.defs grammar, do not read it off a man page.
#
# The daemon's guards (R9-11 system-account refusal, R10-06 tool-identity validation)
# classify accounts against UID_MIN/UID_MAX. If our parser disagrees with the parser that
# ASSIGNS uids, the two classify the same account differently — which is the class R9-11
# closed, reopened at the grammar level.
#
# The authority is `useradd`, not the documentation: it is what hands out uids on this box.
# Each leg writes a login.defs variant into a throwaway --prefix tree, asks useradd to
# allocate, and reads the uid it chose out of that tree's passwd. What useradd honours is
# what our parser must honour.
#
# SYSTEM STATE IS NOT TOUCHED, AND THAT IS CHECKED RATHER THAN ASSUMED (class 16): the real
# /etc account files are md5summed before and after, and a difference is a hard failure.
set -uo pipefail

WORK=$(mktemp -d "${TMPDIR:-/tmp}/delphi-logindefs-XXXXXX")
trap 'rm -rf "$WORK"' EXIT

GUARDED=(/etc/passwd /etc/group /etc/shadow /etc/gshadow /etc/subuid /etc/subgid /etc/login.defs)
before=$(md5sum "${GUARDED[@]}" 2>/dev/null)

command -v useradd >/dev/null || { echo "useradd not present — cannot measure"; exit 1; }
echo "shadow: $(dpkg -s passwd 2>/dev/null | sed -n 's/^Version: //p')"
echo

# leg <name> <login.defs body> <expected-if-honoured>
leg() {
    local name=$1 body=$2 expect=$3 p="$WORK/$RANDOM$RANDOM" uid rc
    mkdir -p "$p/etc"
    : > "$p/etc/passwd"; : > "$p/etc/group"; : > "$p/etc/shadow"; : > "$p/etc/gshadow"
    printf '%s' "$body" > "$p/etc/login.defs"
    useradd --prefix "$p" -M probeuser >/dev/null 2>&1; rc=$?
    uid=$(cut -d: -f3 "$p/etc/passwd" 2>/dev/null)
    printf '%-42s useradd rc=%d  uid=%-8s  %s\n' "$name" "$rc" "${uid:-<none>}" \
        "$([ "$uid" = "$expect" ] && echo "HONOURED (== $expect)" || echo "NOT honoured (wanted $expect)")"
}

echo "== does useradd honour the form? (5000 = the value under test; 1000 = shadow's built-in default) =="
leg "plain            'UID_MIN 5000'"      $'UID_MIN 5000\nUID_MAX 50000\n'         5000
leg "leading spaces   '   UID_MIN 5000'"   $'   UID_MIN 5000\nUID_MAX 50000\n'      5000
leg "leading tab      '\\tUID_MIN 5000'"    $'\tUID_MIN 5000\nUID_MAX 50000\n'       5000
leg "hex              'UID_MIN 0x1388'"    $'UID_MIN 0x1388\nUID_MAX 50000\n'       5000
leg "octal            'UID_MIN 011610'"    $'UID_MIN 011610\nUID_MAX 50000\n'       5000
leg "plus-prefixed    'UID_MIN +5000'"     $'UID_MIN +5000\nUID_MAX 50000\n'        5000
leg "trailing comment 'UID_MIN 5000 # x'"  $'UID_MIN 5000 # x\nUID_MAX 50000\n'     5000
leg "quoted           'UID_MIN \"5000\"'"    $'UID_MIN "5000"\nUID_MAX 50000\n'       5000
leg "equals           'UID_MIN=5000'"      $'UID_MIN=5000\nUID_MAX 50000\n'         5000
leg "commented-out    '#UID_MIN 5000'"     $'#UID_MIN 5000\nUID_MAX 50000\n'        5000

echo
echo "== duplicate keys: which wins? (first=5000, second=6000) =="
leg "dup: 5000 then 6000  -> FIRST?"       $'UID_MIN 5000\nUID_MIN 6000\nUID_MAX 50000\n'  5000
leg "dup: 5000 then 6000  -> LAST?"        $'UID_MIN 5000\nUID_MIN 6000\nUID_MAX 50000\n'  6000

echo
after=$(md5sum "${GUARDED[@]}" 2>/dev/null)
if [ "$before" = "$after" ]; then
    echo "SYSTEM ACCOUNT FILES UNCHANGED (md5 verified before/after)"
else
    echo "!! SYSTEM ACCOUNT FILES CHANGED — the probe mutated state it does not own:"
    diff <(printf '%s\n' "$before") <(printf '%s\n' "$after")
    exit 1
fi
