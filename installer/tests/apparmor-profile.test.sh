#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Tests for installer/apparmor/delphi-shell.
#
# WHAT CAN AND CANNOT BE VERIFIED WITHOUT ROOT — stated up front so no reader mistakes a
# green run here for "the profile fixes the abort":
#
#   VERIFIABLE unprivileged (and verified below):
#     * the profile PARSES (`apparmor_parser -QK` — skip kernel load, skip cache)
#     * it grants `userns`, which is the profile's entire purpose
#     * it attaches to the REAL installed path, not a stale or guessed one
#     * its documentation states plainly that it is NOT confinement — a file in
#       /etc/apparmor.d/ named after a component otherwise READS as hardening
#
#   NOT VERIFIABLE unprivileged (and NOT claimed anywhere):
#     * that loading it actually stops the GTK icon-loader abort. Loading requires root
#       (`apparmor_parser -r`), and the abort reproduces only in an unprofiled context. That
#       remains PREDICTED from the confirmed mechanism, never measured. Do not let a green
#       run here be cited as the fix working.
#
# Run:  bash installer/tests/apparmor-profile.test.sh
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PROFILE="$REPO/installer/apparmor/delphi-shell"

pass=0; fail=0
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }

[ -f "$PROFILE" ] || { echo "cannot find $PROFILE"; exit 1; }

echo "AppArmor profile — installer/apparmor/delphi-shell:"

# 1. It must PARSE. `-Q` skips the kernel load and `-K` skips the cache, so this needs no
#    privilege. VERIFIED TO DISCRIMINATE: a deliberately-malformed profile returns non-zero
#    (checked below), so a pass here is evidence rather than the absence of evidence.
if command -v apparmor_parser >/dev/null 2>&1; then
    if apparmor_parser -QK "$PROFILE" >/dev/null 2>&1; then
        ok "parses cleanly (apparmor_parser -QK)"
    else
        bad "does NOT parse: $(apparmor_parser -QK "$PROFILE" 2>&1 | head -2)"
    fi

    # The discriminator for the check above: prove the parser rejects invalid input, so a
    # green parse is not merely the parser accepting everything.
    bad_tmp="$(mktemp)"
    printf 'abi <abi/5.0>,\ninclude <tunables/global>\nprofile x /nope {\n  not valid syntax here\n}\n' > "$bad_tmp"
    if apparmor_parser -QK "$bad_tmp" >/dev/null 2>&1; then
        bad "the parse check is WORTHLESS — apparmor_parser accepted a malformed profile"
    else
        ok "parse check discriminates (a malformed profile is rejected)"
    fi
    rm -f "$bad_tmp"
else
    bad "apparmor_parser not available — cannot validate the profile at all"
fi

# 2. It must grant `userns`. This single rule is the profile's entire reason to exist; if it
#    is ever dropped the file becomes a pure no-op that still LOOKS like hardening.
if grep -qE '^\s*userns,' "$PROFILE"; then
    ok "grants 'userns' (the sole functional purpose)"
else
    bad "does NOT grant 'userns' — the profile would be a no-op that still looks like hardening"
fi

# 3. It must attach to the path the installer actually installs. A profile attached to a
#    stale path silently protects nothing while appearing present.
if grep -qE '^\s*profile\s+delphi-shell\s+/usr/libexec/delphi-shell\s' "$PROFILE"; then
    ok "attaches to /usr/libexec/delphi-shell (the installed path)"
else
    bad "attachment path does not match /usr/libexec/delphi-shell"
fi
if grep -qE 'copy_fd "\$\{FD\[delphi-shell\.apparmor\]\}"\s+/etc/apparmor\.d/delphi-shell' "$REPO/installer/install.sh"; then
    ok "install.sh installs it to /etc/apparmor.d/delphi-shell"
else
    bad "install.sh does not install the profile to the expected path"
fi

# 4. THE DOCUMENTATION IS LOAD-BEARING, so it is TESTED, not merely written once.
#    A file in /etc/apparmor.d/ bearing a component's name reads as hardening. This one
#    provides none. A future reader must not be able to conclude from its existence that the
#    renderer is sandboxed — so the disclaimers are asserted like any other requirement.
assert_doc() {   # file  pattern  description
    if grep -qiE "$2" "$1"; then ok "$3"; else bad "$3 — MISSING from $(basename "$1")"; fi
}
assert_doc "$PROFILE" "NOT A CONFINEMENT MEASURE" \
    "profile states it is NOT a confinement measure"
assert_doc "$PROFILE" "flags=\(unconfined\).*(permit|every access)|permits every access" \
    "profile explains flags=(unconfined) permits everything"
assert_doc "$PROFILE" "UNTRUSTED RENDERER|renderer is NOT sandboxed|remains? UNCONFINED" \
    "profile states the renderer remains unconfined"
assert_doc "$PROFILE" "status quo plus a name" \
    "profile states the honest delta (status quo plus a name)"
assert_doc "$PROFILE" "FOLLOW-UP|confining profile" \
    "profile records the follow-up for a genuinely confining profile"
assert_doc "$REPO/installer/install.sh" "NOT A CONFINEMENT MEASURE" \
    "install.sh repeats the not-confinement statement at the install site"
assert_doc "$REPO/installer/install.sh" "RENDERER REMAINS UNCONFINED|renderer remains unconfined" \
    "install.sh states the renderer remains unconfined"

echo
echo "── apparmor-profile: $pass passed, $fail failed ──"
echo "   REMINDER: none of this shows the profile STOPS the abort. That needs root to load"
echo "   and an unprofiled context to reproduce against; it stays PREDICTED, not measured."
[ "$fail" -eq 0 ]
