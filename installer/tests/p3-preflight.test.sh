#!/bin/bash
# SPDX-License-Identifier: MIT
#
# Tests for installer/p3-preflight.sh — proof that the pre-flight REFUSES for each specific
# reason, and that a fully-good state PASSES.
#
# WHY TEST THE CHECKER. A pre-flight that passes while its subject is broken is worse than no
# pre-flight: it converts "unverified" into "verified", and the operator then runs the root
# step on that assurance. This project has already been bitten by green checks that passed for
# the wrong reason (see docs/DEFECT_CLASSES.md 15, 16, 18, and the tree-install fixtures whose
# first run passed on mode bits rather than the gates under test). So each refusal here is
# asserted on its OWN message, never on a generic non-zero exit, and the PASS case is included
# so the suite cannot be satisfied by a script that simply always refuses.
#
# Runs the PRODUCTION script unmodified, via a symlink to the real inode, inside `unshare -rm`
# with tmpfs over every path it reads. No test seam is added to the script.
#
# Run:  bash installer/tests/p3-preflight.test.sh
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REAL="$REPO/installer/p3-preflight.sh"
[ -f "$REAL" ] || { echo "cannot find $REAL"; exit 1; }

pass=0; fail=0
ok()  { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }

UNIT_REL=usr/lib/systemd/system/delphi-runtimed@.service

# Run the real pre-flight in a namespace whose /usr, /etc/pam.d are tmpfs, populated to a
# fully-VALID state, then perturbed by $1 (shell code run inside the namespace).
run_preflight() {   # perturbation-code
    local perturb="$1" tmp
    tmp="$(mktemp -d)"
    mkdir -p "$tmp/installer/staging/shell/assets"
    ln -s "$REAL" "$tmp/installer/p3-preflight.sh"
    # Staged bundle (the freshness reference).
    printf '<!doctype html><script src="./assets/app-AAAA.js"></script>\n' \
        > "$tmp/installer/staging/shell/index.html"
    printf 'BUNDLE-A\n' > "$tmp/installer/staging/shell/assets/app-AAAA.js"

    unshare -rm bash -c '
        set -u
        tmp="$1"; perturb="$2"
        for d in /usr/libexec /usr/share /etc/pam.d /usr/lib/systemd/system; do
            mkdir -p "$d"; mount -t tmpfs none "$d" || exit 97
        done
        mkdir -p /usr/lib/systemd/system /usr/share/delphi/shell/assets

        # Binaries: seam-free by construction (no seam symbol in the content).
        for b in delphi-runtimed delphi-shell delphi-minimal-ai; do
            printf "clean-binary-%s\n" "$b" > "/usr/libexec/$b"; chmod 0755 "/usr/libexec/$b"
        done
        printf "pam\n" > /etc/pam.d/delphi-runtime

        # Installed bundle == staged bundle (fresh).
        cp -r "$tmp/installer/staging/shell/." /usr/share/delphi/shell/

        # A fully-populated unit.
        cat > /usr/lib/systemd/system/delphi-runtimed@.service <<UNIT
[Service]
Environment=DELPHI_SHELL_VT=tty3
Environment=DELPHI_AI_BIN=/usr/libexec/delphi-minimal-ai
Environment=DELPHI_AI_EXE=/usr/bin/touch
Environment=DELPHI_AI_ARG=/tmp/delphi-p3-marker
Environment=DELPHI_AI_BIND_RW=/tmp
UNIT
        rm -f /tmp/delphi-p3-marker

        eval "$perturb"

        bash "$tmp/installer/p3-preflight.sh" > "$tmp/out.log" 2>&1
        echo $? > "$tmp/rc"
    ' _ "$tmp" "$perturb"

    PF_RC="$(cat "$tmp/rc" 2>/dev/null || echo 99)"
    PF_LOG="$(sed 's/\x1b\[[0-9]*m//g' "$tmp/out.log" 2>/dev/null)"
    rm -rf "$tmp"
}

expect_refusal() {   # description  perturbation  expected-substring
    local desc="$1"
    run_preflight "$2"
    if [ "$PF_RC" -ne 0 ] && [[ "$PF_LOG" == *"$3"* ]]; then
        ok "$desc — refused for its own reason (rc=$PF_RC)"
    else
        bad "$desc — expected rc!=0 and '$3' (rc=$PF_RC). log: $(echo "$PF_LOG" | grep REFUSE | head -3)"
    fi
}

echo "P3 pre-flight — the PASS case (a script that always refuses must not satisfy this suite):"
run_preflight "true"
if [ "$PF_RC" -eq 0 ] && [[ "$PF_LOG" == *"ALL PRECONDITIONS MET"* ]]; then
    ok "a fully-valid state PASSES with rc=0"
else
    bad "valid state did not pass (rc=$PF_RC). refusals: $(echo "$PF_LOG" | grep REFUSE | head -4)"
fi

echo
echo "Each precondition must REFUSE for its OWN reason:"

# The staleness that actually bit, twenty minutes before this script was written: the bundle
# was installed pre-P2, so window.__delphiConsent never registered and the dialog was blank.
expect_refusal "stale bundle (installed differs from staged)" \
    'printf "BUNDLE-STALE\n" > /usr/share/delphi/shell/assets/app-AAAA.js' \
    "installed bundle DIFFERS from staging"

# A seam-carrying binary silently converts P3 into a non-proof of P5.
expect_refusal "seam-carrying binary" \
    'printf "DELPHI_INSECURE_ASSUME_ACTIVE_SESSION\n" >> /usr/libexec/delphi-runtimed' \
    "CARRIES the gate-bypass seam"

# The gap that blocked P3: minimal-ai panics without DELPHI_AI_EXE.
expect_refusal "missing DELPHI_AI_EXE" \
    'sed -i "/DELPHI_AI_EXE/d" /usr/lib/systemd/system/delphi-runtimed@.service' \
    "DELPHI_AI_EXE unset"

expect_refusal "missing DELPHI_SHELL_VT" \
    'sed -i "/DELPHI_SHELL_VT/d" /usr/lib/systemd/system/delphi-runtimed@.service' \
    "DELPHI_SHELL_VT unset"

# THE SILENT-WRONG-ANSWER CASE: a stale marker makes a FAILED run read as a success.
expect_refusal "pre-existing marker" \
    'touch /tmp/delphi-p3-marker' \
    "ALREADY EXISTS"

# A missing DELPHI_AI_ARG must not leave the marker sections silently unchecked — a section
# that prints nothing reads as a section that passed.
expect_refusal "missing DELPHI_AI_ARG does not silently skip the marker checks" \
    'sed -i "/DELPHI_AI_ARG/d" /usr/lib/systemd/system/delphi-runtimed@.service' \
    "marker writability UNCHECKED"

expect_refusal "absolute asset URLs in the installed index.html (vite base regression)" \
    'printf "<!doctype html><script src=\"/assets/app-AAAA.js\"></script>\n" > /usr/share/delphi/shell/index.html' \
    "does NOT use relative asset URLs"

expect_refusal "missing shell bundle" \
    'rm -rf /usr/share/delphi/shell' \
    "index.html is ABSENT"

expect_refusal "Brain address occupied" \
    'printf "stub\n" > /usr/libexec/delphi-ai' \
    "must stay empty"

echo
echo "── p3-preflight: $pass passed, $fail failed ──"
[ "$fail" -eq 0 ]
