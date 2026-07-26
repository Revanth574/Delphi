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
    mkdir -p "$tmp/installer/staging/shell/assets" "$tmp/fakebin"
    ln -s "$REAL" "$tmp/installer/p3-preflight.sh"
    # ── B2A-COMP-R1-03 (P1): sysctl STUB — makes [3b/7] host-INDEPENDENT ────────────────
    # The pre-flight branches on `kernel.apparmor_restrict_unprivileged_userns`. Reading the
    # HOST's value made this suite's verdict depend on the machine's configuration rather than
    # on the property: on a kernel where it is 0 or absent, removing the profile cannot
    # exercise the branch at all, so the AppArmor cases were red or green by host config.
    # (docs/DEFECT_CLASSES.md class 20, inside the test suite itself — and the THIRD
    # AppArmor+userns instance in this arc, the same sysctl each time.)
    #
    # WHY THIS STUB IS LEGITIMATE AND THE REMOVED aa-status ONE WAS NOT — the distinction
    # matters, so a future reader does not delete this as a repeat of that mistake:
    #   * the aa-status stub FAKED A CAPABILITY the real tool does not have for an
    #     unprivileged caller (it returns a permission error), certifying a check that could
    #     never work in production;
    #   * this stub supplies a VALUE that the real tool genuinely returns — it controls the
    #     INPUT to the logic under test, and both possible inputs get a case below.
    printf '#!/bin/bash\ncat "$(dirname "$0")/sysctl-value" 2>/dev/null || echo 1\n' \
        > "$tmp/fakebin/sysctl"
    chmod 0755 "$tmp/fakebin/sysctl"
    printf '1\n' > "$tmp/fakebin/sysctl-value"   # enforcing, unless a case overrides it

    # NO aa-status STUB — deliberately, and this absence is load-bearing.
    # An earlier version stubbed aa-status to report the profile loaded. The REAL tool answers
    # an unprivileged caller with "You do not have enough privilege to read the profile set",
    # so the stub was MORE CAPABLE THAN THE TOOL IT STOOD IN FOR: it made a registry-based
    # check look correct when that check could never work in production, and the suite
    # certified it. (docs/DEFECT_CLASSES.md class 19 — the conclusion was about the apparatus.)
    # The pre-flight now probes the kernel-applied EXEC LABEL instead, which needs no
    # privilege and no stub. Do not reintroduce one.
    # Staged bundle (the freshness reference).
    printf '<!doctype html><script src="./assets/app-AAAA.js"></script>\n' \
        > "$tmp/installer/staging/shell/index.html"
    printf 'BUNDLE-A\n' > "$tmp/installer/staging/shell/assets/app-AAAA.js"

    unshare -rm bash -c '
        set -u
        tmp="$1"; perturb="$2"
        for d in /usr/libexec /usr/share /etc/pam.d /usr/lib/systemd/system /etc/apparmor.d; do
            mkdir -p "$d"; mount -t tmpfs none "$d" || exit 97
        done
        mkdir -p /usr/lib/systemd/system /usr/share/delphi/shell/assets

        # Binaries: seam-free by construction, and MATCHING what the fixture stages, so the
        # new installed-vs-staged binary freshness check has a valid state to pass on.
        for b in delphi-runtimed delphi-shell delphi-minimal-ai; do
            printf "#!/bin/bash\n# clean-binary-%s\nsleep 2\n" "$b" > "$tmp/installer/staging/$b"
            chmod 0755 "$tmp/installer/staging/$b"
            # INSTALLED must be byte-identical to STAGED, or the freshness check rightly
            # refuses. The pre-flight EXECS delphi-shell to read its AppArmor label, so these
            # must actually run — hence the shebang and the sleep.
            cp "$tmp/installer/staging/$b" "/usr/libexec/$b"; chmod 0755 "/usr/libexec/$b"
        done
        printf "pam\n" > /etc/pam.d/delphi-runtime
        # The AppArmor profile the shell host needs for userns (GTK/glycin). Only its
        # PRESENCE can be represented here; whether it is ATTACHED comes from real kernel
        # policy, which a mount namespace does not virtualise — see the PASS-case note.
        printf "profile stub\n" > /etc/apparmor.d/delphi-shell

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

        export PATH="$tmp/fakebin:$PATH"
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

# THE PASS CASE — and an honest limit on it.
# [3b/7] probes the AppArmor label the KERNEL applies at execve. A mount namespace does not
# virtualise AppArmor policy, and the profile attaches by PATH to a real ELF, so a stub
# cannot carry the delphi-shell label here. That one check therefore CANNOT pass inside the
# namespace, and pretending otherwise is what the (now removed) aa-status stub did.
#
# So the assertion is: EVERY OTHER precondition passes, and the ONLY refusal is the
# exec-label one. That still cannot be satisfied by a script that always refuses (it would
# emit other refusals), so the suite keeps its guard against a degenerate pre-flight.
# The [3b/7] pass is verified on the REAL system instead — observed
# "profile is LOADED and ATTACHED (exec label: delphi-shell (unconfined))".
echo "P3 pre-flight — the PASS case (a script that always refuses must not satisfy this suite):"
run_preflight "true"
# Match only the indented per-check entries ("  REFUSE  ..."), never the summary line
# ("REFUSED — N precondition(s) unmet"), which also contains the word.
other_refusals=$(echo "$PF_LOG" | grep -c "^  REFUSE.*" 2>/dev/null || echo 0)
other_refusals=$(echo "$PF_LOG" | grep "^  REFUSE" | grep -vc "exec label")
if [ "$other_refusals" -eq 0 ]; then
    ok "every precondition except the (unsimulatable) exec-label probe passes"
else
    bad "valid state produced $other_refusals unexpected refusal(s): $(echo "$PF_LOG" | grep "^  REFUSE" | grep -v "exec label" | head -3)"
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

# NOTE on the not-attached leg: it CANNOT be simulated here. The exec label comes from the
# REAL kernel policy, which a mount namespace does not virtualise, so a stub at
# /usr/libexec/delphi-shell inside the namespace carries whatever the host policy says.
# That branch is verified on the REAL system instead (observed `delphi-shell (unconfined)`
# when loaded, and the FALSE REFUSAL it replaced was found there too). Simulating it would
# need a stub more capable than the real mechanism — the exact mistake removed above.

# Both branches of [3b/7], deterministically, regardless of the host's own sysctl.
expect_refusal "AppArmor profile absent while userns is restricted" \
    'printf "1\n" > "$tmp/fakebin/sysctl-value"; rm -f /etc/apparmor.d/delphi-shell' \
    "ABSENT while the userns restriction is enforcing"

# The OTHER branch: when the restriction is not enforcing, a missing profile is NOT a
# precondition failure — the host can create a userns without one. Asserting this keeps the
# check from being a blanket "profile must exist" that happens to look right on one machine.
run_preflight 'printf "0\n" > "$tmp/fakebin/sysctl-value"; rm -f /etc/apparmor.d/delphi-shell'
if [[ "$PF_LOG" == *"is not enforcing — profile not required here"* ]] \
   && ! [[ "$PF_LOG" == *"ABSENT while the userns restriction is enforcing"* ]]; then
    ok "userns restriction NOT enforcing — absent profile correctly not a failure"
else
    bad "not-enforcing branch not taken: $(echo "$PF_LOG" | grep -A1 "3b/7" | head -2)"
fi

# THE GAP THAT LET A STALE HOST RUN UNDER A FRESH BUNDLE. The bundle was hash-checked from
# the start; the binary was not, so an install that refreshed the bundle but left an older
# /usr/libexec/delphi-shell passed every check and then behaved like the old code.
expect_refusal "stale host BINARY (installed differs from staged)" \
    'printf "%s\n" "#!/bin/bash" "# STALE" > /usr/libexec/delphi-shell; chmod 0755 /usr/libexec/delphi-shell' \
    "installed /usr/libexec/delphi-shell DIFFERS from staging"

expect_refusal "stale DAEMON binary" \
    'printf "%s\n" "#!/bin/bash" "# STALE" > /usr/libexec/delphi-runtimed; chmod 0755 /usr/libexec/delphi-runtimed' \
    "installed /usr/libexec/delphi-runtimed DIFFERS from staging"

# B2A-COMP-R2-01 (P2): the marker must be inside the SANDBOX's writable bind, not merely on a
# filesystem the user can write. delphi-minimal-ai derives the bind from DELPHI_AI_BIND_RW and
# the action runs in bwrap with only that bind writable, so drift between the two reads as
# all-preconditions-met while every action is denied INSIDE the jail — a sandbox
# misconfiguration wearing a consent-failure costume.
expect_refusal "marker outside DELPHI_AI_BIND_RW" \
    'sed -i "s|DELPHI_AI_BIND_RW=/tmp|DELPHI_AI_BIND_RW=/var/tmp|" /usr/lib/systemd/system/delphi-runtimed@.service' \
    "OUTSIDE the writable bind"

expect_refusal "Brain address occupied" \
    'printf "stub\n" > /usr/libexec/delphi-ai' \
    "must stay empty"

echo
echo "── p3-preflight: $pass passed, $fail failed ──"
[ "$fail" -eq 0 ]
