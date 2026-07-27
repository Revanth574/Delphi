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

    # ── B2A-COMP-R5-02 (P1): THE STUB MUST NOT REPARSE THE UNIT ────────────────────────
    # The round-3 stub grepped `Environment=` out of the unit file and answered ANY `show`
    # call with it. R4-04's whole fix was "stop parsing the unit, ask systemd" — so that stub
    # reintroduced the removed mirror INSIDE THE PROOF, and stayed green even if production
    # queried the wrong unit or the wrong property. Class 22 one layer deeper: the fix's
    # APPARATUS inherited the class the fix closed.
    #
    # This stub instead (1) VALIDATES the argv production must send, failing loudly otherwise,
    # and (2) returns a fixture-controlled fixed string. It supplies a VALUE (like the sysctl
    # stub) rather than reimplementing a parse.
    #
    # WHAT IT STILL CANNOT PROVE, stated rather than implied: that systemd's OWN resolution
    # (EnvironmentFile=, drop-ins, later-wins) matches what the daemon receives. No stub can;
    # that needs a running systemd. It is checked against the REAL system separately — see
    # `real_systemd_contract` at the end of this file.
    # `$UNIT_INST` and `$ENVFILE` are expanded NOW (fixture-creation time) so the stub holds
    # concrete values; `$1`/`$*` are escaped so they stay the stub's own runtime arguments.
    # INSIDE the user namespace `id -un` is `root` (uid 0 is what our uid maps to), and the
    # pre-flight defaults SESSION_USER to `$(id -un)`. So the instance production will ask for
    # is delphi-runtimed@root.service — NOT the outer username. Getting this wrong made every
    # stub call exit 64 and return nothing, which read as "every variable unset".
    local UNIT_INST="delphi-runtimed@root.service" ENVFILE="$tmp/fakebin/unit-env"
    cat > "$tmp/fakebin/systemctl" <<SCTL
#!/bin/bash
if [ "\$1" != show ]; then exit 0; fi
case " \$* " in
  *" $UNIT_INST "*) : ;;
  *) echo "STUB-ERROR: wrong unit instance: \$*" >&2; exit 64 ;;
esac
case " \$* " in
  *" -p Environment "*) : ;;
  *) echo "STUB-ERROR: wrong property: \$*" >&2; exit 65 ;;
esac
cat "$ENVFILE"
SCTL
    chmod 0755 "$tmp/fakebin/systemctl"
    # The fixture's declared environment, in the shape `systemctl show -p Environment --value`
    # emits. Perturbations edit THIS, not a unit file.
    printf 'DELPHI_SHELL_VT=tty3 DELPHI_AI_BIN=/usr/libexec/delphi-minimal-ai DELPHI_AI_EXE=/usr/bin/touch DELPHI_AI_ARG=/tmp/delphi-p3-marker DELPHI_AI_BIND_RW=/tmp\n' \
        > "$tmp/fakebin/unit-env"

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

    SESSION_USER_FOR_STUB="$(id -un)"; export SESSION_USER_FOR_STUB
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

# ── B2A-COMP-R5-03: the structural fix for the generic-assertion class ────────────────
# FOUR tests in this sweep could not fail for the reason they named, and TWO of them (R3-01,
# and the containment positives) shared one shape: a POSITIVE case asserting a generic success
# string that the UNPERTURBED fixture already emits. Such a test passes whether or not its
# perturbation applied.
#
# The rule this encodes: a positive assertion must name a value that the BASELINE does NOT
# produce — and that must be CHECKED, not remembered. `assert_positive` runs the pristine
# fixture first and fails if the baseline already satisfies the expected string. A control,
# in the same sense as the WebKit suite's inline-script leg.
assert_positive() {   # description  expected-substring (must NOT hold for the baseline)
    local desc="$1" expect="$2" perturbed="$PF_LOG"
    run_preflight "true"                       # baseline, no perturbation
    if [[ "$PF_LOG" == *"$expect"* ]]; then
        bad "$desc — NON-DISCRIMINATING: the unperturbed fixture already emits '$expect'"
        return
    fi
    if [[ "$perturbed" == *"$expect"* ]]; then
        ok "$desc"
    else
        bad "$desc — expected '$expect'; got: $(echo "$perturbed" | grep -E "^  (OK|REFUSE)" | tail -3)"
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
    'sed -i "s/ *DELPHI_AI_EXE=[^ ]*//" "$tmp/fakebin/unit-env"' \
    "DELPHI_AI_EXE unset"

expect_refusal "missing DELPHI_SHELL_VT" \
    'sed -i "s/ *DELPHI_SHELL_VT=[^ ]*//" "$tmp/fakebin/unit-env"' \
    "DELPHI_SHELL_VT unset"

# THE SILENT-WRONG-ANSWER CASE: a stale marker makes a FAILED run read as a success.
expect_refusal "pre-existing marker" \
    'touch /tmp/delphi-p3-marker' \
    "ALREADY EXISTS"

# A missing DELPHI_AI_ARG must not leave the marker sections silently unchecked — a section
# that prints nothing reads as a section that passed.
expect_refusal "missing DELPHI_AI_ARG does not silently skip the marker checks" \
    'sed -i "s/ *DELPHI_AI_ARG=[^ ]*//" "$tmp/fakebin/unit-env"' \
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
    'sed -i "s|DELPHI_AI_BIND_RW=/tmp|DELPHI_AI_BIND_RW=/tmp/pf-elsewhere|" "$tmp/fakebin/unit-env"' \
    "OUTSIDE the writable bind"

# ── Containment cases. EVERY PATH THESE NEED IS CONSTRUCTED BY THE FIXTURE ────────────
# B2A-COMP-R4-03 (P1): the round-2 version of the first case used `/tmp/../var/tmp/marker`,
# which assumes the rootfs HAS `/var/tmp`. Where it does not, [6/7] refuses earlier with
# "marker directory does not exist" and the canonicalisation gate is never reached — the
# test's verdict coming from the rootfs rather than from the property. That is the THIRD
# host-dependent test in three rounds (R1-03's sysctl, R3-01's wrong artifact, this).
# A test proving a containment gate must build the tree it needs.

# `..` escape: bind is a directory we create; the marker escapes it into a sibling we also
# create, so the earlier directory-exists check passes and the gate is what decides.
expect_refusal "marker escaping the bind via .. (both dirs constructed)" \
    'mkdir -p /tmp/pf-bind /tmp/pf-outside;
     sed -i "s|DELPHI_AI_BIND_RW=/tmp|DELPHI_AI_BIND_RW=/tmp/pf-bind|" "$tmp/fakebin/unit-env";
     sed -i "s|DELPHI_AI_ARG=/tmp/delphi-p3-marker|DELPHI_AI_ARG=/tmp/pf-bind/../pf-outside/m|" "$tmp/fakebin/unit-env"' \
    "OUTSIDE the writable bind"

# B2A-COMP-R4-01 (P1-class, round 3): the bind must be compared LITERALLY. `sandbox.rs` emits
# `--bind $p $p` verbatim, so a bind that is a SYMLINK still makes the jail's writable dest
# the symlink path — canonicalising it (round 2 used `realpath -m`) accepted a marker under
# the symlink's TARGET, which the sandbox would deny. Class 22 firing on the class-22 fix.
expect_refusal "marker under the bind symlink's TARGET, not the bind itself" \
    'mkdir -p /tmp/pf-target; ln -sfn /tmp/pf-target /tmp/pf-link;
     sed -i "s|DELPHI_AI_BIND_RW=/tmp|DELPHI_AI_BIND_RW=/tmp/pf-link|" "$tmp/fakebin/unit-env";
     sed -i "s|DELPHI_AI_ARG=/tmp/delphi-p3-marker|DELPHI_AI_ARG=/tmp/pf-target/m|" "$tmp/fakebin/unit-env"' \
    "OUTSIDE the writable bind"

# The positive half of the same rule: a marker UNDER the literal bind path must be ACCEPTED,
# even though that path is a symlink. Without this, "refuse everything symlinked" would pass
# the case above while being wrong.
run_preflight 'mkdir -p /tmp/pf-target; ln -sfn /tmp/pf-target /tmp/pf-link;
     sed -i "s|DELPHI_AI_BIND_RW=/tmp|DELPHI_AI_BIND_RW=/tmp/pf-link|" "$tmp/fakebin/unit-env";
     sed -i "s|DELPHI_AI_ARG=/tmp/delphi-p3-marker|DELPHI_AI_ARG=/tmp/pf-link/m|" "$tmp/fakebin/unit-env"'
# B2A-COMP-R5-03 (P1): assert the SPECIFIC bind that was accepted, not the generic success
# message — the pristine /tmp fixture already emits that message, so a positive case asserting
# only the generic string passes even if its perturbation stopped applying. That is the FOURTH
# non-biting test of this sweep and the SECOND of exactly this shape (R3-01 was the first).
# `assert_positive` below makes the discriminating comparison structural rather than remembered.
assert_positive "marker under the LITERAL bind path is accepted (bind verbatim, as sandbox.rs)" \
    "resolves inside the sandbox's writable bind (/tmp/pf-link)"

# B2A-COMP-R4-02 (P2, round 3): `bind_rw=/` built the glob `//*`, matching nothing, so the
# pre-flight REFUSED a configuration delphi-minimal-ai accepts. Root contains everything.
run_preflight 'sed -i "s|DELPHI_AI_BIND_RW=/tmp|DELPHI_AI_BIND_RW=/|" "$tmp/fakebin/unit-env"'
assert_positive "bind_rw=/ contains every absolute marker (not refused)" \
    "resolves inside the sandbox's writable bind (/)"

# B2A-COMP-R5-01 (round 4): `for kv in $_UNIT_ENV` word-splits, so a bind containing
# whitespace was truncated (`/tmp/pf elsewhere` -> `/tmp/pf`) and a marker under the truncated
# prefix looked contained. systemd QUOTES such values, so the raw output carries a quote —
# the pre-flight now REFUSES rather than splitting it wrong.
expect_refusal "unit environment with a QUOTED (whitespace-bearing) value is refused" \
    'printf %s "DELPHI_SHELL_VT=tty3 DELPHI_AI_BIN=/usr/libexec/delphi-minimal-ai DELPHI_AI_EXE=/usr/bin/touch DELPHI_AI_ARG=/tmp/pf/m \"DELPHI_AI_BIND_RW=/tmp/pf elsewhere\"" > "$tmp/fakebin/unit-env"' \
    "cannot split it faithfully"

# B2A-COMP-R3-03 (P2): the runtime defaults ONLY on absence (env::var -> Ok("") when declared
# empty), so a declared-but-empty value must NOT be validated as /tmp.
expect_refusal "DELPHI_AI_BIND_RW declared but EMPTY" \
    'sed -i "s|DELPHI_AI_BIND_RW=/tmp|DELPHI_AI_BIND_RW=|" "$tmp/fakebin/unit-env"' \
    "declared but EMPTY"

# The absent case must still take the runtime's /tmp default and PASS — otherwise the fix
# above would just be a blanket "must be declared", which is a different rule than the runtime's.
run_preflight 'sed -i "s/ *DELPHI_AI_BIND_RW=[^ ]*//" "$tmp/fakebin/unit-env"'
if [[ "$PF_LOG" == *"not declared — delphi-minimal-ai defaults it to /tmp"* ]] \
   && ! [[ "$PF_LOG" == *"declared but EMPTY"* ]]; then
    ok "DELPHI_AI_BIND_RW ABSENT correctly takes the runtime /tmp default"
else
    bad "absent-vs-empty not distinguished: $(echo "$PF_LOG" | grep -A2 "6/7" | head -3)"
fi

expect_refusal "Brain address occupied" \
    'printf "stub\n" > /usr/libexec/delphi-ai' \
    "must stay empty"

echo
echo "── p3-preflight: $pass passed, $fail failed ──"
[ "$fail" -eq 0 ]
