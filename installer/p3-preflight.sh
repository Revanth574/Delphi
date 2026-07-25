#!/bin/bash
# SPDX-License-Identifier: MIT
#
# P3 PRE-FLIGHT — verify every precondition of the composition run BEFORE the root run.
#
# WHY THIS EXISTS. P3's failure modes are silent: a stale bundle draws a blank dialog with no
# error, a stale marker turns a FAILED run into an apparent success, and a seam-carrying
# binary turns a real-gate proof into a non-proof. Each of those presents as "it worked" or
# "nothing happened" rather than as an error, and each would be diagnosed mid-root-run, which
# is the worst place to diagnose anything.
#
# THIS SCRIPT REFUSES, IT DOES NOT WARN. Every failed precondition is a non-zero exit with a
# specific reason. A warning that scrolls past before a root run is the same shape as a green
# check that passed while the thing it checked was broken — this project has already paid for
# that shape more than once (see docs/DEFECT_CLASSES.md classes 15, 16, 18).
#
# UNPRIVILEGED and READ-ONLY: it mutates nothing (per Class 18 — a verification step must not
# mutate what it measures). Run it as the SESSION USER, before `systemctl start`.
#
# Usage:  bash installer/p3-preflight.sh [session-user]      (default: the current user)
set -uo pipefail

SESSION_USER="${1:-$(id -un)}"
UNIT=/usr/lib/systemd/system/delphi-runtimed@.service
SHELL_DIR=/usr/share/delphi/shell
STAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/staging"
SEAM_SYMBOL=DELPHI_INSECURE_ASSUME_ACTIVE_SESSION

refusals=0
ok()     { printf '  \033[32mOK\033[0m      %s\n' "$1"; }
refuse() { printf '  \033[31mREFUSE\033[0m  %s\n' "$1"; refusals=$((refusals + 1)); }
note()   { printf '          %s\n' "$1"; }

echo "P3 pre-flight — session user: $SESSION_USER"
echo

# ── 1. The installed artifacts ────────────────────────────────────────────────────────
echo "[1/7] installed artifacts"
for p in /usr/libexec/delphi-runtimed /usr/libexec/delphi-shell /usr/libexec/delphi-minimal-ai \
         /etc/pam.d/delphi-runtime /etc/apparmor.d/delphi-shell "$UNIT"; do
    if [ -e "$p" ]; then ok "$p"; else refuse "$p is ABSENT — run: sudo bash installer/install.sh"; fi
done
if [ -f "$SHELL_DIR/index.html" ]; then
    ok "$SHELL_DIR/index.html"
else
    refuse "$SHELL_DIR/index.html is ABSENT — the host would draw a WebKit error page, silently"
fi
# The Brain's address must stay empty: a stub at the real address is the lie install.sh refuses.
if [ -e /usr/libexec/delphi-ai ]; then
    refuse "/usr/libexec/delphi-ai EXISTS but must stay empty (no real Brain yet)"
else
    ok "/usr/libexec/delphi-ai correctly absent"
fi

# ── 2. Bundle freshness — the staleness that already bit once ─────────────────────────
# The installed bundle is a BUILD ARTIFACT, and P2's mount landed after the first install.
# Running P3 against a pre-P2 bundle would exercise the exact failure P2 fixed —
# window.__delphiConsent never registers, the host's guarded injections no-op, and the user
# sees NOTHING with no error anywhere.
echo
echo "[2/7] bundle freshness (installed vs staged)"
if [ ! -d "$STAGE_DIR/shell/assets" ]; then
    refuse "$STAGE_DIR/shell/assets missing — run: bash installer/build.sh (unprivileged)"
elif [ ! -d "$SHELL_DIR/assets" ]; then
    refuse "$SHELL_DIR/assets missing — run: sudo bash installer/install.sh"
else
    # Compare CONTENT hashes, not names: vite's content-hashed filenames make a name match
    # nearly sufficient, but hashing is what actually answers "is the installed page the page
    # I just built".
    staged_sum=$(find "$STAGE_DIR/shell" -type f -exec sha256sum {} + \
                 | sed "s|$STAGE_DIR/shell/||" | sort -k2 | sha256sum | cut -d' ' -f1)
    inst_sum=$(find "$SHELL_DIR" -type f -exec sha256sum {} + \
               | sed "s|$SHELL_DIR/||" | sort -k2 | sha256sum | cut -d' ' -f1)
    if [ "$staged_sum" = "$inst_sum" ]; then
        ok "installed bundle matches staging (tree hash ${inst_sum:0:16}…)"
    else
        refuse "installed bundle DIFFERS from staging — it is STALE"
        note "staged:    ${staged_sum:0:16}…"
        note "installed: ${inst_sum:0:16}…"
        note "fix: bash installer/build.sh && sudo bash installer/install.sh"
    fi
fi
# The file:// base fix must be present in what is actually INSTALLED, not just in the repo.
if [ -f "$SHELL_DIR/index.html" ]; then
    if grep -qE '(src|href)="\./' "$SHELL_DIR/index.html"; then
        ok "installed index.html uses RELATIVE asset URLs (file:// safe)"
    else
        refuse "installed index.html does NOT use relative asset URLs — vite \`base\` regression"
        note "an absolute base resolves to the FILESYSTEM ROOT from a file:// document:"
        note "blank page, no error. See shell/src/__tests__/file-protocol-load.test.ts"
    fi
fi

# ── 3. Seam-free binaries — P5 subsumption depends on this ────────────────────────────
# Detector VERIFIED TO DISCRIMINATE: a build WITH `--features insecure-test-seams` carries
# 2 occurrences of the symbol; the seam-free build carries 0. So absence is evidence, not
# merely the absence of evidence.
echo
echo "[3/7] seam-free binaries (P5 subsumption)"
for b in /usr/libexec/delphi-runtimed /usr/libexec/delphi-shell /usr/libexec/delphi-minimal-ai; do
    [ -e "$b" ] || continue
    hits=$(strings "$b" 2>/dev/null | grep -c "$SEAM_SYMBOL")
    if [ "$hits" -eq 0 ]; then
        ok "$(basename "$b") carries no gate-bypass seam"
    else
        refuse "$(basename "$b") CARRIES the gate-bypass seam ($hits hits) — P3 would NOT prove P5"
        note "rebuild WITHOUT --features insecure-test-seams: bash installer/build.sh"
    fi
done

# ── 3b. The userns capability the shell host needs to RENDER ──────────────────────────
# Ubuntu 24.04+ denies unprivileged user namespaces to UNPROFILED processes
# (kernel.apparmor_restrict_unprivileged_userns=1). GTK3 on this distro loads images via
# glycin, whose loader runs under bwrap and REQUIRES a userns — so without the profile every
# themed-icon load fails, the image-missing fallback fails too, and gtkiconhelper.c:495
# ASSERTS, SIGABRT'ing the shell AFTER GTK init succeeds. "Started" would look fine.
echo
echo "[3b/7] shell-host userns capability (GTK/glycin prerequisite)"
# DETECTION NOTE — why this reads the EXEC LABEL and not the profile registry.
# `aa-status` and /sys/kernel/security/apparmor/profiles are BOTH root-only ("You do not
# have enough privilege to read the profile set" / Permission denied), so a registry check
# in an unprivileged pre-flight is UNFALSIFIABLE: it reports "not loaded" whether or not the
# profile is loaded. The first version of this check did exactly that and produced a FALSE
# REFUSAL on a correctly-installed system.
#
# The label the kernel applies at `execve` is readable by the process owner, and it answers a
# STRICTER question than the registry does: not "is a profile named delphi-shell loaded"
# but "does THIS binary actually get it". fd 3 is deliberately left closed so the host's
# fail-closed containment check aborts it immediately — it never reaches GTK and never opens
# a window.
shell_exec_label() {
    local pid lbl="" i
    /usr/libexec/delphi-shell >/dev/null 2>&1 &
    pid=$!
    # Poll: right after fork the child still carries the PARENT's label; the profile is
    # applied at execve, so retry until it appears or the process is gone.
    for i in $(seq 1 40); do
        lbl=$(tr -d '\0' < "/proc/$pid/attr/current" 2>/dev/null)
        case "$lbl" in *delphi-shell*) break ;; esac
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.02
    done
    kill -9 "$pid" 2>/dev/null
    wait "$pid" 2>/dev/null
    printf '%s' "$lbl"
}

if [ "$(sysctl -n kernel.apparmor_restrict_unprivileged_userns 2>/dev/null || echo 0)" != "1" ]; then
    ok "kernel.apparmor_restrict_unprivileged_userns is not enforcing — profile not required here"
elif [ ! -e /etc/apparmor.d/delphi-shell ]; then
    refuse "/etc/apparmor.d/delphi-shell ABSENT while the userns restriction is enforcing"
    note "the shell will SIGABRT on its first themed-icon load — after GTK init reports ok"
elif [ ! -x /usr/libexec/delphi-shell ]; then
    refuse "cannot probe the exec label — /usr/libexec/delphi-shell is not executable"
else
    _lbl="$(shell_exec_label)"
    case "$_lbl" in
        *delphi-shell*)
            ok "profile is LOADED and ATTACHED (exec label: $_lbl)" ;;
        "")
            refuse "could not read the exec label — cannot confirm the profile is attached"
            note "verify by hand: sudo aa-status | grep delphi-shell" ;;
        *)
            refuse "/etc/apparmor.d/delphi-shell exists but is NOT attached (exec label: $_lbl)"
            note "the file alone does nothing — load it:"
            note "  sudo apparmor_parser -r -W /etc/apparmor.d/delphi-shell" ;;
    esac
fi

# ── 4. Unit configuration ─────────────────────────────────────────────────────────────
echo
echo "[4/7] unit environment"
unit_env() {   # key -> value on stdout, empty if unset
    sed -n "s/^Environment=$1=//p" "$UNIT" 2>/dev/null | tail -1
}
VT=$(unit_env DELPHI_SHELL_VT)
AI_BIN=$(unit_env DELPHI_AI_BIN)
AI_EXE=$(unit_env DELPHI_AI_EXE)
AI_ARG=$(unit_env DELPHI_AI_ARG)

if [ -n "$VT" ]; then
    ok "DELPHI_SHELL_VT=$VT"
    note "VERIFY THIS IS THIS BOX'S FREE VT — the committed default is deployment config for"
    note "another machine. A wrong VT opens a session the gate denies forever."
else
    refuse "DELPHI_SHELL_VT unset in $UNIT — the daemon refuses to launch without it"
fi

for pair in "DELPHI_AI_BIN:$AI_BIN" "DELPHI_AI_EXE:$AI_EXE" "DELPHI_AI_ARG:$AI_ARG"; do
    k=${pair%%:*}; v=${pair#*:}
    if [ -n "$v" ]; then ok "$k=$v"; else
        refuse "$k unset in $UNIT"
        [ "$k" = "DELPHI_AI_EXE" ] && \
            note "delphi-minimal-ai does env::var(\"DELPHI_AI_EXE\").expect(...) and PANICS without it"
        [ "$k" = "DELPHI_AI_ARG" ] && \
            note "this is P3's machine-checkable success signal (the marker the action writes)"
    fi
done

for pair in "DELPHI_AI_BIN:$AI_BIN" "DELPHI_AI_EXE:$AI_EXE"; do
    k=${pair%%:*}; v=${pair#*:}
    [ -n "$v" ] || continue
    if [ -x "$v" ]; then ok "$k target is executable"; else refuse "$k=$v is not an executable file"; fi
done

# ── 5. The marker MUST NOT already exist ──────────────────────────────────────────────
# THE SILENT-WRONG-ANSWER GUARD. If a marker survives from a previous attempt, a P3 run that
# FAILS still finds the file present and reads as success. That is the single most dangerous
# state this phase can be in, because the wrong answer is indistinguishable from the right one.
echo
echo "[5/7] marker hygiene"
if [ -z "$AI_ARG" ]; then
    refuse "cannot check the marker — DELPHI_AI_ARG is unset (see above)"
elif [ -e "$AI_ARG" ]; then
    refuse "marker $AI_ARG ALREADY EXISTS — a failed P3 would read as SUCCESS"
    note "owner/mtime: $(stat -c '%U %y' "$AI_ARG" 2>/dev/null)"
    note "fix: rm -f $AI_ARG"
else
    ok "marker $AI_ARG does not exist (a post-run marker will mean the action really ran)"
fi

# ── 6. Marker writability by the PRIV-DROPPED AI ──────────────────────────────────────
# The action runs as the SESSION USER after privilege drop, not as root. A marker path only
# root can write would fail the action for a reason unrelated to consent.
echo
echo "[6/7] marker writability (as the priv-dropped session user, NOT root)"
if [ -z "$AI_ARG" ]; then
    # A section that prints NOTHING reads as a section that passed. Say why it was skipped —
    # silence scrolling past before a root run is the shape this whole script exists to refuse.
    refuse "marker writability UNCHECKED — DELPHI_AI_ARG is unset (see [4/7])"
else
    mdir=$(dirname "$AI_ARG")
    if [ ! -d "$mdir" ]; then
        refuse "marker directory $mdir does not exist"
    elif [ "$SESSION_USER" = "$(id -un)" ]; then
        # Authoritative: we ARE the session user, so ask the kernel.
        if [ -w "$mdir" ]; then ok "$mdir is writable by $SESSION_USER (kernel check)"
        else refuse "$mdir is NOT writable by $SESSION_USER — the action would fail on I/O, not consent"; fi
    else
        # Approximation, and SAID to be one rather than presented as a kernel check.
        perm=$(stat -c '%A %U %G' "$mdir")
        note "not running as $SESSION_USER; reporting mode instead of a kernel writability test"
        note "$mdir -> $perm"
        ok "marker directory exists (writability UNVERIFIED — re-run as $SESSION_USER to confirm)"
    fi
    if [ -n "${AI_ARG##/tmp/*}" ] && [ -n "${AI_ARG##/home/*}" ]; then
        note "NOTE: $AI_ARG is outside /tmp and /home — confirm it is inside DELPHI_AI_BIND_RW,"
        note "or the sandbox will deny the write regardless of filesystem permissions."
    fi
fi

# ── 7. The session user ───────────────────────────────────────────────────────────────
echo
echo "[7/7] session user"
if id "$SESSION_USER" >/dev/null 2>&1; then
    ok "user $SESSION_USER resolves (uid $(id -u "$SESSION_USER"))"
else
    refuse "user $SESSION_USER does not resolve — the daemon resolves --session to a uid itself"
fi

# ── The standing pre-refusal ──────────────────────────────────────────────────────────
cat <<'BANNER'

╔══════════════════════════════════════════════════════════════════════════════════════╗
║ STANDING PRE-REFUSAL — read this BEFORE P3 fails, not after.                         ║
║                                                                                      ║
║ If P3 fails, DO NOT rebuild with `--features insecure-test-seams` to make it pass.   ║
║ That feature bypasses the active-local-seated gate. A P3 run against a seam-carrying ║
║ binary does not prove the gate passed — it proves the gate was not consulted, which  ║
║ silently converts P3 into a NON-PROOF of P5.                                         ║
║                                                                                      ║
║ This is Iron Law #15 clause 1 in a different costume: it is not editing an assertion ║
║ to clear a red, it is editing the SYSTEM UNDER TEST to clear a red. The              ║
║ discriminating question is the same one — would you make this change if the run had  ║
║ PASSED? If no, you are clearing a red, not fixing a cause.                           ║
║                                                                                      ║
║ A failing P3 is a RESULT. Record it, diagnose the cause, and fix the cause.          ║
╚══════════════════════════════════════════════════════════════════════════════════════╝
BANNER

echo
if [ "$refusals" -eq 0 ]; then
    echo "── P3 pre-flight: ALL PRECONDITIONS MET ──"
    echo
    echo "Remaining, and yours to establish on the lane (this script cannot):"
    echo "  * that $VT is genuinely free on THIS box"
    echo "  * whether the run is PRIMARY (the shell's VT is the foreground) or"
    echo "    SECONDARY (chvt to it before approving) — state which in the write-up"
    exit 0
else
    echo "── P3 pre-flight: REFUSED — $refusals precondition(s) unmet. Do NOT start the daemon. ──"
    exit 1
fi
