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
# B2A-COMP-R6-02: the daemon resolves these from the unit (`bin_path(env, default)`), so
# hard-coding them meant that on any deployment using the SUPPORTED overrides the freshness,
# seam-free and exec-label checks all certified binaries the daemon never launches. Fourth
# mirror divergence, same class as R4-04 — and the pre-flight already asks systemd for the
# environment, so it has the authority to resolve these too instead of assuming. Set after
# the unit environment is read (see below); these are the runtime's own defaults.
SHELL_BIN_DEFAULT=/usr/libexec/delphi-shell      # delphi-runtimed.rs bin_path("DELPHI_SHELL_BIN", ..)
AI_BIN_DEFAULT=/usr/libexec/delphi-ai            # delphi-runtimed.rs bin_path("DELPHI_AI_BIN", ..)
BRAIN_ADDRESS=/usr/libexec/delphi-ai             # the literal address that must stay EMPTY
SHELL_DIR=/usr/share/delphi/shell
STAGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/staging"
SEAM_SYMBOL=DELPHI_INSECURE_ASSUME_ACTIVE_SESSION

# ══════════════════════════════════════════════════════════════════════════════════════
# ⚠ THIS SCRIPT IS A MIRROR, AND A MIRROR CAN DIVERGE FROM WHAT IT REFLECTS.
#
# Every value below is DUPLICATED from the runtime rather than read from it. B2A-COMP-R3-03
# was exactly this divergence: the pre-flight applied bash's `${VAR:-default}` (defaults on
# unset OR empty) while `delphi-minimal-ai` uses `env::var().unwrap_or_else()` (defaults only
# on ABSENT), so `Environment=DELPHI_AI_BIND_RW=` validated as `/tmp` and ran as `""`.
#
# The full mirrored set, with its source of truth, so the next divergence is findable:
#
#   /usr/share/delphi/shell   <- shell-host/src/main.rs  DEFAULT_BUNDLE_ROOT
#   /usr/libexec/delphi-shell <- delphi-runtimed.rs:86   bin_path("DELPHI_SHELL_BIN", ..)
#   /usr/libexec/delphi-ai    <- delphi-runtimed.rs:87   bin_path("DELPHI_AI_BIN", ..)
#   /tmp (bind default)       <- delphi-minimal-ai.rs:31 unwrap_or_else(|_| "/tmp")
#   DELPHI_AI_EXE required    <- delphi-minimal-ai.rs:29 .expect()  → panics if absent
#   DELPHI_SHELL_VT required  <- delphi-runtimed.rs:95   .context()? → errors if absent
#   the seam symbol           <- delphi-runtimed.rs:192  cfg(insecure-test-seams)
#
# DELIBERATE, DOCUMENTED DIVERGENCE — the one place this mirror is STRICTER than the runtime:
#   DELPHI_AI_ARG is `unwrap_or_default()` in delphi-minimal-ai.rs:30, so the runtime accepts
#   it ABSENT (empty marker path). This script REFUSES that, because a run without a marker
#   has no machine-checkable success signal at all — the whole point of the pre-flight. That
#   is a stricter gate on purpose, NOT a mirroring bug. Stated here rather than approximated
#   silently.
#
# Reading these from the binaries (a `--print-config` mode) would remove the duplication
# entirely and is the real fix; it is recorded as owed rather than done here.
# ══════════════════════════════════════════════════════════════════════════════════════

refusals=0
ok()     { printf '  \033[32mOK\033[0m      %s\n' "$1"; }
refuse() { printf '  \033[31mREFUSE\033[0m  %s\n' "$1"; refusals=$((refusals + 1)); }
note()   { printf '          %s\n' "$1"; }

echo "P3 pre-flight — session user: $SESSION_USER"
echo

# ── B2A-COMP-R4-04: ASK SYSTEMD, DO NOT REPARSE THE UNIT FILE ─────────────────────────
# The round-2 version grepped `^Environment=KEY=` out of the unit file. That is a MIRROR of
# systemd's unit syntax, and it diverges: systemd accepts `Environment="KEY=VALUE"`, several
# assignments on one line, continuation lines, `EnvironmentFile=`, and later assignments
# overriding earlier ones. MEASURED: for `Environment="DELPHI_AI_BIND_RW=/var/tmp"` the grep
# finds ZERO matches, so the pre-flight would read it as ABSENT, default it to /tmp, and pass
# a config whose real bind is /var/tmp — a FALSE GREEN, and R3-03's own class recurring in
# R3-03's fix (class 22).
#
# `systemctl show` reports systemd's OWN resolution, works for a not-yet-started instance,
# and removes the unit-syntax mirror entirely. This is the same foreclose-by-construction
# argument as Design B: stop reimplementing the rule, read it from the thing that owns it.
UNIT_INSTANCE="delphi-runtimed@${SESSION_USER}.service"
_UNIT_ENV=""
if command -v systemctl >/dev/null 2>&1; then
    _UNIT_ENV=$(systemctl show "$UNIT_INSTANCE" -p Environment --value 2>/dev/null)
    _UNIT_ENV_OK=yes
else
    _UNIT_ENV_OK=no
fi

# B2A-COMP-R5-01: `for kv in $_UNIT_ENV` WORD-SPLITS, so
# `Environment="DELPHI_AI_BIND_RW=/tmp/pf elsewhere"` was read as `/tmp/pf` and the marker
# then looked contained when it is not. That is the THIRD distinct way this one check has
# been wrong (lexical prefix -> symlink -> whitespace), so the fix is not a smarter split:
# a value we cannot split faithfully is REFUSED, per the same rule already applied to a
# missing systemctl. Approximating here is precisely the false green being removed.
_unit_env_splittable() {   # 0 if every pair is whitespace-free (systemd quotes otherwise)
    case "$_UNIT_ENV" in *\"*) return 1 ;; esac
    return 0
}
unit_env() {   # key -> value on stdout, empty if unset
    local k="$1" kv
    for kv in $_UNIT_ENV; do
        case "$kv" in "$k="*) printf '%s' "${kv#*=}" ;; esac
    done
}
# "absent" and "declared but EMPTY" are DIFFERENT to the runtime: `env::var().unwrap_or_else()`
# defaults only on absence, while a declared-empty value is `Ok("")` and used as-is.
unit_env_present() {   # key -> 0 if systemd reports it at all (even empty)
    local k="$1" kv
    for kv in $_UNIT_ENV; do
        case "$kv" in "$k="*) return 0 ;; esac
    done
    return 1
}

if [ "$_UNIT_ENV_OK" = yes ] && ! _unit_env_splittable; then
    refuse "the unit environment contains a QUOTED value — this check cannot split it faithfully"
    note "systemd quotes any value containing whitespace, and splitting on whitespace would"
    note "silently truncate it (e.g. a bind of '/tmp/pf elsewhere' read as '/tmp/pf'), making"
    note "a marker look contained when it is not. Refusing rather than approximating."
    note "raw: $_UNIT_ENV"
fi
if [ "$_UNIT_ENV_OK" != yes ]; then
    refuse "systemctl unavailable — cannot read the unit environment the way systemd resolves it"
    note "the pre-flight will NOT fall back to grepping the unit file: that parse diverges from"
    note "systemd's (quoted assignments, EnvironmentFile=, later-wins) and the divergence"
    note "presents as a FALSE GREEN. Refusing rather than approximating."
fi

# The paths the DAEMON will actually launch, resolved from the unit rather than assumed.
# B2A-COMP-R7-02: `${VAR:-default}` defaults on empty AND unset; the runtime's `bin_path()`
# uses `var_os` and defaults ONLY on absent, so a DECLARED-EMPTY `DELPHI_SHELL_BIN` makes the
# daemon `execve` an empty path while the pre-flight cheerfully checks the default binary.
# Exactly the R3-03 divergence, different variable — which is why the absent/declared
# distinction has its own helper rather than being spelled inline each time.
# B2A-COMP-R8-03: "declared but empty" is signalled OUT OF BAND, by exit status, never by a
# magic value on stdout. The previous `<declared-empty>` sentinel was an in-band PATHNAME:
# a deployment legitimately using that name would be misread, and every downstream check
# treated it as a filename — `$p is ABSENT — run: sudo bash installer/install.sh` names a
# file that was never meant to exist and misdirects to the installer when the fault is the
# unit declaration. Same class as the `<none>`/`-` sentinels this project has already paid
# for: a value space that overlaps the data it describes cannot be disambiguated later.
#
# The empty string IS the honest value here — it is literally what the daemon would execve —
# so it is what callers receive, with the status carrying the "and that is a fault" signal.
resolve_bin() {   # var-name  runtime-default  ->  path on stdout; rc 0 = usable, 2 = declared-empty
    local var="$1" dflt="$2" val
    if unit_env_present "$var"; then
        val=$(unit_env "$var")
        [ -n "$val" ] || return 2      # nothing on stdout: no value to mistake for a path
        printf '%s' "$val"
    else
        printf '%s' "$dflt"
    fi
}
SHELL_BIN=$(resolve_bin DELPHI_SHELL_BIN "$SHELL_BIN_DEFAULT"); SHELL_BIN_RC=$?
AI_BIN=$(resolve_bin DELPHI_AI_BIN       "$AI_BIN_DEFAULT");    AI_BIN_RC=$?
for _pair in "DELPHI_SHELL_BIN:$SHELL_BIN_RC" "DELPHI_AI_BIN:$AI_BIN_RC"; do
    if [ "${_pair#*:}" = "2" ]; then
        refuse "${_pair%%:*} is declared but EMPTY in the unit"
        note "the runtime resolves it with var_os + default-on-ABSENT, so an empty declaration"
        note "is used as-is: the daemon would execve an empty path. Remove the line to get the"
        note "default, or give it a path."
    fi
done
# Refused ONCE above. Downstream path checks SKIP an unresolved bin rather than emitting a
# second refusal that names an empty file and points at the wrong fix.
have_bin() { [ -n "$1" ]; }

# ── 1. The installed artifacts ────────────────────────────────────────────────────────
echo "[1/7] installed artifacts"
for p in /usr/libexec/delphi-runtimed "$SHELL_BIN" "$AI_BIN" \
         /etc/pam.d/delphi-runtime /etc/apparmor.d/delphi-shell "$UNIT"; do
    have_bin "$p" || continue      # unresolved bin: refused above, by its actual reason
    if [ -e "$p" ]; then ok "$p"; else refuse "$p is ABSENT — run: sudo bash installer/install.sh"; fi
done
if [ -f "$SHELL_DIR/index.html" ]; then
    ok "$SHELL_DIR/index.html"
else
    refuse "$SHELL_DIR/index.html is ABSENT — the host would draw a WebKit error page, silently"
fi
# The Brain's address must stay empty: a stub at the real address is the lie install.sh refuses.
if [ -e "$BRAIN_ADDRESS" ]; then
    refuse "$BRAIN_ADDRESS EXISTS but must stay empty (no real Brain yet)"
else
    ok "$BRAIN_ADDRESS correctly absent"
fi

# ── 2. Bundle freshness — the staleness that already bit once ─────────────────────────
# The installed bundle is a BUILD ARTIFACT, and P2's mount landed after the first install.
# Running P3 against a pre-P2 bundle would exercise the exact failure P2 fixed —
# window.__delphiConsent never registers, the host's guarded injections no-op, and the user
# sees NOTHING with no error anywhere.
echo
echo "[2/7] freshness — bundle AND binaries (installed vs staged)"
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
# ── HOST BINARY freshness — the gap that let a STALE host run under a FRESH bundle ────
# The bundle was hash-checked from the start; the BINARY was not. So an install that updated
# /usr/share/delphi/shell while leaving an older /usr/libexec/delphi-shell in place passed
# every check and then behaved like the old code — which is exactly what happened when the
# custom-scheme host had been built but not yet installed. Same treatment as the bundle:
# compare installed content against staged content.
if ! have_bin "$SHELL_BIN"; then
    note "skipping the host freshness check — DELPHI_SHELL_BIN did not resolve (refused above)"
elif [ ! -f "$STAGE_DIR/delphi-shell" ]; then
    refuse "$STAGE_DIR/delphi-shell missing — run: bash installer/build.sh (unprivileged)"
elif [ ! -f "$SHELL_BIN" ]; then
    refuse "$SHELL_BIN missing — run: sudo bash installer/install.sh"
else
    staged_bin=$(sha256sum "$STAGE_DIR/delphi-shell" | cut -d' ' -f1)
    inst_bin=$(sha256sum "$SHELL_BIN" | cut -d' ' -f1)
    if [ "$staged_bin" = "$inst_bin" ]; then
        ok "installed delphi-shell matches staging (${inst_bin:0:16}…)"
    else
        refuse "installed $SHELL_BIN DIFFERS from staging — it is STALE"
        note "staged:    ${staged_bin:0:16}…"
        note "installed: ${inst_bin:0:16}…"
        note "a stale host runs old code against a fresh bundle, silently."
        note "fix: sudo bash installer/install.sh"
    fi
fi
# Same for the daemon and the AI scaffold — a stale daemon is the same failure one layer up.
# B2A-COMP-R7-03 (class 17): R6-02 resolved the binary paths for the artifact/seam/exec-label
# checks but left THIS loop hashing the fixed /usr/libexec/delphi-minimal-ai — the fix applied
# to one site while a sibling carried the defect. Every site now uses the resolved path.
for _b in "delphi-runtimed:/usr/libexec/delphi-runtimed" "delphi-minimal-ai:$AI_BIN"; do
    _stage="$STAGE_DIR/${_b%%:*}"; _inst="${_b#*:}"
    if [ -f "$_stage" ] && [ -f "$_inst" ]; then
        if [ "$(sha256sum "$_stage" | cut -d' ' -f1)" = "$(sha256sum "$_inst" | cut -d' ' -f1)" ]; then
            ok "installed $_inst matches staging"
        else
            refuse "installed $_inst DIFFERS from staging — it is STALE"
            note "fix: sudo bash installer/install.sh"
        fi
    fi
done

# The relative-asset-URL requirement must hold in what is actually INSTALLED, not just the repo.
if [ -f "$SHELL_DIR/index.html" ]; then
    if grep -qE '(src|href)="\./' "$SHELL_DIR/index.html"; then
        ok "installed index.html uses RELATIVE asset URLs"
    else
        refuse "installed index.html does NOT use relative asset URLs — vite \`base\` regression"
        note "an absolute base resolves against the scheme root rather than the page:"
        note "blank window, no error. See shell/src/__tests__/bundle-emits-relative-urls.test.ts"
        note "and runtime/shell-host/tests/real_webkit_load.rs (the real-WebKit proof)."
    fi
fi

# ── 3. Seam-free binaries — P5 subsumption depends on this ────────────────────────────
# Detector VERIFIED TO DISCRIMINATE: a build WITH `--features insecure-test-seams` carries
# 2 occurrences of the symbol; the seam-free build carries 0. So absence is evidence, not
# merely the absence of evidence.
echo
echo "[3/7] seam-free binaries (P5 subsumption)"
for b in /usr/libexec/delphi-runtimed "$SHELL_BIN" "$AI_BIN"; do
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
    "$SHELL_BIN" >/dev/null 2>&1 &
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
elif ! have_bin "$SHELL_BIN"; then
    note "skipping the exec-label probe — DELPHI_SHELL_BIN did not resolve (refused above)"
elif [ ! -x "$SHELL_BIN" ]; then
    refuse "cannot probe the exec label — $SHELL_BIN is not executable"
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

VT=$(unit_env DELPHI_SHELL_VT)
# NOT `AI_BIN`: that name already holds the RESOLVED path (default applied) from section 0,
# and reassigning it here made one identifier mean two different things at two points in the
# script. Section 4 asks a different question — "does the unit DECLARE it" — so it gets its
# own name. Nothing after this point may read DECL_AI_BIN as the path the daemon will run.
DECL_AI_BIN=$(unit_env DELPHI_AI_BIN)
AI_EXE=$(unit_env DELPHI_AI_EXE)
AI_ARG=$(unit_env DELPHI_AI_ARG)
AI_BIND_RW=$(unit_env DELPHI_AI_BIND_RW)

if [ -n "$VT" ]; then
    ok "DELPHI_SHELL_VT=$VT"
    note "VERIFY THIS IS THIS BOX'S FREE VT — the committed default is deployment config for"
    note "another machine. A wrong VT opens a session the gate denies forever."
else
    refuse "DELPHI_SHELL_VT unset in $UNIT — the daemon refuses to launch without it"
fi

for pair in "DELPHI_AI_BIN:$DECL_AI_BIN" "DELPHI_AI_EXE:$AI_EXE" "DELPHI_AI_ARG:$AI_ARG"; do
    k=${pair%%:*}; v=${pair#*:}
    if [ -n "$v" ]; then ok "$k=$v"; else
        refuse "$k unset in $UNIT"
        [ "$k" = "DELPHI_AI_EXE" ] && \
            note "delphi-minimal-ai does env::var(\"DELPHI_AI_EXE\").expect(...) and PANICS without it"
        [ "$k" = "DELPHI_AI_ARG" ] && \
            note "this is P3's machine-checkable success signal (the marker the action writes)"
    fi
done

for pair in "DELPHI_AI_BIN:$DECL_AI_BIN" "DELPHI_AI_EXE:$AI_EXE"; do
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
    # B2A-COMP-R2-01 (P2): VALIDATE THE MARKER AGAINST THE SANDBOX BIND, not against a
    # hardcoded guess at which prefixes are writable. `delphi-minimal-ai` derives the action's
    # writable bind from DELPHI_AI_BIND_RW (defaulting to /tmp), and the action runs inside
    # bwrap with ONLY that bind writable. So a marker outside it is denied by the SANDBOX no
    # matter what the filesystem permissions say — and the previous check, which only looked at
    # filesystem writability plus a /tmp-or-/home hint, reported [6/7] green for exactly that
    # misconfiguration. Drift (AI_ARG=/tmp/... with AI_BIND_RW=/var/tmp) then reads as
    # all-preconditions-met while every action is denied inside the jail.
    # B2A-COMP-R3-03 (P2): mirror the RUNTIME's default rule, not bash's. `env::var().
    # unwrap_or_else()` defaults only on ABSENCE; a declared-but-empty value is used as-is
    # (and an empty bind makes bwrap fail, so the action dies inside the jail).
    if unit_env_present DELPHI_AI_BIND_RW; then
        bind_rw="$AI_BIND_RW"          # declared: used verbatim, EMPTY INCLUDED
    else
        bind_rw="/tmp"                 # absent: delphi-minimal-ai's own default
        note "DELPHI_AI_BIND_RW not declared — delphi-minimal-ai defaults it to /tmp"
    fi

    if [ -z "$bind_rw" ]; then
        refuse "DELPHI_AI_BIND_RW is declared but EMPTY"
        note "the runtime does NOT default an empty value (env::var returns Ok(\"\")), so the"
        note "sandbox gets an empty writable bind and every action fails inside bwrap."
        note "fix: give it a path, or remove the line entirely to get the /tmp default."
    elif [ "${bind_rw#/}" = "$bind_rw" ]; then
        refuse "DELPHI_AI_BIND_RW=$bind_rw is not an absolute path"
    else
        # ── Containment, mirroring what the SANDBOX actually does ──────────────────
        # B2A-COMP-R3-02 (round 2): a purely LEXICAL prefix test accepted
        # `/tmp/../var/tmp/marker` against `bind_rw=/tmp` — right prefix, resolves outside.
        # B2A-COMP-R4-01 (round 3): the round-2 fix used `realpath -m`, which FOLLOWS
        # SYMLINKS — and that is a second false green, because `sandbox.rs` passes the bind
        # LITERALLY (`--bind $p $p`, verified at sandbox.rs). With
        # `DELPHI_AI_BIND_RW=/tmp/link -> /var/tmp`, canonicalising the bind made the gate
        # accept `/var/tmp/marker`, while the jail's writable dest is the literal
        # `/tmp/link` — so the write lands OUTSIDE. Class 22 firing on the class-22 fix.
        #
        # The rule the runtime actually has: the bind string is used verbatim; only `..`
        # is collapsed by the kernel when the mount is made. So normalise LEXICALLY on both
        # sides (`-m -s`: resolve `..`, do NOT follow symlinks) and compare. This mirrors
        # the runtime rather than being more-correct-seeming than it.
        norm_path() { realpath -m -s -- "$1"; }
        real_arg=$(norm_path "$AI_ARG" 2>/dev/null || echo "$AI_ARG")
        real_bind=$(norm_path "$bind_rw" 2>/dev/null || echo "$bind_rw")

        # B2A-COMP-R4-02 (round 3): `bind_rw=/` made the glob `//*`, which matches nothing,
        # so every marker fell to OUTSIDE — the pre-flight REFUSING a configuration
        # `delphi-minimal-ai` accepts. Root is the one bind under which every absolute path
        # is contained, and it needs saying explicitly rather than emerging from the glob.
        if [ "$real_bind" = "/" ]; then
            inside=yes
        else
            case "$real_arg/" in
                "$real_bind"/*) inside=yes ;;
                *)              inside=no  ;;
            esac
        fi

        if [ "$inside" = yes ]; then
            ok "marker resolves inside the sandbox's writable bind ($real_bind)"
            if [ "$real_arg" != "$AI_ARG" ]; then
                note "note: $AI_ARG normalises to $real_arg"
            fi
        else
            refuse "marker $AI_ARG normalises to $real_arg, OUTSIDE the writable bind $real_bind"
            note "the action runs in bwrap with only DELPHI_AI_BIND_RW writable, so the write"
            note "is denied by the SANDBOX regardless of filesystem permissions — and the run"
            note "would look like a consent/gate failure rather than a config error."
            note "fix: set DELPHI_AI_ARG inside $real_bind, or widen DELPHI_AI_BIND_RW."
        fi
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
